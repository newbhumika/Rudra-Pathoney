import os
import re
import json
import sqlite3
import threading
import time
import queue
import signal
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request, Response
import requests
import time
from collections import defaultdict, deque

DB_PATH = os.environ.get("HPGUI_DB_PATH", os.path.join(os.path.dirname(__file__), "honeypot.db"))
COWRIE_LOG_DIR = os.environ.get("COWRIE_LOG_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "cowrie/log")))
COWRIE_DOCKER_NAME = os.environ.get("COWRIE_DOCKER_NAME", "cowrie")
INGEST_FROM = os.environ.get("INGEST_FROM", "auto")  # auto|docker|files|none
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "9672014b4263a2")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyAKUukM29UgbrbPCUfKZBZuq3_xcXNqVLE")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")  # Add your VT key
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")    # Add your AbuseIPDB key

# In-memory cache for geolocations: ip -> {lat, lon, city, country}
_geo_cache: Dict[str, Dict[str, Any]] = {}

# Behavioral analysis tracking
_behavior_cache: Dict[str, Dict[str, Any]] = {}
_attack_patterns: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

# ------------- Database Layer -------------

class Database:
	def __init__(self, db_path: str) -> None:
		self.db_path = db_path
		self._lock = threading.RLock()
		self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
		self._conn.execute("PRAGMA journal_mode=WAL;")
		self._conn.execute("PRAGMA synchronous=NORMAL;")
		self._create_schema()

	def _create_schema(self) -> None:
		with self._lock:
			self._conn.execute(
				"""
				CREATE TABLE IF NOT EXISTS logs (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					timestamp TEXT,
					attacker_ip TEXT,
					username TEXT,
					password TEXT,
					command TEXT,
					session_id TEXT,
					event TEXT,
					raw TEXT
				);
				"""
			)
			self._conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(timestamp);")
			self._conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(attacker_ip);")
			self._conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(username);")
			self._conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_pass ON logs(password);")
			self._conn.commit()

	def insert_log(self, record: Dict[str, Any]) -> None:
		with self._lock:
			self._conn.execute(
				"""
				INSERT INTO logs (timestamp, attacker_ip, username, password, command, session_id, event, raw)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				""",
				(
					record.get("timestamp"),
					record.get("attacker_ip"),
					record.get("username"),
					record.get("password"),
					record.get("command"),
					record.get("session_id"),
					record.get("event"),
					json.dumps(record.get("raw")) if isinstance(record.get("raw"), (dict, list)) else record.get("raw"),
				),
			)
			self._conn.commit()

	def fetch_logs(
		self,
		page: int = 1,
		page_size: int = 50,
		ip: Optional[str] = None,
		since_hours: Optional[int] = None,
		q: Optional[str] = None,
		command_keyword: Optional[str] = None,
	) -> Tuple[List[Dict[str, Any]], int]:
		conditions: List[str] = []
		params: List[Any] = []

		if ip:
			conditions.append("attacker_ip = ?")
			params.append(ip)
		if since_hours:
			cutoff = datetime.utcnow() - timedelta(hours=since_hours)
			conditions.append("timestamp >= ?")
			params.append(cutoff.isoformat())
		if q:
			conditions.append("(username LIKE ? OR password LIKE ? OR command LIKE ? OR session_id LIKE ?)")
			like = f"%{q}%"
			params.extend([like, like, like, like])
		if command_keyword:
			conditions.append("command LIKE ?")
			params.append(f"%{command_keyword}%")

		where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

		with self._lock:
			count_sql = f"SELECT COUNT(*) FROM logs {where}"
			cur = self._conn.execute(count_sql, params)
			total = int(cur.fetchone()[0])

			offset = (page - 1) * page_size
			query_sql = f"""
			SELECT id, timestamp, attacker_ip, username, password, command, session_id, event
			FROM logs
			{where}
			ORDER BY timestamp DESC, id DESC
			LIMIT ? OFFSET ?
			"""
			cur = self._conn.execute(query_sql, (*params, page_size, offset))
			rows = cur.fetchall()

		columns = ["id", "timestamp", "attacker_ip", "username", "password", "command", "session_id", "event"]
		data = [dict(zip(columns, row)) for row in rows]
		return data, total

	def aggregates(self, since_hours: Optional[int] = None) -> Dict[str, Any]:
		conditions: List[str] = []
		params: List[Any] = []
		if since_hours:
			cutoff = datetime.utcnow() - timedelta(hours=since_hours)
			conditions.append("timestamp >= ?")
			params.append(cutoff.isoformat())
		where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

		with self._lock:
			# Top attacker IPs
			cur = self._conn.execute(
				f"""
				SELECT attacker_ip, COUNT(*) as cnt
				FROM logs
				{where}
				AND attacker_ip IS NOT NULL AND attacker_ip != ''
				GROUP BY attacker_ip
				ORDER BY cnt DESC
				LIMIT 10
				""",
				params,
			)
			top_ips = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]

			# Top credentials
			cur = self._conn.execute(
				f"""
				SELECT COALESCE(username,'') || ':' || COALESCE(password,'') AS cred, COUNT(*) as cnt
				FROM logs
				{where}
				AND username IS NOT NULL AND password IS NOT NULL
				GROUP BY cred
				ORDER BY cnt DESC
				LIMIT 10
				""",
				params,
			)
			top_credentials = [{"credential": r[0], "count": r[1]} for r in cur.fetchall()]

			# Attempts over time (per hour)
			cur = self._conn.execute(
				f"""
				SELECT strftime('%Y-%m-%d %H:00:00', timestamp) AS hour, COUNT(*)
				FROM logs
				{where}
				GROUP BY hour
				ORDER BY hour ASC
				""",
				params,
			)
			attempts_over_time = [{"hour": r[0], "count": r[1]} for r in cur.fetchall()]

		return {
			"top_ips": top_ips,
			"top_credentials": top_credentials,
			"attempts_over_time": attempts_over_time,
		}


# ------------- Log Parsing -------------

COWRIE_JSON_KEYS = {
	"timestamp": ["timestamp", "time"],
	"ip": ["src_ip", "peerIP", "peer_ip"],
	"username": ["username", "user"],
	"password": ["password", "passwd"],
	"command": ["input", "command"],
	"session": ["session", "sessionid", "session_id"],
}

LOGIN_REGEX = re.compile(
	r"(?i)(login|auth) (attempt|failed|success).*?user(?:name)?\s*[:=]?\s*([^\s]+).*?pass(?:word)?\s*[:=]?\s*([^\s]+).*?from\s+([0-9a-fA-F:\.]+)"
)
CMD_REGEX = re.compile(r"(?i)(?:command|input)\s*[:=]?\s*(.+)")
IP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def parse_cowrie_line(line: str) -> Optional[Dict[str, Any]]:
	line = line.strip()
	if not line:
		return None

	# Try JSON first
	try:
		obj = json.loads(line)
		if isinstance(obj, dict) and (obj.get("eventid") or obj.get("event")):
			return parse_from_json(obj)
	except json.JSONDecodeError:
		pass

	# Fallback: regex extraction from text line
	record: Dict[str, Any] = {"raw": line}

	login_match = LOGIN_REGEX.search(line)
	if login_match:
		_, _, user, passwd, ip = login_match.groups()
		record.update(
			{
				"event": "login",
				"username": safe_trim(user),
				"password": safe_trim(passwd),
				"attacker_ip": ip,
			}
		)
		cmd_match = CMD_REGEX.search(line)
		if cmd_match:
			record["command"] = safe_trim(cmd_match.group(1))
		# Timestamp best-effort: now
		record["timestamp"] = datetime.utcnow().isoformat()
		return record

	# Generic command line with IP
	cmd_match = CMD_REGEX.search(line)
	if cmd_match:
		record["event"] = "command"
		record["command"] = safe_trim(cmd_match.group(1))
		ip_match = IP_REGEX.search(line)
		if ip_match:
			record["attacker_ip"] = ip_match.group(1)
		record["timestamp"] = datetime.utcnow().isoformat()
		return record

	return None


def parse_from_json(obj: Dict[str, Any]) -> Dict[str, Any]:
	event = obj.get("eventid") or obj.get("event")
	timestamp = _first_present(obj, COWRIE_JSON_KEYS["timestamp"]) or datetime.utcnow().isoformat()
	attacker_ip = _first_present(obj, COWRIE_JSON_KEYS["ip"]) or obj.get("src_ip") or obj.get("srcIP")
	username = _first_present(obj, COWRIE_JSON_KEYS["username"]) or None
	password = _first_present(obj, COWRIE_JSON_KEYS["password"]) or None
	command = _first_present(obj, COWRIE_JSON_KEYS["command"]) or None
	session_id = _first_present(obj, COWRIE_JSON_KEYS["session"]) or None

	# Normalize timestamp to ISO if needed
	try:
		# Cowrie uses ISO already; if numeric, convert from epoch
		if isinstance(timestamp, (int, float)):
			timestamp = datetime.utcfromtimestamp(float(timestamp)).isoformat()
	except Exception:
		pass

	return {
		"timestamp": str(timestamp),
		"attacker_ip": attacker_ip,
		"username": username,
		"password": password,
		"command": command,
		"session_id": session_id,
		"event": event,
		"raw": obj,
	}


def _first_present(obj: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
	for k in keys:
		if k in obj and obj[k] not in (None, ""):
			return obj[k]
	return None


def safe_trim(value: Optional[str]) -> Optional[str]:
	if value is None:
		return None
	return str(value).strip().strip('\"').strip("'")


# ------------- Ingestor -------------

class LogIngestor(threading.Thread):
	def __init__(self, db: Database, source: str = "auto") -> None:
		super().__init__(daemon=True)
		self.db = db
		self.source = source
		self._stop_event = threading.Event()
		self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=10000)

	def stop(self) -> None:
		self._stop_event.set()

	def run(self) -> None:
		# Producer and consumer pattern so parsing/writes are resilient
		producer = threading.Thread(target=self._produce, daemon=True)
		producer.start()
		while not self._stop_event.is_set():
			try:
				record = self._queue.get(timeout=1)
				self.db.insert_log(record)
				self._queue.task_done()
			except queue.Empty:
				continue
			except Exception:
				# Avoid thread dying silently
				time.sleep(0.1)

	def _produce(self) -> None:
		# Decide source
		source = self.source
		if source == "auto":
			# Prefer docker if available
			if self._docker_available(COWRIE_DOCKER_NAME):
				source = "docker"
			elif os.path.isdir(COWRIE_LOG_DIR):
				source = "files"
			else:
				source = "none"

		if source == "docker":
			self._stream_from_docker(COWRIE_DOCKER_NAME)
		elif source == "files":
			self._tail_from_files(COWRIE_LOG_DIR)
		else:
			# No source, but keep thread alive to avoid crashing app
			while not self._stop_event.is_set():
				time.sleep(1)

	def _docker_available(self, container_name: str) -> bool:
		try:
			result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=5)
			if result.returncode != 0:
				return False
			return container_name in result.stdout.splitlines()
		except Exception:
			return False

	def _stream_from_docker(self, container_name: str) -> None:
		process = None
		try:
			process = subprocess.Popen(
				["docker", "logs", "-f", container_name],
				stdout=subprocess.PIPE,
				stderr=subprocess.STDOUT,
				text=True,
				bufsize=1,
				universal_newlines=True,
			)
			assert process.stdout is not None
			for line in iter(process.stdout.readline, ""):
				if self._stop_event.is_set():
					break
				record = parse_cowrie_line(line)
				if record:
					self._offer(record)
		finally:
			if process is not None:
				try:
					process.kill()
				except Exception:
					pass

	def _tail_from_files(self, log_dir: str) -> None:
		# Prefer cowrie.json (JSON-lines)
		json_log_path = os.path.join(log_dir, "cowrie.json")
		if os.path.isfile(json_log_path):
			self._tail_file(json_log_path)
			return

		# Fallback: any *.log file
		candidates = [
			os.path.join(log_dir, name)
			for name in os.listdir(log_dir)
			if name.endswith(".log") or name.endswith(".txt")
		]
		candidates.sort()
		if candidates:
			self._tail_file(candidates[-1])
			return

		# Nothing found; idle
		while not self._stop_event.is_set():
			time.sleep(1)

	def _tail_file(self, path: str) -> None:
		try:
			with open(path, "r", encoding="utf-8", errors="ignore") as f:
				# Seek to end
				f.seek(0, os.SEEK_END)
				while not self._stop_event.is_set():
					pos = f.tell()
					line = f.readline()
					if not line:
						time.sleep(0.5)
						f.seek(pos)
						continue
					record = parse_cowrie_line(line)
					if record:
						self._offer(record)
		except FileNotFoundError:
			# File disappeared; idle
			while not self._stop_event.is_set():
				time.sleep(1)

	def _offer(self, record: Dict[str, Any]) -> None:
		try:
			# Analyze behavior for this record
			if record.get("attacker_ip"):
				analyze_behavior(record["attacker_ip"], record)
			
			self._queue.put(record, timeout=1)
		except queue.Full:
			# Drop oldest by draining one item
			try:
				self._queue.get_nowait()
			except Exception:
				pass
			try:
				self._queue.put_nowait(record)
			except Exception:
				pass


# ------------- Flask App -------------

def create_app() -> Flask:
	app = Flask(__name__)

	db = Database(DB_PATH)
	app.config["_db"] = db

	# Start ingestor thread
	ingestor = LogIngestor(db, source=INGEST_FROM)
	ingestor.start()
	app.config["_ingestor"] = ingestor

	# Graceful shutdown
	def _graceful_shutdown(*_: Any) -> None:
		try:
			app.config.get("_ingestor").stop()
		except Exception:
			pass
		os._exit(0)

	signal.signal(signal.SIGINT, _graceful_shutdown)
	signal.signal(signal.SIGTERM, _graceful_shutdown)

	# ---------- Pages ----------
	@app.route("/")
	def index() -> str:
		return render_template("index.html")

	@app.route("/logs")
	def logs_page() -> str:
		return render_template("logs.html")

	@app.route("/analytics")
	def analytics_page() -> str:
		return render_template("analytics.html")

	@app.route("/map")
	def map_page() -> str:
		return render_template("map.html")

	@app.route("/insights")
	def insights_page() -> str:
		return render_template("insights.html")

	@app.route("/threat-hunting")
	def threat_hunting_page() -> str:
		return render_template("threat_hunting.html")

	@app.route("/session-replay")
	def session_replay_page() -> str:
		return render_template("session_replay.html")

	@app.route("/about")
	def about_page() -> str:
		return render_template("about.html")

	# ---------- APIs ----------
	@app.route("/api/logs")
	def api_logs() -> Response:
		page = int(request.args.get("page", 1))
		page_size = min(int(request.args.get("page_size", 50)), 500)
		ip = request.args.get("ip") or None
		since_hours = request.args.get("since_hours")
		since_hours_int = int(since_hours) if since_hours else None
		q = request.args.get("q") or None
		command_keyword = request.args.get("command") or None

		data, total = db.fetch_logs(
			page=page,
			page_size=page_size,
			ip=ip,
			since_hours=since_hours_int,
			q=q,
			command_keyword=command_keyword,
		)
		
		# Add command analysis to each log entry
		for entry in data:
			if entry.get("command"):
				entry["command_analysis"] = analyze_command(entry["command"])
		
		return jsonify({"data": data, "total": total, "page": page, "page_size": page_size})

	@app.route("/api/aggregates")
	def api_aggregates() -> Response:
		since_hours = request.args.get("since_hours")
		since_hours_int = int(since_hours) if since_hours else None
		agg = db.aggregates(since_hours=since_hours_int)
		return jsonify(agg)

	@app.route("/api/geo/top_ips")
	def api_geo_top_ips() -> Response:
		# Reuse aggregates to get top ips and then enrich with geo
		since_hours = request.args.get("since_hours")
		since_hours_int = int(since_hours) if since_hours else None
		agg = db.aggregates(since_hours=since_hours_int)
		ips = [row["ip"] for row in agg.get("top_ips", [])]
		results = []
		for ip in ips:
			geo = geolocate_ip(ip)
			if geo:
				results.append({"ip": ip, **geo})
		return jsonify({"data": results})

	@app.route("/api/threat/intel/<ip>")
	def api_threat_intel(ip: str) -> Response:
		"""Get threat intelligence for a specific IP"""
		result = enrich_threat_intel(ip)
		return jsonify(result)

	@app.route("/api/threat/behavior/<ip>")
	def api_threat_behavior(ip: str) -> Response:
		"""Get behavioral analysis for a specific IP"""
		behavior = _behavior_cache.get(ip, {})
		if behavior:
			# Convert sets to lists for JSON serialization
			behavior["unique_commands"] = list(behavior.get("unique_commands", set()))
			behavior["unique_credentials"] = list(behavior.get("unique_credentials", set()))
			behavior["recent_activity"] = list(behavior.get("recent_activity", []))
		return jsonify(behavior)

	@app.route("/api/threat/analysis/<ip>")
	def api_threat_analysis(ip: str) -> Response:
		"""Get AI-powered threat analysis for a specific IP"""
		result = get_ai_threat_analysis(ip)
		return jsonify(result)

	@app.route("/api/threat/alerts")
	def api_threat_alerts() -> Response:
		"""Get current predictive alerts"""
		alerts = generate_predictive_alerts()
		return jsonify({"alerts": alerts})

	@app.route("/api/threat/dashboard")
	def api_threat_dashboard() -> Response:
		"""Get comprehensive threat dashboard data"""
		# Get top threats by score
		threats = []
		for ip, behavior in _behavior_cache.items():
			threats.append({
				"ip": ip,
				"threat_score": behavior.get("threat_score", 0),
				"total_events": behavior.get("total_events", 0),
				"login_attempts": behavior.get("login_attempts", 0),
				"unique_commands": len(behavior.get("unique_commands", set())),
				"last_seen": behavior.get("last_seen", 0)
			})
		
		# Sort by threat score
		threats.sort(key=lambda x: x["threat_score"], reverse=True)
		
		# Get current alerts
		alerts = generate_predictive_alerts()
		
		return jsonify({
			"top_threats": threats[:10],
			"current_alerts": alerts,
			"total_ips_monitored": len(_behavior_cache),
			"total_events": sum(b.get("total_events", 0) for b in _behavior_cache.values())
		})

	@app.route("/api/session/<session_id>")
	def api_session_replay(session_id: str) -> Response:
		"""Get complete session reconstruction for replay"""
		result = reconstruct_session(session_id)
		return jsonify(result)

	@app.route("/api/session/<session_id>/flow")
	def api_session_flow(session_id: str) -> Response:
		"""Get attack flow visualization data"""
		result = get_session_summary(session_id)
		return jsonify(result)

	@app.route("/api/sessions")
	def api_sessions_list() -> Response:
		"""Get list of all active sessions"""
		with db._lock:
			cur = db._conn.execute(
				"""
				SELECT DISTINCT session_id, attacker_ip, MIN(timestamp) as start_time, MAX(timestamp) as end_time, COUNT(*) as event_count
				FROM logs
				WHERE session_id IS NOT NULL AND session_id != ''
				GROUP BY session_id, attacker_ip
				ORDER BY start_time DESC
				LIMIT 100
				"""
			)
			rows = cur.fetchall()
		
		sessions = []
		for row in rows:
			sessions.append({
				"session_id": row[0],
				"attacker_ip": row[1],
				"start_time": row[2],
				"end_time": row[3],
				"event_count": row[4]
			})
		
		return jsonify({"sessions": sessions})

	@app.route("/api/insights")
	def api_insights() -> Response:
		# Collect recent logs and ask Groq for summary and recommendations
		since_hours = request.args.get("since_hours")
		limit = int(request.args.get("limit", 200))
		since_hours_int = int(since_hours) if since_hours else None
		rows, _total = db.fetch_logs(page=1, page_size=limit, since_hours=since_hours_int)
		lines = []
		for r in rows:
			lines.append(
				f"{r.get('timestamp','')} | IP={r.get('attacker_ip','')} | user={r.get('username','')} | pass={r.get('password','')} | cmd={r.get('command','')} | evt={r.get('event','')}"
			)
		context = "\n".join(lines[:limit])

		prompt = (
			"You are a security analyst. Analyze Cowrie honeypot logs. "
			"Identify attacker patterns, top IPs, common credentials, suspicious commands, and anomalies. "
			"Map notable behaviors to MITRE ATT&CK where applicable. Provide concise remediation advice and firewall rules (CIDR or IP) suggestions. "
			"Output STRICT JSON only (no markdown fences, no prose) with fields: summary (short), findings (array of strings), mitre (array of strings), recommendations (array of strings), firewall_rules (array of strings)."
		)

		try:
			headers = {
				"Content-Type": "application/json",
			}
			text = prompt + "\n\n" + (context or "No recent logs.")
			payload = {
				"contents": [
					{"role": "user", "parts": [{"text": text}]}
				]
			}
			url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
			resp = requests.post(url, headers=headers, json=payload, timeout=30)
			resp.raise_for_status()
			data = resp.json()
			content_text = (
				data.get("candidates", [{}])[0]
					.get("content", {})
					.get("parts", [{}])[0]
					.get("text", "{}")
			)

			# Normalize to clean JSON
			def _strip_fences(s: str) -> str:
				if "```" in s:
					start = s.find("```")
					end = s.rfind("```")
					if start != -1 and end != -1 and end > start:
						inner = s[start+3:end]
						# remove possible language tag
						return "\n".join(inner.splitlines()[1:]) if "\n" in inner else inner
				return s

			clean = _strip_fences(content_text).strip()
			try:
				obj = json.loads(clean)
				# Ensure required keys exist with defaults
				obj.setdefault("summary", "")
				obj.setdefault("findings", [])
				obj.setdefault("mitre", [])
				obj.setdefault("recommendations", [])
				obj.setdefault("firewall_rules", [])
				return jsonify(obj)
			except Exception:
				return jsonify({
					"summary": clean,
					"findings": [],
					"mitre": [],
					"recommendations": [],
					"firewall_rules": [],
				})
		except Exception as e:
			return jsonify({"error": str(e)}), 500

	@app.route("/export.csv")
	def export_csv() -> Response:
		# Reuse fetch with large page size by iterating pages
		ip = request.args.get("ip") or None
		since_hours = request.args.get("since_hours")
		since_hours_int = int(since_hours) if since_hours else None
		q = request.args.get("q") or None
		command_keyword = request.args.get("command") or None

		def generate() -> Iterable[str]:
			yield "id,timestamp,attacker_ip,username,password,command,session_id,event\n"
			page = 1
			page_size = 1000
			while True:
				rows, _total = db.fetch_logs(
					page=page,
					page_size=page_size,
					ip=ip,
					since_hours=since_hours_int,
					q=q,
					command_keyword=command_keyword,
				)
				if not rows:
					break
				for r in rows:
					vals = [
						str(r.get("id", "")),
						csv_safe(r.get("timestamp")),
						csv_safe(r.get("attacker_ip")),
						csv_safe(r.get("username")),
						csv_safe(r.get("password")),
						csv_safe(r.get("command")),
						csv_safe(r.get("session_id")),
						csv_safe(r.get("event")),
					]
					yield ",".join(vals) + "\n"
				page += 1

		headers = {"Content-Disposition": "attachment; filename=honeypot_logs.csv"}
		return Response(generate(), mimetype="text/csv", headers=headers)

	return app


def csv_safe(value: Optional[str]) -> str:
	if value is None:
		return ""
	s = str(value)
	if any(c in s for c in [',', '\n', '"']):
		return '"' + s.replace('"', '""') + '"'
	return s


def geolocate_ip(ip: str) -> Optional[Dict[str, Any]]:
	if not ip:
		return None
	
	# Skip private/local IPs that can't be geolocated
	if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', '169.254.', '::1')):
		print(f"Skipping private IP: {ip}")
		return None
	
	if ip in _geo_cache:
		return _geo_cache[ip]
	
	try:
		url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
		print(f"Geolocating IP: {ip}")
		resp = requests.get(url, timeout=4)
		if resp.status_code != 200:
			print(f"ipinfo.io error for {ip}: {resp.status_code}")
			return None
		data = resp.json()
		loc = data.get("loc")  # "lat,lon"
		if not loc:
			print(f"No location data for {ip}")
			return None
		lat_str, lon_str = loc.split(",")
		geo = {
			"lat": float(lat_str),
			"lon": float(lon_str),
			"city": data.get("city"),
			"region": data.get("region"),
			"country": data.get("country"),
		}
		_geo_cache[ip] = geo
		print(f"Geolocated {ip}: {geo}")
		return geo
	except Exception as e:
		print(f"Error geolocating {ip}: {e}")
		return None


# ------------- Threat Intelligence & Behavioral Analysis -------------

def enrich_threat_intel(ip: str) -> Dict[str, Any]:
	"""Enrich IP with threat intelligence from multiple sources"""
	if not ip or ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', '169.254.', '::1')):
		return {"error": "Private IP, cannot enrich"}
	
	result = {"ip": ip, "sources": {}}
	
	# VirusTotal enrichment
	if VIRUSTOTAL_API_KEY:
		try:
			vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
			headers = {"x-apikey": VIRUSTOTAL_API_KEY}
			resp = requests.get(vt_url, headers=headers, timeout=5)
			if resp.status_code == 200:
				data = resp.json()
				stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
				result["sources"]["virustotal"] = {
					"malicious": stats.get("malicious", 0),
					"suspicious": stats.get("suspicious", 0),
					"harmless": stats.get("harmless", 0),
					"undetected": stats.get("undetected", 0)
				}
		except Exception as e:
			result["sources"]["virustotal"] = {"error": str(e)}
	
	# AbuseIPDB enrichment
	if ABUSEIPDB_API_KEY:
		try:
			abuse_url = f"https://api.abuseipdb.com/api/v2/check"
			params = {"ipAddress": ip, "maxAgeInDays": "90"}
			headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
			resp = requests.get(abuse_url, params=params, headers=headers, timeout=5)
			if resp.status_code == 200:
				data = resp.json()
				result["sources"]["abuseipdb"] = {
					"abuse_confidence": data.get("data", {}).get("abuseConfidenceScore", 0),
					"country": data.get("data", {}).get("countryCode"),
					"usage_type": data.get("data", {}).get("usageType")
				}
		except Exception as e:
			result["sources"]["abuseipdb"] = {"error": str(e)}
	
	return result


def analyze_behavior(ip: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
	"""Analyze behavioral patterns for an IP address"""
	now = time.time()
	
	if ip not in _behavior_cache:
		_behavior_cache[ip] = {
			"first_seen": now,
			"last_seen": now,
			"total_events": 0,
			"unique_commands": set(),
			"unique_credentials": set(),
			"login_attempts": 0,
			"command_attempts": 0,
			"session_count": 0,
			"recent_activity": deque(maxlen=100)
		}
	
	behavior = _behavior_cache[ip]
	behavior["last_seen"] = now
	behavior["total_events"] += 1
	
	# Track recent activity
	behavior["recent_activity"].append({
		"timestamp": now,
		"event": event_data.get("event"),
		"command": event_data.get("command"),
		"username": event_data.get("username")
	})
	
	# Count event types
	if event_data.get("event") == "login":
		behavior["login_attempts"] += 1
	if event_data.get("command"):
		behavior["command_attempts"] += 1
		behavior["unique_commands"].add(event_data.get("command"))
	if event_data.get("username") and event_data.get("password"):
		behavior["unique_credentials"].add(f"{event_data.get('username')}:{event_data.get('password')}")
	if event_data.get("session_id"):
		behavior["session_count"] += 1
	
	# Calculate threat score
	threat_score = 0
	threat_score += min(behavior["login_attempts"] * 2, 20)  # Max 20 for login attempts
	threat_score += min(len(behavior["unique_commands"]) * 3, 30)  # Max 30 for command variety
	threat_score += min(len(behavior["unique_credentials"]) * 5, 25)  # Max 25 for credential attempts
	threat_score += min(behavior["total_events"] // 10, 25)  # Max 25 for volume
	
	# Check for rapid-fire attacks (last 5 minutes)
	recent_events = [e for e in behavior["recent_activity"] if now - e["timestamp"] < 300]
	if len(recent_events) > 20:
		threat_score += 20  # Bonus for rapid attacks
	
	behavior["threat_score"] = min(threat_score, 100)
	
	return behavior


def generate_predictive_alerts() -> List[Dict[str, Any]]:
	"""Generate predictive alerts based on current patterns"""
	alerts = []
	now = time.time()
	
	# Analyze all IPs for patterns
	for ip, behavior in _behavior_cache.items():
		# DDoS prediction
		recent_events = [e for e in behavior["recent_activity"] if now - e["timestamp"] < 300]
		if len(recent_events) > 50:
			alerts.append({
				"type": "ddos_warning",
				"ip": ip,
				"message": f"IP {ip} showing DDoS-like behavior: {len(recent_events)} events in 5 minutes",
				"severity": "high",
				"timestamp": now
			})
		
		# Credential stuffing prediction
		if behavior["login_attempts"] > 100:
			alerts.append({
				"type": "credential_stuffing",
				"ip": ip,
				"message": f"IP {ip} likely performing credential stuffing: {behavior['login_attempts']} attempts",
				"severity": "medium",
				"timestamp": now
			})
		
		# Reconnaissance prediction
		if len(behavior["unique_commands"]) > 20:
			alerts.append({
				"type": "reconnaissance",
				"ip": ip,
				"message": f"IP {ip} performing extensive reconnaissance: {len(behavior['unique_commands'])} unique commands",
				"severity": "medium",
				"timestamp": now
			})
	
	return alerts


def get_ai_threat_analysis(ip: str) -> Dict[str, Any]:
	"""Get AI-powered threat analysis for a specific IP"""
	behavior = _behavior_cache.get(ip, {})
	if not behavior:
		return {"error": "No behavior data for this IP"}
	
	# Prepare context for AI analysis
	context = f"""
IP: {ip}
Total Events: {behavior.get('total_events', 0)}
Login Attempts: {behavior.get('login_attempts', 0)}
Unique Commands: {len(behavior.get('unique_commands', set()))}
Unique Credentials: {len(behavior.get('unique_credentials', set()))}
Threat Score: {behavior.get('threat_score', 0)}
First Seen: {time.ctime(behavior.get('first_seen', 0))}
Last Seen: {time.ctime(behavior.get('last_seen', 0))}
Recent Commands: {', '.join(list(behavior.get('unique_commands', set()))[:10])}
	"""
	
	prompt = (
		"You are a cybersecurity threat analyst. Analyze this IP's behavior and provide: "
		"1. Threat level assessment (Low/Medium/High/Critical) "
		"2. Likely attack type "
		"3. Immediate actions to take "
		"4. Long-term monitoring recommendations "
		"Output as JSON: {threat_level, attack_type, immediate_actions, monitoring_recommendations}"
	)
	
	try:
		headers = {"Content-Type": "application/json"}
		payload = {
			"contents": [{"role": "user", "parts": [{"text": prompt + "\n\n" + context}]}]
		}
		url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
		resp = requests.post(url, headers=headers, json=payload, timeout=30)
		resp.raise_for_status()
		data = resp.json()
		content_text = (
			data.get("candidates", [{}])[0]
				.get("content", {})
				.get("parts", [{}])[0]
				.get("text", "{}")
		)
		
		try:
			return json.loads(content_text)
		except Exception:
			return {"summary": content_text}
	except Exception as e:
		return {"error": str(e)}


# ------------- Session Reconstruction & Command Analysis -------------

def reconstruct_session(session_id: str) -> Dict[str, Any]:
	"""Reconstruct a complete attack session timeline"""
	if not session_id:
		return {"error": "No session ID provided"}
	
	# Get all events for this session
	with db._lock:
		cur = db._conn.execute(
			"""
			SELECT id, timestamp, attacker_ip, username, password, command, session_id, event
			FROM logs
			WHERE session_id = ?
			ORDER BY timestamp ASC
			""",
			(session_id,)
		)
		rows = cur.fetchall()
	
	if not rows:
		return {"error": "Session not found"}
	
	# Group by IP and reconstruct timeline
	sessions = {}
	for row in rows:
		ip = row[2]  # attacker_ip
		if ip not in sessions:
			sessions[ip] = {
				"session_id": session_id,
				"attacker_ip": ip,
				"start_time": row[1],  # timestamp
				"end_time": row[1],
				"total_events": 0,
				"timeline": [],
				"attack_flow": [],
				"summary": {
					"login_attempts": 0,
					"commands_executed": 0,
					"unique_commands": set(),
					"credentials_tried": set()
				}
			}
		
		session = sessions[ip]
		session["total_events"] += 1
		session["end_time"] = row[1]
		
		event = {
			"id": row[0],
			"timestamp": row[1],
			"event_type": row[7],  # event
			"username": row[3],
			"password": row[4],
			"command": row[5],
			"analysis": analyze_command(row[5]) if row[5] else None
		}
		
		session["timeline"].append(event)
		
		# Update summary
		if event["event_type"] == "login":
			session["summary"]["login_attempts"] += 1
			if event["username"] and event["password"]:
				session["summary"]["credentials_tried"].add(f"{event['username']}:{event['password']}")
		if event["command"]:
			session["summary"]["commands_executed"] += 1
			session["summary"]["unique_commands"].add(event["command"])
		
		# Build attack flow
		if event["command"]:
			session["attack_flow"].append({
				"step": len(session["attack_flow"]) + 1,
				"command": event["command"],
				"purpose": event["analysis"]["purpose"] if event["analysis"] else "Unknown",
				"threat_level": event["analysis"]["threat_level"] if event["analysis"] else "Unknown",
				"timestamp": event["timestamp"]
			})
	
	# Convert sets to lists for JSON serialization
	for session in sessions.values():
		session["summary"]["unique_commands"] = list(session["summary"]["unique_commands"])
		session["summary"]["credentials_tried"] = list(session["summary"]["credentials_tried"])
	
	return {"sessions": list(sessions.values())}


def analyze_command(command: str) -> Dict[str, Any]:
	"""Analyze a command and explain what it does and why it's suspicious"""
	if not command:
		return None
	
	command = command.strip().lower()
	
	# Command analysis database
	command_db = {
		# Reconnaissance commands
		"whoami": {"purpose": "User enumeration", "threat_level": "Low", "description": "Shows current user, used for privilege escalation planning"},
		"id": {"purpose": "User enumeration", "threat_level": "Low", "description": "Shows user and group information"},
		"uname": {"purpose": "System information gathering", "threat_level": "Low", "description": "Reveals OS and system architecture"},
		"uname -a": {"purpose": "System information gathering", "threat_level": "Low", "description": "Detailed system information for vulnerability research"},
		"cat /etc/passwd": {"purpose": "User enumeration", "threat_level": "Medium", "description": "Lists all users, potential for privilege escalation"},
		"cat /etc/shadow": {"purpose": "Password hash extraction", "threat_level": "High", "description": "Contains password hashes, critical security breach"},
		"ps aux": {"purpose": "Process enumeration", "threat_level": "Low", "description": "Shows running processes, used for persistence detection"},
		"netstat": {"purpose": "Network reconnaissance", "threat_level": "Medium", "description": "Shows network connections and listening ports"},
		"ss": {"purpose": "Network reconnaissance", "threat_level": "Medium", "description": "Modern netstat alternative, shows socket statistics"},
		"lsof": {"purpose": "File and network enumeration", "threat_level": "Medium", "description": "Lists open files and network connections"},
		
		# File system exploration
		"ls": {"purpose": "File enumeration", "threat_level": "Low", "description": "Lists directory contents, reconnaissance"},
		"ls -la": {"purpose": "File enumeration", "threat_level": "Low", "description": "Detailed file listing including hidden files"},
		"find": {"purpose": "File discovery", "threat_level": "Medium", "description": "Searches for files, can reveal sensitive data"},
		"grep": {"purpose": "Content searching", "threat_level": "Medium", "description": "Searches file contents, can find credentials"},
		
		# Network tools
		"wget": {"purpose": "File download", "threat_level": "High", "description": "Downloads files, potential malware delivery"},
		"curl": {"purpose": "File download", "threat_level": "High", "description": "Downloads files, potential malware delivery"},
		"nc": {"purpose": "Network tool", "threat_level": "High", "description": "Netcat, can be used for reverse shells"},
		"ncat": {"purpose": "Network tool", "threat_level": "High", "description": "Modern netcat, reverse shell capability"},
		"telnet": {"purpose": "Network connection", "threat_level": "Medium", "description": "Unencrypted network connection"},
		"ssh": {"purpose": "Remote access", "threat_level": "Medium", "description": "Secure shell, legitimate but can be abused"},
		
		# Privilege escalation
		"sudo": {"purpose": "Privilege escalation", "threat_level": "High", "description": "Executes commands with elevated privileges"},
		"su": {"purpose": "User switching", "threat_level": "High", "description": "Switch to another user, potential privilege escalation"},
		
		# System manipulation
		"chmod": {"purpose": "File permissions", "threat_level": "Medium", "description": "Changes file permissions, can make files executable"},
		"chown": {"purpose": "File ownership", "threat_level": "Medium", "description": "Changes file ownership"},
		"kill": {"purpose": "Process termination", "threat_level": "Medium", "description": "Terminates processes, can stop security services"},
		
		# Package management
		"apt": {"purpose": "Package management", "threat_level": "Medium", "description": "Installs packages, potential malicious software"},
		"apt-get": {"purpose": "Package management", "threat_level": "Medium", "description": "Installs packages, potential malicious software"},
		"yum": {"purpose": "Package management", "threat_level": "Medium", "description": "Installs packages, potential malicious software"},
		"pip": {"purpose": "Python package management", "threat_level": "Medium", "description": "Installs Python packages, potential malicious code"},
		
		# Shell and execution
		"bash": {"purpose": "Shell execution", "threat_level": "High", "description": "Bash shell, can execute arbitrary commands"},
		"sh": {"purpose": "Shell execution", "threat_level": "High", "description": "Shell execution, command injection risk"},
		"python": {"purpose": "Script execution", "threat_level": "High", "description": "Python interpreter, can run malicious scripts"},
		"perl": {"purpose": "Script execution", "threat_level": "High", "description": "Perl interpreter, can run malicious scripts"},
		
		# Data exfiltration
		"tar": {"purpose": "File compression", "threat_level": "Medium", "description": "Creates archives, potential data exfiltration"},
		"zip": {"purpose": "File compression", "threat_level": "Medium", "description": "Creates archives, potential data exfiltration"},
		"scp": {"purpose": "File transfer", "threat_level": "High", "description": "Secure copy, can exfiltrate data"},
		"rsync": {"purpose": "File synchronization", "threat_level": "High", "description": "File sync, can exfiltrate data"}
	}
	
	# Check for exact matches first
	if command in command_db:
		return command_db[command]
	
	# Check for partial matches
	for cmd, analysis in command_db.items():
		if command.startswith(cmd + " ") or command == cmd:
			return analysis
	
	# Check for suspicious patterns
	suspicious_patterns = [
		("reverse shell", "Reverse shell", "High", "Creates backdoor connection to attacker"),
		("base64", "Data encoding", "Medium", "Encodes/decodes data, can hide malicious content"),
		("eval", "Code execution", "High", "Evaluates arbitrary code, major security risk"),
		("exec", "Code execution", "High", "Executes commands, potential command injection"),
		("system", "Code execution", "High", "System command execution, major security risk"),
		("shell", "Shell access", "High", "Shell access, potential command execution"),
		("download", "File download", "High", "Downloads files, potential malware"),
		("upload", "File upload", "High", "Uploads files, potential data exfiltration"),
		("wget", "File download", "High", "Downloads files, potential malware delivery"),
		("curl", "File download", "High", "Downloads files, potential malware delivery")
	]
	
	for pattern, purpose, threat_level, description in suspicious_patterns:
		if pattern in command:
			return {
				"purpose": purpose,
				"threat_level": threat_level,
				"description": description
			}
	
	# Default analysis for unknown commands
	return {
		"purpose": "Unknown command",
		"threat_level": "Medium",
		"description": "Command not in database, requires manual analysis"
	}


def get_session_summary(session_id: str) -> Dict[str, Any]:
	"""Get a summary of session activity for visualization"""
	session_data = reconstruct_session(session_id)
	if "error" in session_data:
		return session_data
	
	sessions = session_data.get("sessions", [])
	if not sessions:
		return {"error": "No session data found"}
	
	# Get the first session (assuming single IP per session)
	session = sessions[0]
	
	# Build attack flow visualization data
	flow_data = {
		"nodes": [],
		"edges": [],
		"session_info": {
			"id": session_id,
			"ip": session["attacker_ip"],
			"start_time": session["start_time"],
			"end_time": session["end_time"],
			"total_events": session["total_events"]
		}
	}
	
	# Add nodes for each command
	for i, flow_step in enumerate(session["attack_flow"]):
		node_id = f"step_{i+1}"
		flow_data["nodes"].append({
			"id": node_id,
			"label": flow_step["command"][:30] + "..." if len(flow_step["command"]) > 30 else flow_step["command"],
			"full_command": flow_step["command"],
			"purpose": flow_step["purpose"],
			"threat_level": flow_step["threat_level"],
			"timestamp": flow_step["timestamp"],
			"step": flow_step["step"]
		})
		
		# Add edges connecting steps
		if i > 0:
			flow_data["edges"].append({
				"from": f"step_{i}",
				"to": node_id,
				"label": f"Step {i} → {i+1}"
			})
	
	return flow_data


if __name__ == "__main__":
	app = create_app()
	# Ensure folders exist for templates/static if running fresh clone
	os.makedirs(os.path.join(os.path.dirname(__file__), "templates"), exist_ok=True)
	os.makedirs(os.path.join(os.path.dirname(__file__), "static", "js"), exist_ok=True)
	os.makedirs(os.path.join(os.path.dirname(__file__), "static", "css"), exist_ok=True)
	app.run(host="0.0.0.0", port=5000, debug=True)

