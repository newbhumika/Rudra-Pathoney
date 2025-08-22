(function(){
	function qs(id){ return document.getElementById(id); }
	
	function getThreatBadge(threatLevel) {
		switch(threatLevel?.toLowerCase()) {
			case 'high': return 'danger';
			case 'medium': return 'warning';
			case 'low': return 'success';
			default: return 'secondary';
		}
	}
	function params(obj){
		const sp = new URLSearchParams();
		Object.entries(obj).forEach(([k,v])=>{ if(v!==undefined && v!==null && v!=='') sp.set(k, v); });
		return sp.toString();
	}

	// Dashboard (index): render charts and refresh periodically
	function fetchAggregates(hours){
		const url = '/api/aggregates' + (hours ? ('?since_hours='+hours) : '');
		return fetch(url).then(r=>r.json());
	}

	let chartTopIPs, chartAttempts, chartCreds;
	function renderCharts(data){
		const top = data.top_ips || [];
		const creds = data.top_credentials || [];
		const over = data.attempts_over_time || [];

		if(qs('chartTopIPs')){
			const labels = top.map(x=>x.ip);
			const values = top.map(x=>x.count);
			chartTopIPs && chartTopIPs.destroy();
			chartTopIPs = new Chart(qs('chartTopIPs'), {
				type: 'bar', data: { labels, datasets: [{ label: 'Attempts', data: values, backgroundColor: '#0d6efd' }] }, options: { plugins:{legend:{display:false}}, scales:{x:{ticks:{color:'#ddd'}},y:{ticks:{color:'#ddd'}}}}
			});
		}
		if(qs('chartAttempts')){
			const labels = over.map(x=>x.hour);
			const values = over.map(x=>x.count);
			chartAttempts && chartAttempts.destroy();
			chartAttempts = new Chart(qs('chartAttempts'), {
				type: 'line', data: { labels, datasets: [{ label: 'Attempts', data: values, borderColor: '#20c997', tension: .2 }] }, options: { plugins:{legend:{display:false}}, scales:{x:{ticks:{color:'#ddd'}},y:{ticks:{color:'#ddd'}}}}
			});
		}
		if(qs('chartCreds')){
			const labels = creds.map(x=>x.credential);
			const values = creds.map(x=>x.count);
			chartCreds && chartCreds.destroy();
			chartCreds = new Chart(qs('chartCreds'), {
				type: 'bar', data: { labels, datasets: [{ label: 'Occurrences', data: values, backgroundColor: '#ffc107' }] }, options: { plugins:{legend:{display:false}}, scales:{x:{ticks:{color:'#ddd'}},y:{ticks:{color:'#ddd'}}}}
			});
		}
	}

	function initIndex(){
		if(!qs('chartTopIPs')) return;
		let hours = 24;
		function refresh(){ fetchAggregates(hours).then(renderCharts); }
		refresh();
		setInterval(refresh, 10000);
	}

	// Logs page: DataTables with filters and polling
	function initLogs(){
		const tableEl = $('#logsTable');
		if(!tableEl.length) return;
		let dt = tableEl.DataTable({
			searching: false,
			serverSide: true,
			processing: true,
			pageLength: 25,
			ajax: function(data, callback){
				const page = Math.floor(data.start / data.length) + 1;
				const page_size = data.length;
				const query = {
					page, page_size,
					ip: qs('filter-ip').value.trim(),
					since_hours: qs('filter-hours').value,
					q: qs('filter-q').value.trim(),
					command: qs('filter-command').value.trim(),
				};
				const url = '/api/logs?' + params(query);
				fetch(url).then(r=>r.json()).then(json=>{
					callback({
						draw: data.draw,
						recordsTotal: json.total,
						recordsFiltered: json.total,
						data: json.data.map(r=>[
							r.timestamp, r.attacker_ip||'', r.username||'', r.password||'', r.command||'', r.session_id||'', r.event||'', 
							r.command_analysis ? `<span class="badge bg-${getThreatBadge(r.command_analysis.threat_level)}" title="${r.command_analysis.description}">${r.command_analysis.purpose}</span>` : '-'
						])
					});
				});
			},
			order: [[0,'desc']]
		});
		$('#apply-filters').on('click', ()=> dt.ajax.reload());
		setInterval(()=>{ if(qs('auto-refresh').checked) dt.ajax.reload(null,false); }, 8000);

		// CSV export link
		function updateCsvLink(){
			const query = {
				ip: qs('filter-ip').value.trim(),
				since_hours: qs('filter-hours').value,
				q: qs('filter-q').value.trim(),
				command: qs('filter-command').value.trim(),
			};
			qs('exportCsvLink').href = '/export.csv?' + params(query);
		}
		['filter-ip','filter-hours','filter-q','filter-command'].forEach(id=>{
			qs(id).addEventListener('input', updateCsvLink);
			qs(id).addEventListener('change', updateCsvLink);
		});
		updateCsvLink();
	}

	// Analytics page: reuse charts, with a dropdown and button
	function initAnalytics(){
		if(!qs('analytics-hours')) return;
		function refresh(){
			const hours = qs('analytics-hours').value;
			fetchAggregates(hours).then(renderCharts);
		}
		qs('refresh-analytics').addEventListener('click', refresh);
		refresh();
	}

	document.addEventListener('DOMContentLoaded', function(){
		initIndex();
		initLogs();
		initAnalytics();
	});
})();
