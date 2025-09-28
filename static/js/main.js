(function(){
	'use strict';
	
	// Utility functions
	function qs(id){ return document.getElementById(id); }
	function qsa(selector){ return document.querySelectorAll(selector); }
	
	// Enhanced threat badge with more levels
	function getThreatBadge(threatLevel) {
		switch(threatLevel?.toLowerCase()) {
			case 'critical': return 'danger';
			case 'high': return 'danger';
			case 'medium': return 'warning';
			case 'low': return 'success';
			case 'info': return 'info';
			default: return 'secondary';
		}
	}
	
	// Enhanced parameter builder
	function params(obj){
		const sp = new URLSearchParams();
		Object.entries(obj).forEach(([k,v])=>{ 
			if(v!==undefined && v!==null && v!=='') sp.set(k, v); 
		});
		return sp.toString();
	}
	
	// Modern fetch wrapper with error handling
	async function fetchData(url, options = {}) {
		try {
			const response = await fetch(url, {
				...options,
				headers: {
					'Content-Type': 'application/json',
					...options.headers
				}
			});
			
			if (!response.ok) {
				throw new Error(`HTTP error! status: ${response.status}`);
			}
			
			return await response.json();
		} catch (error) {
			console.error('Fetch error:', error);
			showNotification('Error loading data: ' + error.message, 'danger');
			throw error;
		}
	}
	
	// Modern notification system
	function showNotification(message, type = 'info', duration = 5000) {
		const notification = document.createElement('div');
		notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
		notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
		notification.innerHTML = `
			${message}
			<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
		`;
		
		document.body.appendChild(notification);
		
		// Auto remove after duration
		setTimeout(() => {
			if (notification.parentNode) {
				notification.remove();
			}
		}, duration);
	}
	
	// Loading state manager
	function setLoadingState(element, isLoading, message = 'Loading...') {
		if (isLoading) {
			element.classList.add('loading');
			if (element.dataset.originalContent === undefined) {
				element.dataset.originalContent = element.innerHTML;
			}
			element.innerHTML = `
				<div class="d-flex align-items-center">
					<div class="spinner-border spinner-border-sm me-2" role="status"></div>
					${message}
				</div>
			`;
		} else {
			element.classList.remove('loading');
			if (element.dataset.originalContent) {
				element.innerHTML = element.dataset.originalContent;
				delete element.dataset.originalContent;
			}
		}
	}
	
	// Enhanced chart configuration
	const chartDefaults = {
		responsive: true,
		maintainAspectRatio: false,
		plugins: {
			legend: {
				labels: {
					color: '#ddd',
					font: {
						family: 'Inter, sans-serif'
					}
				}
			},
			tooltip: {
				backgroundColor: 'rgba(0, 0, 0, 0.8)',
				titleColor: '#fff',
				bodyColor: '#fff',
				borderColor: 'rgba(255, 255, 255, 0.1)',
				borderWidth: 1
			}
		},
		scales: {
			x: {
				ticks: { color: '#ddd' },
				grid: { color: 'rgba(255, 255, 255, 0.1)' }
			},
			y: {
				ticks: { color: '#ddd' },
				grid: { color: 'rgba(255, 255, 255, 0.1)' }
			}
		}
	};

	// Dashboard (index): Enhanced chart rendering with modern features
	async function fetchAggregates(hours){
		const url = '/api/aggregates' + (hours ? ('?since_hours='+hours) : '');
		return await fetchData(url);
	}

	let chartTopIPs, chartAttempts, chartCreds;
	
	// Enhanced chart rendering with animations and better styling
	function renderCharts(data){
		const top = data.top_ips || [];
		const creds = data.top_credentials || [];
		const over = data.attempts_over_time || [];

		// Top IPs Chart
		if(qs('chartTopIPs')){
			const labels = top.map(x=>x.ip);
			const values = top.map(x=>x.count);
			chartTopIPs && chartTopIPs.destroy();
			chartTopIPs = new Chart(qs('chartTopIPs'), {
				type: 'bar',
				data: {
					labels,
					datasets: [{
						label: 'Attack Attempts',
						data: values,
						backgroundColor: 'rgba(13, 110, 253, 0.8)',
						borderColor: 'rgba(13, 110, 253, 1)',
						borderWidth: 1,
						borderRadius: 4,
						borderSkipped: false,
					}]
				},
				options: {
					...chartDefaults,
					plugins: {
						...chartDefaults.plugins,
						legend: { display: false }
					},
					animation: {
						duration: 1000,
						easing: 'easeInOutQuart'
					}
				}
			});
		}
		
		// Timeline Chart
		if(qs('chartAttempts')){
			const labels = over.map(x=>x.hour);
			const values = over.map(x=>x.count);
			chartAttempts && chartAttempts.destroy();
			chartAttempts = new Chart(qs('chartAttempts'), {
				type: 'line',
				data: {
					labels,
					datasets: [{
						label: 'Attack Timeline',
						data: values,
						borderColor: 'rgba(32, 201, 151, 1)',
						backgroundColor: 'rgba(32, 201, 151, 0.1)',
						borderWidth: 3,
						fill: true,
						tension: 0.4,
						pointBackgroundColor: 'rgba(32, 201, 151, 1)',
						pointBorderColor: '#fff',
						pointBorderWidth: 2,
						pointRadius: 5,
						pointHoverRadius: 8
					}]
				},
				options: {
					...chartDefaults,
					plugins: {
						...chartDefaults.plugins,
						legend: { display: false }
					},
					animation: {
						duration: 1500,
						easing: 'easeInOutQuart'
					}
				}
			});
		}
		
		// Credentials Chart
		if(qs('chartCreds')){
			const labels = creds.map(x=>x.credential);
			const values = creds.map(x=>x.count);
			chartCreds && chartCreds.destroy();
			chartCreds = new Chart(qs('chartCreds'), {
				type: 'bar',
				data: {
					labels,
					datasets: [{
						label: 'Credential Usage',
						data: values,
						backgroundColor: 'rgba(255, 193, 7, 0.8)',
						borderColor: 'rgba(255, 193, 7, 1)',
						borderWidth: 1,
						borderRadius: 4,
						borderSkipped: false,
					}]
				},
				options: {
					...chartDefaults,
					plugins: {
						...chartDefaults.plugins,
						legend: { display: false }
					},
					animation: {
						duration: 1200,
						easing: 'easeInOutQuart'
					}
				}
			});
		}
		
		// Update metrics if function exists
		if (typeof updateMetrics === 'function') {
			updateMetrics(data);
		}
	}

	// Enhanced dashboard initialization
	async function initIndex(){
		if(!qs('chartTopIPs')) return;
		
		let hours = 24;
		let refreshInterval;
		
		async function refresh(){
			try {
				const data = await fetchAggregates(hours);
				renderCharts(data);
				showNotification('Dashboard updated successfully', 'success', 2000);
			} catch (error) {
				console.error('Dashboard refresh error:', error);
			}
		}
		
		// Initial load
		await refresh();
		
		// Set up auto-refresh
		refreshInterval = setInterval(refresh, 30000); // 30 seconds
		
		// Clean up on page unload
		window.addEventListener('beforeunload', () => {
			if (refreshInterval) {
				clearInterval(refreshInterval);
			}
		});
	}

	// Enhanced logs page with modern DataTables
	function initLogs(){
		const tableEl = $('#logsTable');
		if(!tableEl.length) return;
		
		let dt = tableEl.DataTable({
			searching: false,
			serverSide: true,
			processing: true,
			pageLength: 25,
			language: {
				processing: '<div class="d-flex align-items-center"><div class="spinner-border spinner-border-sm me-2" role="status"></div>Loading logs...</div>',
				emptyTable: 'No attack logs found',
				zeroRecords: 'No matching records found'
			},
			ajax: async function(data, callback){
				try {
					const page = Math.floor(data.start / data.length) + 1;
					const page_size = data.length;
					const query = {
						page, page_size,
						ip: qs('filter-ip')?.value?.trim() || '',
						since_hours: qs('filter-hours')?.value || '24',
						q: qs('filter-q')?.value?.trim() || '',
						command: qs('filter-command')?.value?.trim() || '',
					};
					
					const url = '/api/logs?' + params(query);
					const json = await fetchData(url);
					
					// Update stats if function exists
					if (typeof updateLogStats === 'function') {
						updateLogStats(json);
					}
					
					callback({
						draw: data.draw,
						recordsTotal: json.total,
						recordsFiltered: json.total,
						data: json.data.map(r=>[
							formatTimestamp(r.timestamp),
							formatIP(r.attacker_ip),
							formatUsername(r.username),
							formatPassword(r.password),
							formatCommand(r.command),
							formatSession(r.session_id),
							formatEvent(r.event),
							formatAnalysis(r.command_analysis)
						])
					});
				} catch (error) {
					console.error('Logs table error:', error);
					callback({
						draw: data.draw,
						recordsTotal: 0,
						recordsFiltered: 0,
						data: []
					});
				}
			},
			order: [[0,'desc']],
			columnDefs: [
				{ targets: [0], className: 'text-center' },
				{ targets: [1], className: 'font-monospace' },
				{ targets: [2,3], className: 'font-monospace' },
				{ targets: [4], className: 'font-monospace', width: '200px' },
				{ targets: [5], className: 'font-monospace' },
				{ targets: [6], className: 'text-center' },
				{ targets: [7], className: 'text-center' }
			]
		});
		
		// Enhanced filter handling
		$('#apply-filters').on('click', ()=> {
			dt.ajax.reload();
			showNotification('Filters applied', 'info', 2000);
		});
		
		// Auto-refresh with better error handling
		let autoRefreshInterval;
		function startAutoRefresh() {
			if (autoRefreshInterval) clearInterval(autoRefreshInterval);
			autoRefreshInterval = setInterval(()=>{ 
				if(qs('auto-refresh')?.checked) {
					dt.ajax.reload(null, false);
				}
			}, 10000); // 10 seconds
		}
		
		startAutoRefresh();
		
		// Auto-refresh toggle handler
		qs('auto-refresh')?.addEventListener('change', function() {
			if (this.checked) {
				startAutoRefresh();
				showNotification('Auto-refresh enabled', 'success', 2000);
			} else {
				if (autoRefreshInterval) {
					clearInterval(autoRefreshInterval);
					autoRefreshInterval = null;
				}
				showNotification('Auto-refresh disabled', 'info', 2000);
			}
		});

		// Enhanced CSV export
		function updateCsvLink(){
			const query = {
				ip: qs('filter-ip')?.value?.trim() || '',
				since_hours: qs('filter-hours')?.value || '24',
				q: qs('filter-q')?.value?.trim() || '',
				command: qs('filter-command')?.value?.trim() || '',
			};
			const csvLink = qs('exportCsvLink');
			if (csvLink) {
				csvLink.href = '/export.csv?' + params(query);
			}
		}
		
		['filter-ip','filter-hours','filter-q','filter-command'].forEach(id=>{
			const element = qs(id);
			if (element) {
				element.addEventListener('input', updateCsvLink);
				element.addEventListener('change', updateCsvLink);
			}
		});
		updateCsvLink();
		
		// Clean up on page unload
		window.addEventListener('beforeunload', () => {
			if (autoRefreshInterval) {
				clearInterval(autoRefreshInterval);
			}
		});
	}
	
	// Enhanced data formatting functions
	function formatTimestamp(timestamp) {
		if (!timestamp) return '-';
		const date = new Date(timestamp);
		return `<span title="${date.toLocaleString()}">${date.toLocaleTimeString()}</span>`;
	}
	
	function formatIP(ip) {
		if (!ip) return '-';
		return `<span class="font-monospace">${ip}</span>`;
	}
	
	function formatUsername(username) {
		if (!username) return '-';
		return `<span class="font-monospace">${username}</span>`;
	}
	
	function formatPassword(password) {
		if (!password) return '-';
		return `<span class="font-monospace text-muted">${'*'.repeat(password.length)}</span>`;
	}
	
	function formatCommand(command) {
		if (!command) return '-';
		const truncated = command.length > 50 ? command.substring(0, 50) + '...' : command;
		return `<span class="font-monospace" title="${command}">${truncated}</span>`;
	}
	
	function formatSession(sessionId) {
		if (!sessionId) return '-';
		return `<span class="font-monospace">${sessionId.substring(0, 8)}...</span>`;
	}
	
	function formatEvent(event) {
		if (!event) return '-';
		const badgeClass = event === 'login' ? 'bg-warning' : 'bg-info';
		return `<span class="badge ${badgeClass}">${event}</span>`;
	}
	
	function formatAnalysis(analysis) {
		if (!analysis) return '-';
		return `<span class="badge bg-${getThreatBadge(analysis.threat_level)}" title="${analysis.description}">${analysis.purpose}</span>`;
	}

	// Enhanced analytics page initialization
	async function initAnalytics(){
		if(!qs('analytics-hours')) return;
		
		async function refresh(){
			try {
				const hours = qs('analytics-hours').value;
				const data = await fetchAggregates(hours);
				renderCharts(data);
				
				// Update analytics KPIs if function exists
				if (typeof updateAnalyticsKPIs === 'function') {
					updateAnalyticsKPIs(data);
				}
				
				showNotification('Analytics updated successfully', 'success', 2000);
			} catch (error) {
				console.error('Analytics refresh error:', error);
			}
		}
		
		const refreshBtn = qs('refresh-analytics');
		if (refreshBtn) {
			refreshBtn.addEventListener('click', refresh);
		}
		
		// Initial load
		await refresh();
	}
	
	// Global initialization with error handling
	document.addEventListener('DOMContentLoaded', async function(){
		try {
			// Initialize all components
			await Promise.all([
				initIndex(),
				initLogs(),
				initAnalytics()
			]);
			
			// Add global keyboard shortcuts
			document.addEventListener('keydown', function(e) {
				// Ctrl/Cmd + R to refresh current page data
				if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
					e.preventDefault();
					if (typeof refreshDashboard === 'function') {
						refreshDashboard();
					} else if (typeof refreshLogs === 'function') {
						refreshLogs();
					} else if (typeof refreshAnalytics === 'function') {
						refreshAnalytics();
					}
				}
				
				// Escape to close any open modals
				if (e.key === 'Escape') {
					const modals = document.querySelectorAll('.modal.show');
					modals.forEach(modal => {
						const bsModal = bootstrap.Modal.getInstance(modal);
						if (bsModal) bsModal.hide();
					});
				}
			});
			
			// Add smooth scrolling for anchor links
			document.querySelectorAll('a[href^="#"]').forEach(anchor => {
				anchor.addEventListener('click', function (e) {
					e.preventDefault();
					const target = document.querySelector(this.getAttribute('href'));
					if (target) {
						target.scrollIntoView({
							behavior: 'smooth',
							block: 'start'
						});
					}
				});
			});
			
			// Add tooltip initialization
			const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
			tooltipTriggerList.map(function (tooltipTriggerEl) {
				return new bootstrap.Tooltip(tooltipTriggerEl);
			});
			
			// Add popover initialization
			const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
			popoverTriggerList.map(function (popoverTriggerEl) {
				return new bootstrap.Popover(popoverTriggerEl);
			});
			
			// Show welcome notification
			setTimeout(() => {
				showNotification('Welcome to Rudra Honeypot Dashboard!', 'info', 3000);
			}, 1000);
			
		} catch (error) {
			console.error('Initialization error:', error);
			showNotification('Error initializing dashboard: ' + error.message, 'danger', 5000);
		}
	});
	
	// Export functions for global access
	window.showNotification = showNotification;
	window.setLoadingState = setLoadingState;
	window.fetchData = fetchData;
	
})();

