import * as fs from 'fs';
import * as path from 'path';

export type ReportFormat = 'json' | 'csv' | 'html';

export interface CheckResult {
	status: number | string;
	method: string;
	payload: string;
	responseTime: number;
	category: string;
	is_redirect?: boolean;
	error?: string;
}

export interface BatchResult {
	url: string;
	success: boolean;
	total: number;
	blocked: number;
	bypassed: number;
	bypassRate: number;
	error?: string;
}

/**
 * Deduce report format from file extension if not explicitly specified.
 */
export function deduceFormat(outputPath: string): ReportFormat {
	const ext = path.extname(outputPath).toLowerCase();
	if (ext === '.json') return 'json';
	if (ext === '.csv') return 'csv';
	if (ext === '.html' || ext === '.htm') return 'html';
	return 'html'; // Default to html
}

/**
 * Generate a CSV report for CheckResults.
 */
function generateCheckCsv(results: CheckResult[]): string {
	const headers = ['Category', 'Method', 'Status', 'Response Time (ms)', 'Is Redirect', 'Payload', 'Error'];
	const escape = (val: any) => {
		const str = String(val ?? '');
		if (str.includes(',') || str.includes('"') || str.includes('\n')) {
			return `"${str.replace(/"/g, '""')}"`;
		}
		return str;
	};

	const lines = [
		headers.join(','),
		...results.map(r => [
			escape(r.category),
			escape(r.method),
			escape(r.status),
			escape(r.responseTime),
			escape(r.is_redirect ? 'Yes' : 'No'),
			escape(r.payload),
			escape(r.error)
		].join(','))
	];

	return lines.join('\n');
}

/**
 * Generate a CSV report for BatchResults.
 */
function generateBatchCsv(results: BatchResult[]): string {
	const headers = ['Target URL', 'Success', 'Total Tests', 'Blocked', 'Bypassed', 'Bypass Rate (%)', 'Error'];
	const escape = (val: any) => {
		const str = String(val ?? '');
		if (str.includes(',') || str.includes('"') || str.includes('\n')) {
			return `"${str.replace(/"/g, '""')}"`;
		}
		return str;
	};

	const lines = [
		headers.join(','),
		...results.map(r => [
			escape(r.url),
			escape(r.success ? 'Yes' : 'No'),
			escape(r.total),
			escape(r.blocked),
			escape(r.bypassed),
			escape(r.bypassRate),
			escape(r.error)
		].join(','))
	];

	return lines.join('\n');
}

/**
 * Generate a beautiful HTML report for CheckResults.
 */
function generateCheckHtml(url: string, results: CheckResult[]): string {
	const total = results.length;
	const blocked = results.filter(r => r.status === 403 || r.status === 'BLOCKED').length;
	const bypassed = results.filter(r => r.status === 200 || r.status === '200').length;
	const redirect = results.filter(r => r.is_redirect).length;
	const errors = results.filter(r => r.status === 'ERR' || r.error).length;

	const blockRate = total ? Math.round((blocked / total) * 100) : 0;
	const bypassRate = total ? Math.round((bypassed / total) * 100) : 0;

	// Escape JSON for embedded script
	const escapedJson = JSON.stringify(results).replace(/</g, '\\u003c');

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>WAF Audit Report - ${url}</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
	<style>
		:root {
			--bg-color: #0b0f19;
			--card-bg: rgba(22, 29, 49, 0.7);
			--card-border: rgba(255, 255, 255, 0.08);
			--text-main: #f3f4f6;
			--text-muted: #9ca3af;
			--primary: #6366f1;
			--primary-hover: #4f46e5;
			--green: #10b981;
			--red: #ef4444;
			--yellow: #f59e0b;
			--blue: #3b82f6;
		}

		* {
			box-sizing: border-box;
			margin: 0;
			padding: 0;
		}

		body {
			font-family: 'Outfit', sans-serif;
			background-color: var(--bg-color);
			color: var(--text-main);
			line-height: 1.5;
			padding: 2rem;
			background-image: 
				radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
				radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.08) 0px, transparent 50%);
			background-attachment: fixed;
		}

		header {
			max-width: 1200px;
			margin: 0 auto 2rem auto;
			display: flex;
			justify-content: space-between;
			align-items: center;
			flex-wrap: wrap;
			gap: 1rem;
		}

		.title-area h1 {
			font-size: 2.5rem;
			font-weight: 800;
			background: linear-gradient(135deg, #fff 30%, #a5b4fc 100%);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			margin-bottom: 0.25rem;
		}

		.title-area p {
			color: var(--text-muted);
			font-family: 'JetBrains Mono', monospace;
			font-size: 0.95rem;
		}

		.badge {
			display: inline-block;
			padding: 0.25rem 0.75rem;
			border-radius: 9999px;
			font-size: 0.85rem;
			font-weight: 600;
			text-transform: uppercase;
		}

		.badge-success { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
		.badge-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
		.badge-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
		.badge-info { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }

		.dashboard {
			max-width: 1200px;
			margin: 0 auto;
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
			gap: 1.5rem;
			margin-bottom: 2rem;
		}

		.card {
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			border-radius: 1rem;
			padding: 1.5rem;
			backdrop-filter: blur(12px);
			box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
			transition: transform 0.2s, border-color 0.2s;
		}

		.card:hover {
			transform: translateY(-2px);
			border-color: rgba(255, 255, 255, 0.15);
		}

		.card-title {
			font-size: 0.9rem;
			color: var(--text-muted);
			font-weight: 600;
			text-transform: uppercase;
			letter-spacing: 0.05em;
			margin-bottom: 0.5rem;
		}

		.card-val {
			font-size: 2.25rem;
			font-weight: 800;
		}

		.val-success { color: var(--green); }
		.val-danger { color: var(--red); }
		.val-warning { color: var(--yellow); }
		.val-info { color: var(--blue); }

		.main-section {
			max-width: 1200px;
			margin: 0 auto;
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			border-radius: 1rem;
			padding: 1.5rem;
			backdrop-filter: blur(12px);
			box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
		}

		.controls {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 1.5rem;
			flex-wrap: wrap;
			gap: 1rem;
		}

		.filters {
			display: flex;
			gap: 0.5rem;
			flex-wrap: wrap;
		}

		.filter-btn {
			background: rgba(255, 255, 255, 0.05);
			border: 1px solid var(--card-border);
			color: var(--text-main);
			padding: 0.5rem 1rem;
			border-radius: 0.5rem;
			cursor: pointer;
			font-weight: 600;
			transition: all 0.2s;
			font-family: inherit;
		}

		.filter-btn:hover {
			background: rgba(255, 255, 255, 0.1);
		}

		.filter-btn.active {
			background: var(--primary);
			border-color: var(--primary);
		}

		.search-input {
			background: rgba(255, 255, 255, 0.05);
			border: 1px solid var(--card-border);
			color: var(--text-main);
			padding: 0.5rem 1rem;
			border-radius: 0.5rem;
			font-family: inherit;
			outline: none;
			width: 250px;
			transition: border-color 0.2s;
		}

		.search-input:focus {
			border-color: var(--primary);
		}

		.table-container {
			overflow-x: auto;
		}

		table {
			width: 100%;
			border-collapse: collapse;
			text-align: left;
			font-size: 0.95rem;
		}

		th, td {
			padding: 1rem;
			border-bottom: 1px solid var(--card-border);
		}

		th {
			font-weight: 600;
			color: var(--text-muted);
			text-transform: uppercase;
			font-size: 0.8rem;
			letter-spacing: 0.05em;
		}

		tr:hover td {
			background: rgba(255, 255, 255, 0.02);
		}

		.td-payload {
			font-family: 'JetBrains Mono', monospace;
			font-size: 0.85rem;
			max-width: 400px;
			word-break: break-all;
		}

		.status-403, .status-BLOCKED { color: var(--green); font-weight: bold; }
		.status-200 { color: var(--red); font-weight: bold; }
		.status-redirect { color: var(--yellow); font-weight: bold; }
		.status-error { color: var(--text-muted); font-style: italic; }

		footer {
			max-width: 1200px;
			margin: 2rem auto 0 auto;
			text-align: center;
			color: var(--text-muted);
			font-size: 0.85rem;
		}
	</style>
</head>
<body>
	<header>
		<div class="title-area">
			<h1>WAF Audit Report</h1>
			<p>Target: ${url}</p>
		</div>
		<div>
			<span class="badge ${bypassRate > 0 ? 'badge-danger' : 'badge-success'}">
				${bypassRate > 0 ? '🔓 Vulnerable / Bypasses Detected' : '🛡️ Secure / All Blocked'}
			</span>
		</div>
	</header>

	<div class="dashboard">
		<div class="card">
			<div class="card-title">Total Payloads</div>
			<div class="card-val val-info">${total}</div>
		</div>
		<div class="card">
			<div class="card-title">🛡️ Blocked</div>
			<div class="card-val val-success">${blocked} <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted)">(${blockRate}%)</span></div>
		</div>
		<div class="card">
			<div class="card-title">🔓 Bypassed</div>
			<div class="card-val val-danger">${bypassed} <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted)">(${bypassRate}%)</span></div>
		</div>
		<div class="card">
			<div class="card-title">🔄 Redirects</div>
			<div class="card-val val-warning">${redirect}</div>
		</div>
	</div>

	<div class="main-section">
		<div class="controls">
			<div class="filters">
				<button class="filter-btn active" onclick="setFilter('all')">All (${total})</button>
				<button class="filter-btn" onclick="setFilter('blocked')">Blocked (${blocked})</button>
				<button class="filter-btn" onclick="setFilter('bypassed')">Bypasses (${bypassed})</button>
				<button class="filter-btn" onclick="setFilter('redirect')">Redirects (${redirect})</button>
				<button class="filter-btn" onclick="setFilter('errors')">Errors (${errors})</button>
			</div>
			<input type="text" class="search-input" placeholder="Search payloads..." id="search" oninput="handleSearch()">
		</div>

		<div class="table-container">
			<table>
				<thead>
					<tr>
						<th>Category</th>
						<th>Method</th>
						<th>Status</th>
						<th>Time</th>
						<th>Payload</th>
					</tr>
				</thead>
				<tbody id="results-table-body">
					<!-- Populated by JS -->
				</tbody>
			</table>
		</div>
	</div>

	<footer>
		Generated by WAF Checker CLI on ${new Date().toLocaleString()}
	</footer>

	<script>
		const data = ${escapedJson};
		let currentFilter = 'all';
		let searchQuery = '';

		function setFilter(filter) {
			document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
			event.target.classList.add('active');
			currentFilter = filter;
			renderTable();
		}

		function handleSearch() {
			searchQuery = document.getElementById('search').value.toLowerCase();
			renderTable();
		}

		function renderTable() {
			const body = document.getElementById('results-table-body');
			body.innerHTML = '';

			const filtered = data.filter(item => {
				// Apply status filter
				if (currentFilter === 'blocked') {
					if (item.status !== 403 && item.status !== 'BLOCKED') return false;
				} else if (currentFilter === 'bypassed') {
					if (item.status !== 200 && item.status !== '200') return false;
				} else if (currentFilter === 'redirect') {
					if (!item.is_redirect) return false;
				} else if (currentFilter === 'errors') {
					if (item.status !== 'ERR' && !item.error) return false;
				}

				// Apply search
				if (searchQuery) {
					return item.payload.toLowerCase().includes(searchQuery) || 
						   item.category.toLowerCase().includes(searchQuery) ||
						   String(item.status).toLowerCase().includes(searchQuery);
				}

				return true;
			});

			if (filtered.length === 0) {
				body.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching entries found.</td></tr>';
				return;
			}

			filtered.forEach(item => {
				const tr = document.createElement('tr');
				
				let statusClass = 'status-error';
				let statusText = item.status || 'ERR';
				
				if (item.status === 403 || item.status === 'BLOCKED') {
					statusClass = 'status-403';
					statusText = '🛡️ ' + item.status;
				} else if (item.status === 200 || item.status === '200') {
					statusClass = 'status-200';
					statusText = '🔓 ' + item.status;
				} else if (item.is_redirect) {
					statusClass = 'status-redirect';
					statusText = '🔄 ' + item.status;
				}

				tr.innerHTML = \`
					<td><span class="badge badge-info">\${escapeHtml(item.category)}</span></td>
					<td><span class="badge badge-warning">\${escapeHtml(item.method)}</span></td>
					<td class="\${statusClass}">\${escapeHtml(statusText)}</td>
					<td>\${item.responseTime}ms</td>
					<td class="td-payload">\${escapeHtml(item.payload)}</td>
				\`;
				body.appendChild(tr);
			});
		}

		function escapeHtml(str) {
			return String(str || '')
				.replace(/&/g, '&amp;')
				.replace(/</g, '&lt;')
				.replace(/>/g, '&gt;')
				.replace(/"/g, '&quot;')
				.replace(/'/g, '&#039;');
		}

		// Initial render
		renderTable();
	</script>
</body>
</html>`;
}

/**
 * Generate a beautiful HTML report for BatchResults.
 */
function generateBatchHtml(results: BatchResult[]): string {
	const totalTargets = results.length;
	const successfulRuns = results.filter(r => r.success).length;
	const failedRuns = totalTargets - successfulRuns;
	const totalBypassed = results.reduce((acc, r) => acc + (r.bypassed || 0), 0);

	// Escape JSON for embedded script
	const escapedJson = JSON.stringify(results).replace(/</g, '\\u003c');

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>WAF Batch Audit Report</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
	<style>
		:root {
			--bg-color: #0b0f19;
			--card-bg: rgba(22, 29, 49, 0.7);
			--card-border: rgba(255, 255, 255, 0.08);
			--text-main: #f3f4f6;
			--text-muted: #9ca3af;
			--primary: #6366f1;
			--primary-hover: #4f46e5;
			--green: #10b981;
			--red: #ef4444;
			--yellow: #f59e0b;
			--blue: #3b82f6;
		}

		* {
			box-sizing: border-box;
			margin: 0;
			padding: 0;
		}

		body {
			font-family: 'Outfit', sans-serif;
			background-color: var(--bg-color);
			color: var(--text-main);
			line-height: 1.5;
			padding: 2rem;
			background-image: 
				radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
				radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.08) 0px, transparent 50%);
			background-attachment: fixed;
		}

		header {
			max-width: 1200px;
			margin: 0 auto 2rem auto;
			display: flex;
			justify-content: space-between;
			align-items: center;
			flex-wrap: wrap;
			gap: 1rem;
		}

		.title-area h1 {
			font-size: 2.5rem;
			font-weight: 800;
			background: linear-gradient(135deg, #fff 30%, #a5b4fc 100%);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			margin-bottom: 0.25rem;
		}

		.title-area p {
			color: var(--text-muted);
			font-size: 0.95rem;
		}

		.badge {
			display: inline-block;
			padding: 0.25rem 0.75rem;
			border-radius: 9999px;
			font-size: 0.85rem;
			font-weight: 600;
			text-transform: uppercase;
		}

		.badge-success { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
		.badge-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
		.badge-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }

		.dashboard {
			max-width: 1200px;
			margin: 0 auto;
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
			gap: 1.5rem;
			margin-bottom: 2rem;
		}

		.card {
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			border-radius: 1rem;
			padding: 1.5rem;
			backdrop-filter: blur(12px);
			box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
		}

		.card-title {
			font-size: 0.9rem;
			color: var(--text-muted);
			font-weight: 600;
			text-transform: uppercase;
			letter-spacing: 0.05em;
			margin-bottom: 0.5rem;
		}

		.card-val {
			font-size: 2.25rem;
			font-weight: 800;
		}

		.val-success { color: var(--green); }
		.val-danger { color: var(--red); }
		.val-warning { color: var(--yellow); }

		.main-section {
			max-width: 1200px;
			margin: 0 auto;
			background: var(--card-bg);
			border: 1px solid var(--card-border);
			border-radius: 1rem;
			padding: 1.5rem;
			backdrop-filter: blur(12px);
			box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
		}

		.controls {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 1.5rem;
			flex-wrap: wrap;
			gap: 1rem;
		}

		.filters {
			display: flex;
			gap: 0.5rem;
			flex-wrap: wrap;
		}

		.filter-btn {
			background: rgba(255, 255, 255, 0.05);
			border: 1px solid var(--card-border);
			color: var(--text-main);
			padding: 0.5rem 1rem;
			border-radius: 0.5rem;
			cursor: pointer;
			font-weight: 600;
			transition: all 0.2s;
		}

		.filter-btn.active {
			background: var(--primary);
			border-color: var(--primary);
		}

		.table-container {
			overflow-x: auto;
		}

		table {
			width: 100%;
			border-collapse: collapse;
			text-align: left;
			font-size: 0.95rem;
		}

		th, td {
			padding: 1rem;
			border-bottom: 1px solid var(--card-border);
		}

		th {
			font-weight: 600;
			color: var(--text-muted);
			text-transform: uppercase;
			font-size: 0.8rem;
			letter-spacing: 0.05em;
		}

		tr:hover td {
			background: rgba(255, 255, 255, 0.02);
		}

		.status-success { color: var(--green); font-weight: bold; }
		.status-fail { color: var(--red); font-weight: bold; }

		footer {
			max-width: 1200px;
			margin: 2rem auto 0 auto;
			text-align: center;
			color: var(--text-muted);
			font-size: 0.85rem;
		}
	</style>
</head>
<body>
	<header>
		<div class="title-area">
			<h1>WAF Batch Audit Report</h1>
			<p>Scanned ${totalTargets} targets</p>
		</div>
		<div>
			<span class="badge ${totalBypassed > 0 ? 'badge-danger' : 'badge-success'}">
				${totalBypassed > 0 ? `🔓 ${totalBypassed} Bypasses Detected` : '🛡️ All Targets Secure'}
			</span>
		</div>
	</header>

	<div class="dashboard">
		<div class="card">
			<div class="card-title">Total Targets</div>
			<div class="card-val">${totalTargets}</div>
		</div>
		<div class="card">
			<div class="card-title">🟢 Successful Runs</div>
			<div class="card-val val-success">${successfulRuns}</div>
		</div>
		<div class="card">
			<div class="card-title">🔴 Failed Scans</div>
			<div class="card-val val-danger">${failedRuns}</div>
		</div>
		<div class="card">
			<div class="card-title">🔓 Total Bypasses</div>
			<div class="card-val val-danger">${totalBypassed}</div>
		</div>
	</div>

	<div class="main-section">
		<div class="controls">
			<div class="filters">
				<button class="filter-btn active" onclick="setFilter('all')">All Targets</button>
				<button class="filter-btn" onclick="setFilter('vulnerable')">Vulnerable</button>
				<button class="filter-btn" onclick="setFilter('secure')">Secure</button>
				<button class="filter-btn" onclick="setFilter('failed')">Failed Scans</button>
			</div>
		</div>

		<div class="table-container">
			<table>
				<thead>
					<tr>
						<th>Target URL</th>
						<th>Status</th>
						<th>Total Tests</th>
						<th>Blocked</th>
						<th>Bypassed</th>
						<th>Bypass Rate</th>
					</tr>
				</thead>
				<tbody id="results-table-body">
					<!-- Populated by JS -->
				</tbody>
			</table>
		</div>
	</div>

	<footer>
		Generated by WAF Checker CLI on ${new Date().toLocaleString()}
	</footer>

	<script>
		const data = ${escapedJson};
		let currentFilter = 'all';

		function setFilter(filter) {
			document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
			event.target.classList.add('active');
			currentFilter = filter;
			renderTable();
		}

		function renderTable() {
			const body = document.getElementById('results-table-body');
			body.innerHTML = '';

			const filtered = data.filter(item => {
				if (currentFilter === 'vulnerable') {
					return item.success && item.bypassed > 0;
				} else if (currentFilter === 'secure') {
					return item.success && item.bypassed === 0;
				} else if (currentFilter === 'failed') {
					return !item.success;
				}
				return true;
			});

			if (filtered.length === 0) {
				body.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching entries found.</td></tr>';
				return;
			}

			filtered.forEach(item => {
				const tr = document.createElement('tr');
				
				let statusText = '🟢 SUCCESS';
				let statusClass = 'status-success';
				if (!item.success) {
					statusText = '⚠️ FAILED: ' + (item.error || 'Unknown error');
					statusClass = 'status-fail';
				} else if (item.bypassed > 0) {
					statusText = '🔓 BYPASSES FOUND';
					statusClass = 'status-fail';
				}

				tr.innerHTML = \`
					<td style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;">\${escapeHtml(item.url)}</td>
					<td class="\${statusClass}">\${escapeHtml(statusText)}</td>
					<td>\${item.total || 0}</td>
					<td>\${item.blocked || 0}</td>
					<td>\${item.bypassed || 0}</td>
					<td>\${item.bypassRate || 0}%</td>
				\`;
				body.appendChild(tr);
			});
		}

		function escapeHtml(str) {
			return String(str || '')
				.replace(/&/g, '&amp;')
				.replace(/</g, '&lt;')
				.replace(/>/g, '&gt;')
				.replace(/"/g, '&quot;')
				.replace(/'/g, '&#039;');
		}

		// Initial render
		renderTable();
	</script>
</body>
</html>`;
}

/**
 * Write check or batch report to file.
 */
export function writeReport(
	outputPath: string,
	format: ReportFormat,
	type: 'check' | 'batch',
	urlOrFile: string,
	results: any[]
): void {
	let outputContent = '';

	if (format === 'json') {
		outputContent = JSON.stringify(results, null, 2);
	} else if (format === 'csv') {
		outputContent = type === 'check' 
			? generateCheckCsv(results as CheckResult[])
			: generateBatchCsv(results as BatchResult[]);
	} else {
		outputContent = type === 'check'
			? generateCheckHtml(urlOrFile, results as CheckResult[])
			: generateBatchHtml(results as BatchResult[]);
	}

	// Ensure target directory exists
	const dir = path.dirname(outputPath);
	if (dir && !fs.existsSync(dir)) {
		fs.mkdirSync(dir, { recursive: true });
	}

	fs.writeFileSync(outputPath, outputContent, 'utf8');
}
