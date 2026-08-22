import { AuditResultItem, calculateAuditStats } from './types';

function escapeHtml(str?: string): string {
	return String(str || '')
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#039;');
}

export function generateHTMLReport(results: AuditResultItem[], targetUrl?: string): string {
	const stats = calculateAuditStats(results, targetUrl);

	const categoryMap = new Map<string, { total: number; blocked: number; bypassed: number; errors: number }>();
	for (const r of results) {
		const entry = categoryMap.get(r.category) || { total: 0, blocked: 0, bypassed: 0, errors: 0 };
		entry.total++;
		if (r.status === 403 || r.status === '403' || r.status === 'BLOCKED') {
			entry.blocked++;
		} else if (r.status === 200 || r.status === '200') {
			entry.bypassed++;
		} else {
			entry.errors++;
		}
		categoryMap.set(r.category, entry);
	}

	const scoreColor = stats.protectionScore >= 90 ? '#10b981' : stats.protectionScore >= 70 ? '#f59e0b' : '#ef4444';

	const categoryRows = Array.from(categoryMap.entries())
		.map(([cat, data]) => {
			const rate = data.total > 0 ? Math.round((data.blocked / data.total) * 100) : 100;
			const color = rate >= 90 ? '#10b981' : rate >= 70 ? '#f59e0b' : '#ef4444';
			return `<tr>
				<td><strong>${escapeHtml(cat)}</strong></td>
				<td>${data.total}</td>
				<td style="color: #10b981; font-weight: 600;">${data.blocked}</td>
				<td style="color: #ef4444; font-weight: 600;">${data.bypassed}</td>
				<td><span class="badge" style="background: ${color}20; color: ${color};">${rate}%</span></td>
			</tr>`;
		})
		.join('\n');

	const resultRows = results
		.map((r, i) => {
			const isBypass = r.status === 200 || r.status === '200';
			const isBlocked = r.status === 403 || r.status === '403' || r.status === 'BLOCKED';
			const statusClass = isBypass ? 'status-bypass' : isBlocked ? 'status-blocked' : 'status-error';
			const statusLabel = isBypass ? '⚠️ BYPASS (200)' : isBlocked ? '🛡️ BLOCKED (403)' : `❓ ${r.status}`;

			return `<tr>
				<td>#${i + 1}</td>
				<td><span class="category-tag">${escapeHtml(r.category)}</span></td>
				<td><span class="method-tag">${escapeHtml(r.method)}</span></td>
				<td><span class="${statusClass}">${escapeHtml(statusLabel)}</span></td>
				<td>${r.responseTime}ms</td>
				<td>${escapeHtml(r.bypassTechnique || 'Standard')}</td>
				<td><code>${escapeHtml(r.payload)}</code></td>
			</tr>`;
		})
		.join('\n');

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>WAF Audit Report - ${escapeHtml(stats.targetUrl || 'Target')}</title>
	<style>
		:root {
			--bg: #0f172a;
			--surface: #1e293b;
			--border: #334155;
			--text: #f8fafc;
			--text-muted: #94a3b8;
			--primary: #3b82f6;
			--success: #10b981;
			--warning: #f59e0b;
			--danger: #ef4444;
		}
		* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
		body { background: var(--bg); color: var(--text); padding: 2rem 1rem; line-height: 1.5; }
		.container { max-width: 1200px; margin: 0 auto; }
		header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }
		h1 { font-size: 1.8rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
		.meta { color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem; }
		.score-circle { display: flex; flex-direction: column; align-items: center; justify-content: center; width: 100px; height: 100px; border-radius: 50%; border: 4px solid ${scoreColor}; background: var(--surface); text-align: center; }
		.score-number { font-size: 1.8rem; font-weight: 800; color: ${scoreColor}; }
		.score-label { font-size: 0.65rem; text-transform: uppercase; color: var(--text-muted); }
		.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
		.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
		.card-title { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
		.card-val { font-size: 1.8rem; font-weight: 700; margin-top: 0.25rem; }
		.table-container { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto; margin-bottom: 2rem; }
		table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
		th { background: #182234; padding: 0.75rem 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); }
		td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
		tr:last-child td { border-bottom: none; }
		code { background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; color: #e2e8f0; word-break: break-all; }
		.badge { padding: 0.2rem 0.5rem; border-radius: 9999px; font-weight: 600; font-size: 0.8rem; }
		.status-bypass { color: var(--danger); font-weight: 700; }
		.status-blocked { color: var(--success); font-weight: 600; }
		.status-error { color: var(--warning); }
		.category-tag { background: #334155; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
		.method-tag { background: #1e3a8a; color: #93c5fd; padding: 0.15rem 0.4rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
		h2 { font-size: 1.3rem; margin-bottom: 1rem; }
	</style>
</head>
<body>
	<div class="container">
		<header>
			<div>
				<h1>🛡️ WAF Checker Audit Report</h1>
				<div class="meta">
					Target: <strong>${escapeHtml(stats.targetUrl || 'Target')}</strong> | 
					Detected WAF: <strong>${escapeHtml(stats.detectedWAF || 'Unknown')}</strong> | 
					Date: <strong>${new Date().toUTCString()}</strong>
				</div>
			</div>
			<div class="score-circle">
				<div class="score-number">${stats.protectionScore}%</div>
				<div class="score-label">Protection</div>
			</div>
		</header>

		<div class="grid">
			<div class="card">
				<div class="card-title">Total Tests</div>
				<div class="card-val">${stats.total}</div>
			</div>
			<div class="card">
				<div class="card-title">Blocked Attacks</div>
				<div class="card-val" style="color: var(--success);">${stats.blocked}</div>
			</div>
			<div class="card">
				<div class="card-title">Bypassed Attacks</div>
				<div class="card-val" style="color: var(--danger);">${stats.bypassed}</div>
			</div>
			<div class="card">
				<div class="card-title">Errors / Unreachable</div>
				<div class="card-val" style="color: var(--warning);">${stats.errors + stats.other}</div>
			</div>
		</div>

		<h2>📊 Category Summary</h2>
		<div class="table-container">
			<table>
				<thead>
					<tr>
						<th>Category</th>
						<th>Total</th>
						<th>Blocked</th>
						<th>Bypassed</th>
						<th>Protection Rate</th>
					</tr>
				</thead>
				<tbody>
					${categoryRows}
				</tbody>
			</table>
		</div>

		<h2>📝 Detailed Test Results</h2>
		<div class="table-container">
			<table>
				<thead>
					<tr>
						<th>#</th>
						<th>Category</th>
						<th>Method</th>
						<th>Status</th>
						<th>Response Time</th>
						<th>Technique</th>
						<th>Payload</th>
					</tr>
				</thead>
				<tbody>
					${resultRows}
				</tbody>
			</table>
		</div>
	</div>
</body>
</html>`;
}
