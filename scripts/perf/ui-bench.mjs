// Browser-side scan loop benchmark: drives the real fetchResults() of the
// Web UI (packages/worker/src/static) in headless Chromium against a mocked
// /api/check that returns results in pages of 15, as the Worker does.
//
// Usage: node scripts/perf/ui-bench.mjs [totalResults=3000] [runs=3] [pageLatencyMs=30]
// Needs Playwright (pre-installed in CI images; otherwise `npm i -g playwright`).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const STATIC = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../packages/worker/src/static');
const TOTAL = Number(process.argv[2] || 3000);
const RUNS = Number(process.argv[3] || 3);
const LATENCY = Number(process.argv[4] ?? 30);

const server = createServer(async (req, res) => {
	const p = new URL(req.url, 'http://x').pathname;
	try {
		const file = path.join(STATIC, p === '/' ? 'index.html' : p);
		if (!file.startsWith(STATIC)) throw new Error('outside');
		res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html' });
		res.end(await readFile(file));
	} catch {
		res.writeHead(404).end();
	}
}).listen(0);
const base = `http://127.0.0.1:${server.address().port}/`;

const browser = await chromium.launch();
const rows = [];
for (let run = 0; run < RUNS; run++) {
	const page = await browser.newPage();
	// Third-party assets (fonts, bootstrap CDN) are irrelevant here.
	await page.route(/^https?:\/\/(?!127\.0\.0\.1)/, (r) => r.abort());
	await page.goto(base, { waitUntil: 'load' });
	const cdp = await page.context().newCDPSession(page);
	await cdp.send('Performance.enable');
	const metric = async () => Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map((x) => [x.name, x.value]));
	const before = await metric();
	const out = await page.evaluate(async ([TOTAL, LATENCY]) => {
		const statuses = [403, 403, 403, 200, 404, 500, 406];
		window.fetch = async (url) => {
			const u = new URL(url, location.href);
			const pageNo = Number(u.searchParams.get('page'));
			await new Promise((r) => setTimeout(r, LATENCY));
			const items = [];
			for (let i = pageNo * 15; i < Math.min(TOTAL, pageNo * 15 + 15); i++) {
				items.push({
					category: 'SQL Injection', payload: `' OR 1=1 -- <script>alert(${i})</script> & more text`, method: i % 2 ? 'POST' : 'GET',
					status: statuses[i % statuses.length], is_redirect: false, responseTime: 100 + (i % 50), blocked: i % 7 < 3, verdict: 'blocked',
					...(i % 97 === 0 ? { userAgentBypass: { bypassed: true, tested: 3, hits: [{ name: 'Googlebot', status: 200 }] } } : {}),
				});
			}
			return new Response(JSON.stringify(items), { status: 200, headers: { 'content-type': 'application/json' } });
		};
		document.getElementById('url').value = 'https://example.com/';
		for (const id of ['autoDetectWAF', 'calibrateBaseline']) { const el = document.getElementById(id); if (el) el.checked = false; }
		const t0 = performance.now();
		await fetchResults();
		const ms = performance.now() - t0;
		await new Promise((r) => setTimeout(r, 0));
		// Interactions on the finished table, each timed through a forced layout.
		// sort*ScriptMs is the synchronous part alone, before the browser restyles.
		let scriptPart = 0;
		const timed = (f) => { const t = performance.now(); f(); scriptPart = Math.round(performance.now() - t); document.body.offsetHeight; return Math.round(performance.now() - t); };
		const sortNumMs = timed(() => sortResultsTable(2, 'num'));
		const sortNumScriptMs = scriptPart;
		const sortTextMs = timed(() => sortResultsTable(0, 'text'));
		const sortTextScriptMs = scriptPart;
		const filterMs = timed(() => { document.querySelector('.status-filter-checkbox[data-status="403"]').checked = false; filterResultsTableByStatus(); });
		const searchMs = timed(() => { document.getElementById('resultsSearch').value = 'post'; filterResultsTableByStatus(); });
		return { ms: Math.round(ms), rows: document.querySelectorAll('#resultsTable tbody tr').length, heapMB: +(performance.memory.usedJSHeapSize / 1048576).toFixed(1), sortNumMs, sortNumScriptMs, sortTextMs, sortTextScriptMs, filterMs, searchMs };
	}, [TOTAL, LATENCY]);
	const after = await metric(); // includes the interactions below the scan
	const d = (k) => Math.round((after[k] - before[k]) * 1000);
	rows.push({ ...out, scriptMs: d('ScriptDuration'), layoutMs: d('LayoutDuration'), styleMs: d('RecalcStyleDuration'), taskMs: d('TaskDuration') });
	await page.close();
}
await browser.close();
server.close();
const med = (k) => rows.map((r) => r[k]).sort((a, b) => a - b)[rows.length >> 1];
console.log(JSON.stringify({ total: TOTAL, latency: LATENCY, ...Object.fromEntries(Object.keys(rows[0]).map((k) => [k, med(k)])) }));
