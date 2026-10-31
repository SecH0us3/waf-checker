// Core performance scenarios. Run through scripts/perf/run.sh (bundles core first).
// Usage: node --expose-gc bench.mjs <scenario>
// Prints one JSON line: import cost, wall/CPU time, GC count/time, heap and RSS.
import { PerformanceObserver, performance } from 'node:perf_hooks';
const CORE = new URL('./.out/core.mjs', import.meta.url).href;
const scenario = process.argv[2] || 'import';

let gcCount = 0, gcTime = 0;
new PerformanceObserver((l) => { for (const e of l.getEntries()) { gcCount++; gcTime += e.duration; } }).observe({ entryTypes: ['gc'] });

const cpu0 = process.cpuUsage();
const t0 = performance.now();
const core = await import(CORE);
const importMs = performance.now() - t0;
const importCpu = process.cpuUsage(cpu0);
await new Promise((r) => setTimeout(r, 20)); global.gc(); await new Promise((r) => setTimeout(r, 20)); const importGc = gcCount, importGcMs = gcTime;
const heapAfterImport = process.memoryUsage().heapUsed;

function mkFetch(status, bodySize) {
	const body = ('<!doctype html><html><head><title>Attention Required! | Cloudflare</title></head><body><div class="cf-error">Sorry, you have been blocked. Cloudflare Ray ID: 8a1b2c3d4e5f6a7b ' + 'x'.repeat(Math.max(0, bodySize - 200)) + '</div></body></html>');
	const headers = { 'content-type': 'text/html', server: 'cloudflare', 'cf-ray': '8a1b2c3d4e5f6a7b-AMS' };
	return async () => new Response(body, { status, headers });
}

async function fullScan(opts) {
	let page = 0, total = 0, n = 0, peak = 0;
	for (;;) {
		const env = await core.handleApiCheckWithEnvelope(
			'https://example.com/', page, opts.methods, undefined, undefined, false, undefined, false, false,
			!!opts.enhanced, !!opts.advanced, false, !!opts.encoding, opts.waf, undefined,
			{ fetch: opts.fetch, quiet: true, pageSize: opts.pageSize, concurrency: 4 },
		);
		n += env.results.length; total = env.total;
		peak = Math.max(peak, process.memoryUsage().heapUsed);
		if (!env.hasMore || (opts.maxPages && page + 1 >= opts.maxPages)) break;
		page++;
	}
	return { pages: page + 1, items: n, total, peakHeapMB: +(peak / 1048576).toFixed(1) };
}

const scenarios = {
	import: async () => ({}),
	basic: () => fullScan({ methods: ['GET', 'POST'], fetch: mkFetch(403, 4096), pageSize: 50 }),
	heavy3pages: () => fullScan({ methods: ['GET', 'POST'], fetch: mkFetch(403, 4096), pageSize: 50, enhanced: true, advanced: true, encoding: true, waf: 'cloudflare', maxPages: 3 }),
	encpaged: () => fullScan({ methods: ['GET'], fetch: mkFetch(403, 4096), pageSize: 50, encoding: true, waf: 'modsecurity' }),
	bigbody: () => fullScan({ methods: ['GET'], fetch: mkFetch(200, 512 * 1024), pageSize: 50 }),
	verdict: async () => {
		const body = '<!doctype html><html><body>' + 'lorem ipsum dolor sit amet '.repeat(40000) + '</body></html>';
		const h = new Headers({ server: 'nginx' });
		const base = { status: 200, contentType: 'text/html', bodyLength: 10, bodySignature: 'html:x|y', wafBlockedOnBenign: false, isOriginBlocked: false };
		for (let i = 0; i < 300; i++) core.evaluateWAFVerdict(200, body, undefined, h, 'q', base);
		return { iterations: 300, bodyKB: Math.round(body.length / 1024) };
	},
	signature: async () => {
		// Baseline fingerprinting of typical (8-16 KB) HTML responses.
		const body = '<!doctype html>\n<html>\n  <head><title>Shop</title></head>\n  <body>\n' + '    <div class="item">\n      <a href="/p/1234">Product   name</a>\t<span>  19.99 </span>\n    </div>\n'.repeat(120) + '  </body>\n</html>\n';
		let n = 0;
		for (let i = 0; i < 3000; i++) n += core.computeBodySignature(body).length + (core.isSoftBlockBody(body) ? 1 : 0);
		return { iterations: 3000, bodyKB: Math.round(body.length / 1024), n };
	},
	plan: async () => {
		let n = 0;
		for (let i = 0; i < 5; i++) for (const [cat, c] of Object.entries(core.PAYLOADS)) for (const p of c.payloads) { n += core.PayloadEncoder.generateBypassVariations(p, cat).length; n += core.generateWAFSpecificPayloads('modsecurity', p).length; }
		return { variations: n };
	},
};

const gc0 = gcCount, gct0 = gcTime;
const c1 = process.cpuUsage(); const t1 = performance.now();
const out = await scenarios[scenario]();
const ms = performance.now() - t1; const cpu = process.cpuUsage(c1);
await new Promise((r) => setTimeout(r, 50));
const rss = process.memoryUsage().rss;
console.log(JSON.stringify({ scenario, importMs: +importMs.toFixed(1), importGc, importGcMs: +importGcMs.toFixed(1), importCpuMs: Math.round((importCpu.user + importCpu.system) / 1000), heapAfterImportMB: +(heapAfterImport / 1048576).toFixed(2),
	wallMs: Math.round(ms), cpuMs: Math.round((cpu.user + cpu.system) / 1000), gcCount: gcCount - gc0, gcMs: +(gcTime - gct0).toFixed(1), rssMB: Math.round(rss / 1048576), ...out }));
process.exit(0);
