// Behavioural fingerprint of the core: hashes every request a scan sends and every
// result it returns, across option combinations, plus the pure payload generators.
// scripts/perf/run.sh golden diffs it against golden.json, so a performance change
// can be shown to leave scan output byte-identical.
import { createHash } from 'node:crypto';
const core = await import('./.out/core.mjs');
const H = () => createHash('sha256');
const out = {};
// deterministic Math.random
let s = 42; Math.random = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x80000000; };
// pure functions
{ const h = H(); h.update(JSON.stringify(core.ENHANCED_PAYLOADS)); out.enhanced = h.digest('hex').slice(0, 16); }
{ const h = H(); const src = { ...core.PAYLOADS, ...core.ADVANCED_PAYLOADS };
  const wafs = ['cloudflare','aws','modsecurity','akamai','azure','palo alto','sophos','imperva','f5','google','signal sciences','nginx','haproxy','datapower','reblaze','dotdefender','qrator','x'];
  for (const [cat, c] of Object.entries(src)) for (const p of [...c.payloads, ...(c.falsePayloads||[])]) {
    h.update(JSON.stringify(core.PayloadEncoder.generateBypassVariations(p, cat)));
    for (const w of wafs) h.update(JSON.stringify(core.generateWAFSpecificPayloads(w, p)));
    for (const t of ['verb','pollution','content-type','smuggling']) h.update(JSON.stringify(core.generateHTTPManipulationPayloads(p, t)));
  }
  out.variations = h.digest('hex').slice(0, 16); }
const bodies = [
  ['<!doctype html><html><title>Attention Required! | Cloudflare</title><body>Sorry, you have been blocked</body></html>', 403, { server: 'cloudflare', 'cf-ray': 'abc' }],
  ['{"ok":true}', 200, { 'content-type': 'application/json' }],
  ['<html><body>Request rejected. Your support ID is: 123456789</body></html>', 200, {}],
  ['DB_PASSWORD=1\n', 200, {}],
];
async function scan(name, args, opts = {}) {
  for (const [bi, [body, status, headers]] of bodies.entries()) {
    const h = H(); let n = 0;
    const fetch = async (url, init) => { n++;
      const hdr = init.headers ? [...new Headers(init.headers)] : [];
      h.update(JSON.stringify([url, init.method, init.body == null ? null : String(init.body), hdr]));
      const ua = hdr.find(([k]) => k === 'user-agent');
      return new Response(body, { status: ua && /Googlebot/.test(ua[1]) ? 200 : status, headers }); };
    let page = 0;
    for (;;) {
      s = 42;
      const env = await core.handleApiCheckWithEnvelope('https://example.com/api', page, ...args, { fetch, quiet: true, pageSize: opts.pageSize || 400, concurrency: opts.concurrency || 1, ...opts.extra });
      h.update(JSON.stringify([env.total, env.hasMore, env.pageSize, env.baseline, env.results.map((r) => ({ ...r, responseTime: 0 }))]));
      if (!env.hasMore) break; page++;
    }
    out[`${name}#${bi}`] = h.digest('hex').slice(0, 16) + ` req=${n} pages=${page + 1}`;
  }
}
const A = (o = {}) => [o.methods || ['GET', 'POST'], o.cats, o.tpl, !!o.follow, o.custom, !!o.fp, !!o.cs, !!o.enh, !!o.adv, false, !!o.enc, o.waf, o.manip];
await scan('basic', A());
await scan('fp', A({ fp: true }));
await scan('cs', A({ cs: true }));
await scan('enh', A({ enh: true, methods: ['GET'] }), { pageSize: 3000 });
await scan('adv', A({ adv: true, cats: ['SQL Injection', 'XSS', 'Path Traversal', 'NoSQL Injection'] }));
await scan('enc', A({ enc: true, waf: 'modsecurity', cats: ['SQL Injection', 'XSS', 'Prototype Pollution', 'LDAP Injection'] }));
await scan('wafs', A({ waf: 'akamai', custom: 'X-Test: {PAYLOAD}\nAuthorization: Bearer x', tpl: '{"q":"{PAYLOAD}","n":["{PAYLOAD}"]}' }));
await scan('manip', A({ manip: { enableParameterPollution: true } }));
await scan('pad', A({ manip: { enableInspectionLimitPadding: true, paddingSize: '8kb' }, cats: ['SQL Injection'] }));
await scan('spoof', A({ cats: ['SQL Injection', 'Path Traversal', 'User-Agent', 'Host Header'] }), { extra: { spoofUserAgents: true, spoofIpHeaders: true, calibrateBaseline: true } });
await scan('conc', A({ enc: true, cats: ['XSS'] }), { concurrency: 4, pageSize: 37 });
await scan('allcombo', A({ enh: true, adv: true, enc: true, waf: 'cloudflare', methods: ['GET'], cats: ['XSS', 'SQL Injection', 'Path Traversal'] }), { pageSize: 20000 });
console.log(JSON.stringify(out, null, 1));
process.exit(0);
