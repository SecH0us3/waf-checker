import { AuditResultItem, calculateAuditStats } from './types';
import { ReverseEngineeringReport } from '../reverse-engineering/types';
import { CORE_VERSION } from '../version';

/** Options shared by the single- and multi-target SARIF generators. */
export interface SarifOptions {
	/** tool.driver.version / semanticVersion. Defaults to the @waf-checker/core package version. */
	toolVersion?: string;
	/** runs[].automationDetails.id. Defaults to 'waf-checker/<target host>'. */
	automationId?: string;
}

/** One scanned target: becomes one SARIF run. */
export interface SarifTarget {
	targetUrl: string;
	results: AuditResultItem[];
	reverseEngineering?: ReverseEngineeringReport;
}

const SARIF_SCHEMA_URI = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const TOOL_NAME = 'WAF-Checker';
const INFORMATION_URI = 'https://github.com/SecH0us3/waf-checker';
const HELP_URI = `${INFORMATION_URI}#readme`;
/** Used only when a caller does not pass a target URL (legacy single-target calls). */
const FALLBACK_TARGET_URL = 'https://target.local';
/** partialFingerprints key; bump the suffix if the fingerprint recipe ever changes. */
const FINGERPRINT_KEY = 'wafCheckerFinding/v1';

/**
 * GitHub code scanning reads `properties["security-severity"]` (0.0-10.0) on the
 * rule: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, < 4.0 low.
 *
 * A WAF bypass is a missing compensating control, not a confirmed vulnerability
 * in the origin, so nothing is scored critical. Within that ceiling categories
 * are tiered by what the payload class typically leads to if the origin is
 * vulnerable. First match wins.
 */
const SEVERITY_TIERS: ReadonlyArray<{ pattern: RegExp; score: string }> = [
	// Server-side code execution, data store access, or reaching internal resources.
	{
		pattern: /sql|command|rce|log4shell|jndi|ssti|template|xxe|ssrf|traversal|file inclusion|lfi|rfi|smuggling|deserializ/i,
		score: '8.0',
	},
	// Client-side injection, narrower server-side injection, auth/allow-list and inspection bypasses.
	{
		pattern: /xss|ldap|xpath|graphql|jwt|sensitive file|prototype|cache poison|padding|inspection limit|ip bypass|user-agent/i,
		score: '7.0',
	},
	// Low direct impact on their own, or helper/obfuscation techniques.
	{ pattern: /open redirect|crlf|parameter pollution|unicode|utf-?8|formula/i, score: '5.0' },
];
/** Unknown category: any bypass is still treated as high. */
const DEFAULT_SECURITY_SEVERITY = '7.0';

type SarifLevel = 'error' | 'warning';

function securitySeverityForCategory(category: string): string {
	for (const tier of SEVERITY_TIERS) {
		if (tier.pattern.test(category)) return tier.score;
	}
	return DEFAULT_SECURITY_SEVERITY;
}

function levelForSeverity(score: string): SarifLevel {
	return parseFloat(score) >= 7 ? 'error' : 'warning';
}

/** Stable rule id; unchanged from earlier releases so existing code scanning alerts keep matching. */
function ruleIdForCategory(category: string): string {
	return `WAF-${category.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`;
}

function hostOf(url: string): string {
	try {
		return new URL(url).host.toLowerCase();
	} catch {
		return url;
	}
}

function isBypassResult(r: AuditResultItem): boolean {
	if (r.ipHeaderBypass?.bypassed || r.userAgentBypass?.bypassed) return true;
	if (r.blocked === true) return false;
	return r.status === 200 || r.status === '200';
}

function isErrorResult(r: AuditResultItem): boolean {
	return r.status === 'ERR' || !!r.error;
}

// ---------------------------------------------------------------------------
// SHA-256 (synchronous, dependency-free; runs in both Workers and Node).
// ---------------------------------------------------------------------------
const SHA256_K = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
	0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
	0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
	0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
	0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256Hex(input: string): string {
	const data = new TextEncoder().encode(input);
	const bitLen = data.length * 8;
	const paddedLen = (((data.length + 9 + 63) >> 6) << 6) >>> 0;
	const buf = new Uint8Array(paddedLen);
	buf.set(data);
	buf[data.length] = 0x80;
	const view = new DataView(buf.buffer);
	view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000));
	view.setUint32(paddedLen - 4, bitLen >>> 0);

	const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
	const w = new Uint32Array(64);
	const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

	for (let off = 0; off < paddedLen; off += 64) {
		for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
		for (let i = 16; i < 64; i++) {
			const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
			const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, hh] = h;
		for (let i = 0; i < 64; i++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ (~e & g);
			const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const t2 = (S0 + maj) >>> 0;
			hh = g;
			g = f;
			f = e;
			e = (d + t1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (t1 + t2) >>> 0;
		}
		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
		h[5] += f;
		h[6] += g;
		h[7] += hh;
	}
	let out = '';
	for (const word of h) out += word.toString(16).padStart(8, '0');
	return out;
}

/**
 * Stable identity of a finding across scans: depends only on what was sent and
 * where, never on timing or response details.
 */
function sarifFindingFingerprint(category: string, method: string, payload: string, targetUrl: string): string {
	return sha256Hex([category, String(method).toUpperCase(), payload, hostOf(targetUrl)].join('\u0000'));
}

// ---------------------------------------------------------------------------
// SARIF building
// ---------------------------------------------------------------------------

function buildRules(results: AuditResultItem[]) {
	const rules: any[] = [];
	const indexById = new Map<string, number>();
	for (const { category } of results) {
		const id = ruleIdForCategory(category);
		if (indexById.has(id)) continue;
		const severity = securitySeverityForCategory(category);
		const level = levelForSeverity(severity);
		const tags = [...new Set(['security', 'waf', category.toLowerCase()])].filter((t) => t.length > 0);
		indexById.set(id, rules.length);
		rules.push({
			id,
			name: `${category} Attack Bypass`,
			shortDescription: {
				text: `WAF failed to block ${category} attack payload`,
			},
			fullDescription: {
				text: `A security test payload for category "${category}" was sent to the target, and the WAF did not block it.`,
			},
			help: {
				text:
					`WAF-Checker sent a "${category}" attack payload and it reached the application instead of being blocked by the WAF. ` +
					`Review the WAF rules that cover ${category}, enable or tighten them (raise the paranoia level, add a virtual patch), ` +
					`then re-run waf-checker to confirm the payload is blocked. A bypass means the WAF is not protecting this attack class; ` +
					`whether the application itself is exploitable must be verified separately.`,
				markdown:
					`**WAF bypass: ${category}**\n\n` +
					`WAF-Checker sent a \`${category}\` attack payload and it reached the application instead of being blocked by the WAF.\n\n` +
					`**Remediation**\n\n` +
					`1. Review the WAF rules that cover ${category}; enable or tighten them (raise the paranoia level or add a virtual patch, e.g. \`waf-checker patch\`).\n` +
					`2. Re-run waf-checker against the target and confirm the payload is now blocked.\n\n` +
					`A bypass means the WAF is not protecting this attack class; whether the application itself is exploitable must be verified separately.\n\n` +
					`See the [WAF-Checker documentation](${HELP_URI}).`,
			},
			helpUri: HELP_URI,
			defaultConfiguration: { level },
			properties: {
				tags,
				precision: 'high',
				'security-severity': severity,
			},
		});
	}
	return { rules, indexById };
}

function buildResult(r: AuditResultItem, targetUri: string, ruleIndex: number, detectedWAF: string | undefined) {
	const bypassDetails = r.ipHeaderBypass?.bypassed
		? ` (IP Header bypass via ${r.ipHeaderBypass.hits.map((h) => `${h.headerName}: ${h.headerValue}`).join(', ')})`
		: r.userAgentBypass?.bypassed
			? ` (User-Agent bypass via ${r.userAgentBypass.hits.map((h) => h.name).join(', ')})`
			: '';
	return {
		ruleId: ruleIdForCategory(r.category),
		ruleIndex,
		level: levelForSeverity(securitySeverityForCategory(r.category)),
		message: {
			text: `WAF Bypass detected: [${r.category}] attack payload succeeded${bypassDetails} using ${r.method} method (${r.responseTime}ms). Payload: "${r.payload}"`,
		},
		locations: [
			{
				physicalLocation: {
					artifactLocation: { uri: targetUri },
				},
				logicalLocations: [
					{
						name: `${r.method} ${r.category}`,
						kind: 'endpoint',
					},
				],
			},
		],
		partialFingerprints: {
			[FINGERPRINT_KEY]: sarifFindingFingerprint(r.category, r.method, r.payload, targetUri),
		},
		properties: {
			method: r.method,
			category: r.category,
			payload: r.payload,
			originalPayload: r.originalPayload,
			status: r.status,
			responseTimeMs: r.responseTime,
			bypassTechnique: r.bypassTechnique || 'Standard',
			detectedWAF: r.wafType || detectedWAF,
			...(r.ipHeaderBypass?.bypassed ? { ipHeaderBypass: r.ipHeaderBypass } : {}),
			...(r.userAgentBypass?.bypassed ? { userAgentBypass: r.userAgentBypass } : {}),
		},
	};
}

function buildRun(target: { targetUrl?: string; results: AuditResultItem[]; reverseEngineering?: ReverseEngineeringReport }, options: SarifOptions, now: string) {
	const results = target.results || [];
	const targetUri = target.targetUrl || FALLBACK_TARGET_URL;
	const toolVersion = options.toolVersion || CORE_VERSION;
	const { detectedWAF } = calculateAuditStats(results, target.targetUrl);
	const { rules, indexById } = buildRules(results);

	const sarifResults = results
		.filter(isBypassResult)
		.map((r) => buildResult(r, targetUri, indexById.get(ruleIdForCategory(r.category))!, detectedWAF));

	const errorCount = results.filter(isErrorResult).length;
	const invocation: any = {
		executionSuccessful: !(results.length > 0 && errorCount === results.length),
		startTimeUtc: now,
		endTimeUtc: now,
	};
	if (errorCount > 0) {
		invocation.toolExecutionNotifications = [
			{
				level: 'warning',
				message: { text: `${errorCount} of ${results.length} test requests failed (network error, timeout or invalid response).` },
			},
		];
	}

	const run: any = {
		tool: {
			driver: {
				name: TOOL_NAME,
				version: toolVersion,
				semanticVersion: toolVersion,
				informationUri: INFORMATION_URI,
				rules,
			},
		},
		automationDetails: {
			id: options.automationId || `waf-checker/${hostOf(targetUri)}`,
		},
		invocations: [invocation],
		columnKind: 'utf16CodeUnits',
		results: sarifResults,
	};

	if (target.reverseEngineering) {
		run.properties = { reverseEngineering: target.reverseEngineering };
	}
	return run;
}

function serialize(runs: any[]): string {
	return JSON.stringify({ $schema: SARIF_SCHEMA_URI, version: '2.1.0', runs }, null, 2);
}

export function generateSARIFReport(
	results: AuditResultItem[],
	targetUrl?: string,
	reverseEngineering?: ReverseEngineeringReport,
	options: SarifOptions = {},
): string {
	return serialize([buildRun({ targetUrl, results, reverseEngineering }, options, new Date().toISOString())]);
}

/** One SARIF document with one run per target. */
export function generateMultiTargetSARIFReport(targets: SarifTarget[], options: SarifOptions = {}): string {
	const now = new Date().toISOString();
	return serialize(targets.map((t) => buildRun(t, options, now)));
}
