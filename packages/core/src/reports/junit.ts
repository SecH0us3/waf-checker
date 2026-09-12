import { AuditResultItem, calculateAuditStats } from './types';

/**
 * Escape a string for safe inclusion in an XML attribute or text node.
 * Also strips control characters that are illegal in XML 1.0 (except \t \n \r).
 */
function escapeXml(value: unknown): string {
	const str = String(value ?? '');
	// eslint-disable-next-line no-control-regex
	const stripped = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
	return stripped
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&apos;');
}

/**
 * Escape a string for an XML attribute value. Same as {@link escapeXml} but
 * also encodes tab/newline/carriage-return as numeric entities: parsers
 * normalize raw line breaks in attribute values to spaces, so payloads that
 * carry CRLF (e.g. HTTP request smuggling) must not embed them verbatim.
 */
function escapeXmlAttr(value: unknown): string {
	return escapeXml(value).replace(/\t/g, '&#9;').replace(/\n/g, '&#10;').replace(/\r/g, '&#13;');
}

/** Response times are reported in milliseconds; JUnit expects seconds. */
function toSeconds(ms: number): string {
	return (Math.max(0, ms || 0) / 1000).toFixed(3);
}

type Outcome = 'failure' | 'error' | 'pass';

/**
 * Classify a single audit result into a JUnit test outcome.
 *
 * - A payload that was NOT blocked (HTTP 200), or a request that a legitimate
 *   User-Agent got through, is a WAF **bypass** and reported as a `failure`.
 * - A transport/server error (ERR, 5xx) is reported as an `error`.
 * - Anything else (403/BLOCKED, redirects, 4xx) is a passing test — the WAF
 *   behaved as intended.
 */
function classify(r: AuditResultItem): Outcome {
	if (r.userAgentBypass?.bypassed) return 'failure';
	if (r.status === 200 || r.status === '200') return 'failure';
	if (r.status === 'ERR' || r.status === 500 || r.status === '500' || r.error) return 'error';
	return 'pass';
}

/**
 * Generate a JUnit-style XML report from WAF audit results.
 *
 * The format is consumed natively by CI systems (GitHub Actions test
 * reporters, GitLab CI `junit:` artifacts, Jenkins JUnit plugin, ...), letting
 * a WAF audit surface bypasses as failing "tests" in a pipeline. Each payload
 * becomes a `<testcase>`; results are grouped into one `<testsuite>` per
 * attack category.
 */
export function generateJUnitReport(results: AuditResultItem[], targetUrl?: string): string {
	const stats = calculateAuditStats(results, targetUrl);

	// Group results by category, preserving first-seen order.
	const groups = new Map<string, AuditResultItem[]>();
	for (const r of results) {
		const cat = r.category || 'Uncategorized';
		if (!groups.has(cat)) groups.set(cat, []);
		groups.get(cat)!.push(r);
	}

	let totalFailures = 0;
	let totalErrors = 0;
	let totalTimeMs = 0;

	const suiteXml: string[] = [];
	for (const [category, items] of groups) {
		let suiteFailures = 0;
		let suiteErrors = 0;
		let suiteTimeMs = 0;
		const caseXml: string[] = [];

		items.forEach((r, idx) => {
			const outcome = classify(r);
			suiteTimeMs += r.responseTime || 0;
			if (outcome === 'failure') suiteFailures++;
			else if (outcome === 'error') suiteErrors++;

			// A payload string can be long/duplicated; disambiguate with an index.
			const caseName = `${r.method} ${r.payload}`.slice(0, 250) || `case-${idx + 1}`;
			const classname = `WAF.${category}`;
			const attrs =
				`name="${escapeXmlAttr(caseName)}" classname="${escapeXmlAttr(classname)}" ` +
				`time="${toSeconds(r.responseTime)}"`;

			if (outcome === 'pass') {
				caseXml.push(`\t\t<testcase ${attrs} />`);
				return;
			}

			const tag = outcome === 'failure' ? 'failure' : 'error';
			const message =
				outcome === 'failure'
					? (r.userAgentBypass?.bypassed
						? `WAF bypass: request allowed under a trusted User-Agent (${r.userAgentBypass.hits.map((h) => h.name).join(', ')})`
						: `WAF bypass: ${category} payload was not blocked (status ${r.status})`)
					: `Request error (status ${r.status})`;
			const type = outcome === 'failure' ? 'WafBypass' : 'RequestError';
			const body = [
				`Category: ${category}`,
				`Method: ${r.method}`,
				`Status: ${r.status}`,
				`Payload: ${r.payload}`,
				r.originalPayload ? `Original payload: ${r.originalPayload}` : '',
				r.bypassTechnique ? `Bypass technique: ${r.bypassTechnique}` : '',
				r.wafType ? `Detected WAF: ${r.wafType}` : '',
				targetUrl ? `Target: ${targetUrl}` : '',
			]
				.filter(Boolean)
				.join('\n');

			caseXml.push(
				`\t\t<testcase ${attrs}>`,
				`\t\t\t<${tag} message="${escapeXmlAttr(message)}" type="${type}">${escapeXml(body)}</${tag}>`,
				`\t\t</testcase>`,
			);
		});

		totalFailures += suiteFailures;
		totalErrors += suiteErrors;
		totalTimeMs += suiteTimeMs;

		suiteXml.push(
			`\t<testsuite name="${escapeXmlAttr(category)}" tests="${items.length}" ` +
				`failures="${suiteFailures}" errors="${suiteErrors}" skipped="0" ` +
				`time="${toSeconds(suiteTimeMs)}">`,
			...caseXml,
			`\t</testsuite>`,
		);
	}

	const suitesAttrs =
		`name="WAF-Checker" tests="${stats.total}" failures="${totalFailures}" ` +
		`errors="${totalErrors}" time="${toSeconds(totalTimeMs)}"` +
		(targetUrl ? ` package="${escapeXmlAttr(targetUrl)}"` : '');

	return [
		'<?xml version="1.0" encoding="UTF-8"?>',
		`<testsuites ${suitesAttrs}>`,
		...suiteXml,
		'</testsuites>',
		'',
	].join('\n');
}
