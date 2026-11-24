import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { validateSarif } from './fixtures/sarif-validator';
import {
	calculateAuditStats,
	generateSARIFReport,
	generateMultiTargetSARIFReport,
	generateJSONReport,
	generateJUnitReport,
	generateReport,
	AuditResultItem,
} from '../src/reports';
import type { ReverseEngineeringReport } from '../src/reverse-engineering/types';
import { CORE_VERSION } from '../src/version';

const mockResults: AuditResultItem[] = [
	{
		category: 'SQLi',
		payload: "' OR '1'='1",
		method: 'GET',
		status: 403,
		responseTime: 45,
		wafDetected: true,
		wafType: 'Cloudflare',
	},
	{
		category: 'XSS',
		payload: '<script>alert(1)</script>',
		method: 'POST',
		status: 200, // Bypassed!
		responseTime: 80,
		wafDetected: true,
		wafType: 'Cloudflare',
		bypassTechnique: 'Standard',
	},
	{
		category: 'RCE',
		payload: '; cat /etc/passwd',
		method: 'GET',
		status: 'BLOCKED',
		responseTime: 30,
		wafDetected: true,
		wafType: 'Cloudflare',
	},
	{
		category: 'LFI',
		payload: '../../../../etc/hosts',
		method: 'GET',
		status: 'ERR',
		responseTime: 0,
	},
];

const mockReverseEngineering: ReverseEngineeringReport = {
	targetUrl: 'https://example.com',
	crsRules: [
		{
			ruleId: '942100',
			name: 'SQL Injection Attack Detected via libinjection',
			category: 'SQLi',
			paranoiaLevel: 1,
			anomalyScore: 5,
			status: 'active',
			probePayload: "' OR 1=1--",
			statusCode: 403,
			responseTime: 42,
		},
	],
	crsSummary: { total: 1, active: 1, disabled: 0, bypassed: 0, activePercent: 100 },
	bodyLimit: { limitBytes: 8192, limitFormatted: '8 KB', confidence: 0.9, detected: true },
	anomalyScore: { mode: 'anomaly_scoring', detectedThreshold: 5, confidence: 0.8 },
	rateLimit: { detected: false, thresholdRps: null, retryAfterSeconds: null, safeTestedMaxRps: 10 },
	timestamp: '2026-01-01T00:00:00.000Z',
};

describe('Reports Module', () => {
	describe('calculateAuditStats', () => {
		it('correctly aggregates results stats', () => {
			const stats = calculateAuditStats(mockResults, 'https://example.com');
			expect(stats.total).toBe(4);
			expect(stats.blocked).toBe(2); // 403 + BLOCKED
			expect(stats.bypassed).toBe(1); // 200
			expect(stats.errors).toBe(1); // ERR
			expect(stats.protectionScore).toBe(50); // 2 / 4 = 50%
			expect(stats.detectedWAF).toBe('Cloudflare');
			expect(stats.targetUrl).toBe('https://example.com');
		});

		it('handles empty results array', () => {
			const stats = calculateAuditStats([]);
			expect(stats.total).toBe(0);
			expect(stats.blocked).toBe(0);
			expect(stats.bypassed).toBe(0);
			expect(stats.protectionScore).toBe(100);
		});
	});

	describe('generateSARIFReport', () => {
		it('generates valid SARIF 2.1.0 json', () => {
			const sarifStr = generateSARIFReport(mockResults, 'https://example.com');
			const sarif = JSON.parse(sarifStr);

			expect(sarif.version).toBe('2.1.0');
			expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
			expect(sarif.runs).toHaveLength(1);

			const run = sarif.runs[0];
			expect(run.tool.driver.name).toBe('WAF-Checker');
			expect(run.tool.driver.rules.length).toBeGreaterThan(0);

			// Should only include bypassed items in results
			expect(run.results).toHaveLength(1);
			expect(run.results[0].ruleId).toBe('WAF-XSS');
			expect(run.results[0].level).toBe('error');
			expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('https://example.com');
		});

		it('passes the official SARIF 2.1.0 schema (with, without and empty results)', () => {
			for (const doc of [
				generateSARIFReport(mockResults, 'https://example.com'),
				generateSARIFReport(mockResults),
				generateSARIFReport([], 'https://example.com'),
				generateSARIFReport([]),
				generateSARIFReport(mockResults, 'https://example.com', mockReverseEngineering),
				generateSARIFReport(mockResults, 'https://example.com', undefined, { toolVersion: '9.9.9', automationId: 'ci/nightly/' }),
			]) {
				expect(validateSarif(doc)).toEqual([]);
			}
		});

		it('schema validator rejects malformed SARIF (sanity check)', () => {
			const doc = JSON.parse(generateSARIFReport(mockResults, 'https://example.com'));
			doc.runs[0].results[0].level = 'critical';
			delete doc.runs[0].tool.driver.name;
			expect(validateSarif(doc).length).toBeGreaterThan(0);
		});

		it('takes the tool version from the core package, overridable via options', () => {
			const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
			expect(CORE_VERSION).toBe(pkg.version);

			const driver = JSON.parse(generateSARIFReport(mockResults, 'https://example.com')).runs[0].tool.driver;
			expect(driver.version).toBe(pkg.version);
			expect(driver.semanticVersion).toBe(pkg.version);

			const custom = JSON.parse(generateSARIFReport(mockResults, 'https://example.com', undefined, { toolVersion: '2.0.0-rc.1' }));
			expect(custom.runs[0].tool.driver.version).toBe('2.0.0-rc.1');
			expect(custom.runs[0].tool.driver.semanticVersion).toBe('2.0.0-rc.1');
		});

		it('describes rules with help, helpUri, tags and security-severity', () => {
			const results: AuditResultItem[] = [
				{ category: 'SQL Injection', payload: "' OR 1=1--", method: 'GET', status: 200, responseTime: 10 },
				{ category: 'XSS', payload: '<svg onload=alert(1)>', method: 'GET', status: 200, responseTime: 10 },
				{ category: 'Open Redirect', payload: '//evil.example', method: 'GET', status: 200, responseTime: 10 },
				{ category: 'Totally New Category', payload: 'x', method: 'GET', status: 200, responseTime: 10 },
			];
			const run = JSON.parse(generateSARIFReport(results, 'https://example.com')).runs[0];
			const byId = Object.fromEntries(run.tool.driver.rules.map((r: any) => [r.id, r]));

			expect(Object.keys(byId)).toEqual(['WAF-SQL-INJECTION', 'WAF-XSS', 'WAF-OPEN-REDIRECT', 'WAF-TOTALLY-NEW-CATEGORY']);
			for (const rule of run.tool.driver.rules) {
				expect(rule.help.text.length).toBeGreaterThan(0);
				expect(rule.help.markdown.length).toBeGreaterThan(0);
				expect(rule.helpUri).toMatch(/^https:\/\/github\.com\/SecH0us3\/waf-checker/);
				expect(rule.properties.tags).toContain('security');
				expect(typeof rule.properties['security-severity']).toBe('string');
				expect(rule.properties['security-severity']).toMatch(/^\d+\.\d$/);
			}
			expect(byId['WAF-SQL-INJECTION'].properties['security-severity']).toBe('8.0');
			expect(byId['WAF-XSS'].properties['security-severity']).toBe('7.0');
			expect(byId['WAF-OPEN-REDIRECT'].properties['security-severity']).toBe('5.0');
			expect(byId['WAF-OPEN-REDIRECT'].defaultConfiguration.level).toBe('warning');
			expect(byId['WAF-TOTALLY-NEW-CATEGORY'].properties['security-severity']).toBe('7.0');

			// Result level follows the rule, ruleIndex points at the right rule.
			for (const res of run.results) {
				expect(run.tool.driver.rules[res.ruleIndex].id).toBe(res.ruleId);
				expect(res.level).toBe(run.tool.driver.rules[res.ruleIndex].defaultConfiguration.level);
			}
		});

		it('keeps ruleIndex correct when categories collide on the same rule id', () => {
			const results: AuditResultItem[] = [
				{ category: 'a b', payload: '1', method: 'GET', status: 403, responseTime: 1 },
				{ category: 'A-B', payload: '2', method: 'GET', status: 200, responseTime: 1 },
				{ category: 'C', payload: '3', method: 'GET', status: 200, responseTime: 1 },
			];
			const run = JSON.parse(generateSARIFReport(results, 'https://example.com')).runs[0];
			expect(run.tool.driver.rules.map((r: any) => r.id)).toEqual(['WAF-A-B', 'WAF-C']);
			expect(run.results.map((r: any) => r.ruleIndex)).toEqual([0, 1]);
		});

		it('locates results at the target URL without a fake file region', () => {
			const run = JSON.parse(generateSARIFReport(mockResults, 'https://example.com/app?x=1')).runs[0];
			const loc = run.results[0].locations[0];
			expect(loc.physicalLocation.artifactLocation.uri).toBe('https://example.com/app?x=1');
			expect(loc.physicalLocation.region).toBeUndefined();
			expect(loc.logicalLocations[0]).toEqual({ name: 'POST XSS', kind: 'endpoint' });
		});

		it('emits stable, time-independent partialFingerprints', () => {
			const a = JSON.parse(generateSARIFReport(mockResults, 'https://example.com/a')).runs[0].results[0];
			// Different timing/status details and path on the same host -> same fingerprint.
			const slower = mockResults.map((r) => ({ ...r, responseTime: r.responseTime + 999 }));
			const b = JSON.parse(generateSARIFReport(slower, 'https://EXAMPLE.com/b')).runs[0].results[0];
			expect(Object.keys(a.partialFingerprints)).toEqual(['wafCheckerFinding/v1']);
			expect(a.partialFingerprints['wafCheckerFinding/v1']).toMatch(/^[0-9a-f]{64}$/);
			expect(b.partialFingerprints).toEqual(a.partialFingerprints);

			// Another host, method or payload -> different fingerprint.
			const otherHost = JSON.parse(generateSARIFReport(mockResults, 'https://other.example')).runs[0].results[0];
			expect(otherHost.partialFingerprints).not.toEqual(a.partialFingerprints);
			const otherPayload = mockResults.map((r) => (r.category === 'XSS' ? { ...r, payload: r.payload + ' ' } : r));
			expect(JSON.parse(generateSARIFReport(otherPayload, 'https://example.com')).runs[0].results[0].partialFingerprints).not.toEqual(
				a.partialFingerprints,
			);
			const otherMethod = mockResults.map((r) => (r.category === 'XSS' ? { ...r, method: 'GET' } : r));
			expect(JSON.parse(generateSARIFReport(otherMethod, 'https://example.com')).runs[0].results[0].partialFingerprints).not.toEqual(
				a.partialFingerprints,
			);
		});

		it('hashes fingerprints with SHA-256', () => {
			// sha256("XSS\0POST\0<script>alert(1)</script>\0example.com")
			const fp = JSON.parse(generateSARIFReport(mockResults, 'https://example.com')).runs[0].results[0].partialFingerprints[
				'wafCheckerFinding/v1'
			];
			expect(fp).toBe(createHash('sha256').update('XSS\0POST\0<script>alert(1)</script>\0example.com').digest('hex'));
		});

		it('records automationDetails and invocation timing', () => {
			const run = JSON.parse(generateSARIFReport(mockResults, 'https://Example.com:8443/path')).runs[0];
			expect(run.automationDetails.id).toBe('waf-checker/example.com:8443/');
			expect(run.invocations).toHaveLength(1);
			const inv = run.invocations[0];
			expect(inv.executionSuccessful).toBe(true);
			expect(Date.parse(inv.startTimeUtc)).not.toBeNaN();
			expect(Date.parse(inv.endTimeUtc)).toBeGreaterThanOrEqual(Date.parse(inv.startTimeUtc));
			// One ERR result in mockResults -> surfaced as a warning notification.
			expect(inv.toolExecutionNotifications[0].level).toBe('warning');

			const custom = JSON.parse(generateSARIFReport(mockResults, 'https://example.com', undefined, { automationId: 'nightly/prod' }));
			expect(custom.runs[0].automationDetails.id).toBe('nightly/prod');

			const allFailed = JSON.parse(
				generateSARIFReport([{ category: 'XSS', payload: 'x', method: 'GET', status: 'ERR', responseTime: 0 }], 'https://example.com'),
			);
			expect(allFailed.runs[0].invocations[0].executionSuccessful).toBe(false);
		});

		it('uses caller-supplied invocation times (Date or string), falling back to now', () => {
			const run = JSON.parse(
				generateSARIFReport(mockResults, 'https://example.com', undefined, {
					startTimeUtc: new Date('2026-01-02T03:04:05Z'),
					endTimeUtc: '2026-01-02T03:14:05.500+00:00',
				}),
			).runs[0];
			expect(run.invocations[0].startTimeUtc).toBe('2026-01-02T03:04:05.000Z');
			expect(run.invocations[0].endTimeUtc).toBe('2026-01-02T03:14:05.500Z');

			const before = Date.now();
			const bad = JSON.parse(generateSARIFReport(mockResults, 'https://example.com', undefined, { startTimeUtc: 'not a date' })).runs[0];
			expect(Date.parse(bad.invocations[0].startTimeUtc)).toBeGreaterThanOrEqual(before - 1000);
			expect(validateSarif({ version: '2.1.0', runs: [bad] })).toEqual([]);
		});

		it('attaches the reverse engineering report as run properties', () => {
			const run = JSON.parse(generateSARIFReport(mockResults, 'https://example.com', mockReverseEngineering)).runs[0];
			expect(run.properties.reverseEngineering).toEqual(mockReverseEngineering);
			expect(JSON.parse(generateSARIFReport(mockResults, 'https://example.com')).runs[0].properties).toBeUndefined();
		});
	});

	describe('generateMultiTargetSARIFReport', () => {
		it('emits one run per target in a single schema-valid document', () => {
			const doc = generateMultiTargetSARIFReport([
				{ targetUrl: 'https://a.example', results: mockResults },
				{ targetUrl: 'https://b.example/login', results: mockResults, reverseEngineering: mockReverseEngineering },
				{ targetUrl: 'https://c.example', results: [] },
			]);
			expect(validateSarif(doc)).toEqual([]);

			const sarif = JSON.parse(doc);
			expect(sarif.version).toBe('2.1.0');
			expect(sarif.runs).toHaveLength(3);
			expect(sarif.runs.map((r: any) => r.automationDetails.id)).toEqual([
				'waf-checker/a.example/',
				'waf-checker/b.example/',
				'waf-checker/c.example/',
			]);
			expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('https://a.example');
			expect(sarif.runs[1].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('https://b.example/login');
			expect(sarif.runs[0].properties).toBeUndefined();
			expect(sarif.runs[1].properties.reverseEngineering).toEqual(mockReverseEngineering);
			expect(sarif.runs[2].results).toEqual([]);
			// Same finding on different hosts must not collapse into one alert.
			expect(sarif.runs[0].results[0].partialFingerprints).not.toEqual(sarif.runs[1].results[0].partialFingerprints);
		});

		// GitHub code scanning: an id ending in '/' is the category; otherwise the category is the id up to its last '/'.
		const githubCategory = (id: string) => (id.endsWith('/') ? id.slice(0, -1) : id.slice(0, Math.max(0, id.lastIndexOf('/'))));

		it('gives every run its own automation category', () => {
			const targets = [
				{ targetUrl: 'https://a.example', results: mockResults },
				{ targetUrl: 'https://b.example/x', results: mockResults },
				{ targetUrl: 'https://b.example:8443', results: [] },
			];
			const hosts = ['a.example', 'b.example', 'b.example:8443'];
			for (const [automationId, expected] of [
				[undefined, hosts.map((h) => `waf-checker/${h}/`)],
				['ci/nightly', hosts.map((h) => `ci/nightly/${h}/`)],
				['ci/nightly/', hosts.map((h) => `ci/nightly/${h}/`)],
			] as const) {
				const doc = generateMultiTargetSARIFReport(targets, { automationId });
				expect(validateSarif(doc)).toEqual([]);
				const ids = JSON.parse(doc).runs.map((r: any) => r.automationDetails.id);
				expect(ids).toEqual(expected);
				const categories = ids.map(githubCategory);
				expect(new Set(categories).size).toBe(targets.length);
			}
		});

		it('lets per-target times override option times', () => {
			const doc = generateMultiTargetSARIFReport(
				[
					{ targetUrl: 'https://a.example', results: mockResults, startTimeUtc: '2026-03-01T10:00:00Z', endTimeUtc: new Date('2026-03-01T10:05:00Z') },
					{ targetUrl: 'https://b.example', results: mockResults },
				],
				{ startTimeUtc: '2026-03-01T09:00:00Z', endTimeUtc: '2026-03-01T11:00:00Z' },
			);
			expect(validateSarif(doc)).toEqual([]);
			const [a, b] = JSON.parse(doc).runs.map((r: any) => r.invocations[0]);
			expect([a.startTimeUtc, a.endTimeUtc]).toEqual(['2026-03-01T10:00:00.000Z', '2026-03-01T10:05:00.000Z']);
			expect([b.startTimeUtc, b.endTimeUtc]).toEqual(['2026-03-01T09:00:00.000Z', '2026-03-01T11:00:00.000Z']);
		});

		it('matches the single-target report for a single target', () => {
			const strip = (doc: string) => {
				const s = JSON.parse(doc);
				for (const run of s.runs) delete run.invocations;
				return s;
			};
			expect(strip(generateMultiTargetSARIFReport([{ targetUrl: 'https://example.com', results: mockResults }]))).toEqual(
				strip(generateSARIFReport(mockResults, 'https://example.com')),
			);
		});

		it('handles an empty target list and options', () => {
			expect(validateSarif(generateMultiTargetSARIFReport([]))).toEqual([]);
			expect(JSON.parse(generateMultiTargetSARIFReport([])).runs).toEqual([]);
			const doc = generateMultiTargetSARIFReport([{ targetUrl: 'https://example.com', results: mockResults }], { toolVersion: '3.1.4' });
			expect(validateSarif(doc)).toEqual([]);
			expect(JSON.parse(doc).runs[0].tool.driver.version).toBe('3.1.4');
		});
	});

	describe('generateJSONReport', () => {
		it('generates structured JSON', () => {
			const jsonStr = generateJSONReport(mockResults, 'https://example.com');
			const parsed = JSON.parse(jsonStr);

			expect(parsed.summary.total).toBe(4);
			expect(parsed.summary.protectionScore).toBe(50);
			expect(parsed.results).toHaveLength(4);
		});
	});

	describe('generateReport helper', () => {
		it('routes correctly to different formats', () => {
			expect(JSON.parse(generateReport('sarif', mockResults)).version).toBe('2.1.0');
			const withRe = JSON.parse(generateReport('sarif', mockResults, 'https://example.com', undefined, mockReverseEngineering));
			expect(withRe.runs[0].properties.reverseEngineering).toEqual(mockReverseEngineering);
			expect(JSON.parse(generateReport('json', mockResults)).summary).toBeDefined();
			expect(generateReport('junit', mockResults)).toContain('<testsuites');
		});
	});

	describe('generateJUnitReport', () => {
		it('produces a well-formed JUnit XML document', () => {
			const xml = generateJUnitReport(mockResults, 'https://example.com');
			expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
			expect(xml).toContain('<testsuites name="WAF-Checker"');
			expect(xml.trim().endsWith('</testsuites>')).toBe(true);
			// Every open tag has a matching close (or self-close).
			const suites = (xml.match(/<testsuite /g) || []).length;
			const suiteCloses = (xml.match(/<\/testsuite>/g) || []).length;
			expect(suites).toBe(suiteCloses);
		});

		it('counts totals and maps bypass -> failure, error -> error', () => {
			const xml = generateJUnitReport(mockResults, 'https://example.com');
			// 4 results, 1 bypass (200), 1 error (ERR)
			expect(xml).toContain('tests="4"');
			expect(xml).toContain('failures="1"');
			expect(xml).toContain('errors="1"');
			expect(xml).toContain('<failure ');
			expect(xml).toContain('type="WafBypass"');
			expect(xml).toContain('<error ');
			expect(xml).toContain('type="RequestError"');
		});

		it('groups testcases into one testsuite per category', () => {
			const xml = generateJUnitReport(mockResults);
			expect(xml).toContain('<testsuite name="SQLi"');
			expect(xml).toContain('<testsuite name="XSS"');
			expect(xml).toContain('classname="WAF.XSS"');
		});

		it('escapes XML metacharacters in payloads and attributes', () => {
			const xml = generateJUnitReport([
				{
					category: 'XSS & "friends"',
					payload: '<script>alert(1)</script>',
					method: 'GET',
					status: 200,
					responseTime: 12,
				},
			]);
			expect(xml).not.toContain('<script>alert(1)</script>');
			expect(xml).toContain('&lt;script&gt;');
			expect(xml).toContain('&amp;');
			expect(xml).toContain('&quot;');
		});

		it('reports response time in seconds', () => {
			const xml = generateJUnitReport([
				{ category: 'SQLi', payload: 'x', method: 'GET', status: 403, responseTime: 1500 },
			]);
			expect(xml).toContain('time="1.500"');
		});

		it('treats a legitimate User-Agent bypass as a failure', () => {
			const xml = generateJUnitReport([
				{
					category: 'IP Bypass',
					payload: 'x',
					method: 'GET',
					status: 403,
					responseTime: 20,
					userAgentBypass: {
						bypassed: true,
						tested: 3,
						hits: [{ name: 'Googlebot', userAgent: 'Googlebot', status: 200, verdict: 'exposed' }],
					},
				},
			]);
			expect(xml).toContain('failures="1"');
			expect(xml).toContain('Googlebot');
		});

		it('does not embed raw line breaks inside attribute values', () => {
			const xml = generateJUnitReport([
				{
					category: 'HTTP Request Smuggling',
					payload: 'Transfer-Encoding: chunked\r\n0\r\n\r\nGARBAGE',
					method: 'POST',
					status: 200,
					responseTime: 10,
				},
			]);
			// The name attribute (first line up to its closing quote) must be single-line.
			const nameAttr = xml.match(/name="([^"]*)"/);
			expect(nameAttr).not.toBeNull();
			expect(nameAttr![1]).not.toMatch(/[\r\n]/);
			// CR/LF were encoded as numeric entities instead.
			expect(xml).toContain('&#13;');
			expect(xml).toContain('&#10;');
		});

		it('handles an empty result set', () => {
			const xml = generateJUnitReport([]);
			expect(xml).toContain('tests="0"');
			expect(xml).toContain('failures="0"');
			expect(xml.trim().endsWith('</testsuites>')).toBe(true);
		});
	});
});
