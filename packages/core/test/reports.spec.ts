import { describe, it, expect } from 'vitest';
import {
	calculateAuditStats,
	generateSARIFReport,
	generateJSONReport,
	generateJUnitReport,
	generateReport,
	AuditResultItem,
} from '../src/reports';

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

		it('handles an empty result set', () => {
			const xml = generateJUnitReport([]);
			expect(xml).toContain('tests="0"');
			expect(xml).toContain('failures="0"');
			expect(xml.trim().endsWith('</testsuites>')).toBe(true);
		});
	});
});
