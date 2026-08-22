import { describe, it, expect } from 'vitest';
import {
	calculateAuditStats,
	generateSARIFReport,
	generateMarkdownReport,
	generateHTMLReport,
	generateJSONReport,
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

	describe('generateMarkdownReport', () => {
		it('generates markdown report with summary and details', () => {
			const md = generateMarkdownReport(mockResults, 'https://example.com');

			expect(md).toContain('# 🛡️ WAF Checker Audit Report');
			expect(md).toContain('Overall Score: 50%');
			expect(md).toContain('https://example.com');
			expect(md).toContain('SQLi');
			expect(md).toContain('XSS');
			expect(md).toContain('### ⚠️ Bypassed Payloads (1)');
			expect(md).toContain('<script>alert(1)</script>');
		});

		it('shows no bypasses message when all are blocked', () => {
			const cleanResults: AuditResultItem[] = [
				{
					category: 'SQLi',
					payload: 'test',
					method: 'GET',
					status: 403,
					responseTime: 10,
				},
			];
			const md = generateMarkdownReport(cleanResults, 'https://example.com');
			expect(md).toContain('No Bypasses Detected');
		});
	});

	describe('generateHTMLReport', () => {
		it('generates HTML report with safe escaping', () => {
			const html = generateHTMLReport(mockResults, 'https://example.com');

			expect(html).toContain('<!DOCTYPE html>');
			expect(html).toContain('50%');
			expect(html).toContain('Cloudflare');
			// Payloads must be HTML escaped
			expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
			expect(html).not.toContain('<script>alert(1)</script>');
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
			expect(generateReport('markdown', mockResults)).toContain('# 🛡️ WAF Checker');
			expect(generateReport('html', mockResults)).toContain('<!DOCTYPE html>');
			expect(JSON.parse(generateReport('json', mockResults)).summary).toBeDefined();
		});
	});
});
