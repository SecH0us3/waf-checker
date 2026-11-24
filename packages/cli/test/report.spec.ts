import { describe, it, expect, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { deduceFormat, writeReport, toSarifTargets, toBatchSummaries } from '../src/report';

vi.mock('fs', async () => {
	const actual = await vi.importActual<typeof import('fs')>('fs');
	return {
		...actual,
		writeFileSync: vi.fn(),
		mkdirSync: vi.fn(),
		existsSync: vi.fn((p) => {
			if (p === 'existing-dir') return true;
			return false;
		})
	};
});

describe('Report Module', () => {
	describe('deduceFormat', () => {
		it('should deduce json format from extension', () => {
			expect(deduceFormat('test.json')).toBe('json');
			expect(deduceFormat('path/to/test.JSON')).toBe('json');
		});

		it('should deduce csv format from extension', () => {
			expect(deduceFormat('test.csv')).toBe('csv');
			expect(deduceFormat('test.CSV')).toBe('csv');
		});

		it('should deduce html format from extension', () => {
			expect(deduceFormat('test.html')).toBe('html');
			expect(deduceFormat('test.htm')).toBe('html');
		});

		it('should deduce junit format from extension', () => {
			expect(deduceFormat('test.junit')).toBe('junit');
			expect(deduceFormat('report.xml')).toBe('junit');
			expect(deduceFormat('report.XML')).toBe('junit');
		});

		it('should default to html for unknown extensions', () => {
			expect(deduceFormat('test.txt')).toBe('html');
			expect(deduceFormat('test')).toBe('html');
		});
	});

	describe('writeReport', () => {
		const checkResults = [
			{ status: 403, method: 'GET', payload: 'test-sql', responseTime: 100, category: 'SQL Injection' },
			{ status: 200, method: 'POST', payload: 'test-xss', responseTime: 120, category: 'XSS', is_redirect: false }
		];

		const batchResults = [
			{ url: 'https://example.com', success: true, total: 10, blocked: 9, bypassed: 1, bypassRate: 10 },
			{ url: 'https://google.com', success: false, total: 0, blocked: 0, bypassed: 0, bypassRate: 0, error: 'Connection failure' }
		];

		it('should write JSON check reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.json', 'json', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.json', expect.stringContaining('"status": 403'), 'utf8');
		});

		it('should write SARIF check reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.sarif', 'sarif', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.sarif', expect.stringContaining('"version": "2.1.0"'), 'utf8');
		});

		it('should write JUnit check reports', () => {
			vi.clearAllMocks();
			writeReport('report.xml', 'junit', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.xml', expect.stringContaining('<testsuites'), 'utf8');
		});

		it('should throw error when requesting JUnit for batch report', () => {
			expect(() => {
				writeReport('batch.xml', 'junit', 'batch', 'targets.txt', batchResults);
			}).toThrow(/only supported for single target/);
		});

		it('should keep single-target SARIF as one run with its bypasses', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.sarif', 'sarif', 'check', 'https://example.com', checkResults);
			const doc = JSON.parse(vi.mocked(fs.writeFileSync).mock.calls[0][1] as string);
			expect(doc.version).toBe('2.1.0');
			expect(doc.runs).toHaveLength(1);
			expect(doc.runs[0].results).toHaveLength(1);
			expect(doc.runs[0].results[0].ruleId).toBe('WAF-XSS');
		});

		describe('batch SARIF', () => {
			const detailedBatch = [
				{
					url: 'https://a.example.com/', success: true, total: 2, blocked: 1, bypassed: 1, bypassRate: 50,
					results: [
						{ status: 403, method: 'GET', payload: 'a-sql', responseTime: 10, category: 'SQL Injection' },
						{ status: 200, method: 'GET', payload: 'a-xss', responseTime: 12, category: 'XSS' },
					],
				},
				{
					url: 'https://b.example.org/', success: true, total: 2, blocked: 0, bypassed: 2, bypassRate: 100,
					results: [
						{ status: 200, method: 'GET', payload: 'b-sql', responseTime: 10, category: 'SQL Injection' },
						{ status: 200, method: 'POST', payload: 'b-xss', responseTime: 11, category: 'XSS' },
					],
				},
				{ url: 'https://down.example.net/', success: false, total: 0, blocked: 0, bypassed: 0, bypassRate: 0, error: 'Connection failure' },
			];

			const writeBatchSarif = (results: any[]) => {
				vi.mocked(fs.writeFileSync).mockClear();
				writeReport('batch.sarif', 'sarif', 'batch', 'targets.txt', results);
				expect(fs.writeFileSync).toHaveBeenCalledTimes(1);
				const [outPath, content, encoding] = vi.mocked(fs.writeFileSync).mock.calls[0];
				expect(outPath).toBe('batch.sarif');
				expect(encoding).toBe('utf8');
				return JSON.parse(content as string);
			};

			it('should write one valid SARIF 2.1.0 document with one run per scanned target', () => {
				const doc = writeBatchSarif(detailedBatch);
				expect(doc.version).toBe('2.1.0');
				expect(doc.$schema).toContain('sarif');
				expect(doc.runs).toHaveLength(2);
				for (const run of doc.runs) {
					expect(run.tool.driver.name).toBeTruthy();
					expect(Array.isArray(run.results)).toBe(true);
				}
			});

			it('should attribute each target\'s bypasses to its own run', () => {
				const doc = writeBatchSarif(detailedBatch);
				const [runA, runB] = doc.runs;
				expect(runA.results).toHaveLength(1);
				expect(runB.results).toHaveLength(2);
				expect(runA.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('https://a.example.com/');
				for (const result of runB.results) {
					expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('https://b.example.org/');
				}
				expect(JSON.stringify(runA)).not.toContain('b-sql');
				expect(JSON.stringify(runB)).not.toContain('a-xss');
			});

			it('should give every run a distinct automation id per target host', () => {
				const doc = writeBatchSarif(detailedBatch);
				const ids = doc.runs.map((run: any) => run.automationDetails?.id);
				expect(ids[0]).toContain('a.example.com');
				expect(ids[1]).toContain('b.example.org');
				expect(new Set(ids).size).toBe(ids.length);
			});

			it('should leave failed targets out instead of emitting an empty run', () => {
				const doc = writeBatchSarif(detailedBatch);
				expect(JSON.stringify(doc)).not.toContain('down.example.net');
			});

			it('should map scanned targets to SARIF targets with their real scan times', () => {
				const timed = [
					{ ...detailedBatch[0], startTimeUtc: '2026-11-24T10:00:00.000Z', endTimeUtc: '2026-11-24T10:00:05.000Z' },
					detailedBatch[1],
					detailedBatch[2],
				];
				const targets = toSarifTargets(timed as any);
				expect(targets).toHaveLength(2);
				expect(targets[0]).toEqual({
					targetUrl: 'https://a.example.com/',
					results: detailedBatch[0].results,
					startTimeUtc: '2026-11-24T10:00:00.000Z',
					endTimeUtc: '2026-11-24T10:00:05.000Z',
				});
				// No invented timestamps when the scan time is unknown
				expect(targets[1]).not.toHaveProperty('startTimeUtc');
				expect(targets[1]).not.toHaveProperty('endTimeUtc');
			});

			it('should strip per-payload results and scan times from batch summaries', () => {
				const [summary] = toBatchSummaries([
					{ ...detailedBatch[0], startTimeUtc: '2026-11-24T10:00:00.000Z', endTimeUtc: '2026-11-24T10:00:05.000Z' } as any,
				]);
				expect(summary).toEqual({ url: 'https://a.example.com/', success: true, total: 2, blocked: 1, bypassed: 1, bypassRate: 50 });
			});

			it('should keep a target with no bypasses as a run with no results', () => {
				const doc = writeBatchSarif([
					{
						url: 'https://safe.example.com/', success: true, total: 1, blocked: 1, bypassed: 0, bypassRate: 0,
						results: [{ status: 403, method: 'GET', payload: 'blocked', responseTime: 10, category: 'XSS' }],
					},
				]);
				expect(doc.runs).toHaveLength(1);
				expect(doc.runs[0].results).toEqual([]);
			});
		});

		it('should keep per-target payload details out of batch JSON and HTML reports', () => {
			const withDetails = [
				{ ...batchResults[0], results: [{ status: 200, method: 'GET', payload: 'secret-detail-payload', responseTime: 1, category: 'XSS' }] },
			];
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('batch.json', 'json', 'batch', 'targets.txt', withDetails);
			writeReport('batch.html', 'html', 'batch', 'targets.txt', withDetails);
			const [jsonCall, htmlCall] = vi.mocked(fs.writeFileSync).mock.calls;
			expect(JSON.parse(jsonCall[1] as string)).toEqual([batchResults[0]]);
			expect(htmlCall[1]).not.toContain('secret-detail-payload');
		});

		it('should write Markdown check reports with stats and bypassed table', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.md', 'markdown', 'check', 'https://example.com', [
				...checkResults,
				{ status: 500, method: 'GET', payload: 'err-test', responseTime: 50, category: 'SQL Injection' },
				{ status: 301, method: 'GET', payload: 'redir-test', responseTime: 50, category: 'Open Redirect' },
			]);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('# 🛡️ WAF Checker Audit Report'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('Attack Category Breakdown'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('Bypassed Payloads'), 'utf8');
		});

		it('should write Markdown check reports when no bypasses detected and score is 100%', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			const secureResults = [
				{ status: 403, method: 'GET', payload: 'test-sql', responseTime: 100, category: 'SQL Injection', wafType: 'Cloudflare' },
			];
			writeReport('report.md', 'md', 'check', 'https://example.com', secureResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('Excellent: 100% Protection'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('No Bypasses Detected'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('Detected WAF:** `Cloudflare`'), 'utf8');
		});

		it('should write Markdown check reports with moderate and poor scores', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			const poorResults = [
				{ status: 200, method: 'GET', payload: 'test<script>&\'"|', responseTime: 100, category: 'XSS' },
				{ status: 200, method: 'GET', payload: 'test2', responseTime: 100, category: 'XSS' },
				{ status: 200, method: 'GET', payload: 'test3', responseTime: 100, category: 'XSS' },
				{ status: 403, method: 'GET', payload: 'test4', responseTime: 100, category: 'XSS' },
			];
			writeReport('report.md', 'markdown', 'check', undefined, poorResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('Poor Protection / High Risk'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('&lt;script&gt;&amp;&#39;&quot;&#124;'), 'utf8');

			const moderateResults = [
				{ status: 403, method: 'GET', payload: 'test1', responseTime: 100, category: 'XSS' },
				{ status: 403, method: 'GET', payload: 'test2', responseTime: 100, category: 'XSS' },
				{ status: 403, method: 'GET', payload: 'test3', responseTime: 100, category: 'XSS' },
				{ status: 200, method: 'GET', payload: 'test4', responseTime: 100, category: 'XSS' },
			];
			writeReport('report.md', 'markdown', 'check', 'https://target.com', moderateResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.md', expect.stringContaining('Moderate Protection'), 'utf8');
		});

		it('should write Markdown batch reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('batch.md', 'markdown', 'batch', 'targets.txt', [
				...batchResults,
				{ url: 'https://secure.com', success: true, total: 5, blocked: 5, bypassed: 0, bypassRate: 0 }
			]);
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.md', expect.stringContaining('# 🛡️ WAF Batch Audit Report'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.md', expect.stringContaining('Scanned Targets:** `3`'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.md', expect.stringContaining('🔴 Failed'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.md', expect.stringContaining('⚠️ Bypasses'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.md', expect.stringContaining('🟢 Secure'), 'utf8');
		});

		it('should write CSV check reports with headers', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.csv', 'csv', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.csv', expect.stringContaining('Category,Method,Status'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.csv', expect.stringContaining('SQL Injection,GET,403'), 'utf8');
		});

		it('should include WAF detection columns in CSV check reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			const enriched = [
				{
					status: 200,
					method: 'GET',
					payload: 'test-xss',
					originalPayload: '<script>',
					responseTime: 120,
					category: 'XSS',
					wafType: 'Cloudflare',
					bypassTechnique: 'Double URL encoding',
					verdict: 'exposed',
				},
			];
			writeReport('report.csv', 'csv', 'check', 'https://example.com', enriched);
			const written = vi.mocked(fs.writeFileSync).mock.calls[0][1] as string;
			expect(written).toContain('WAF Type,Bypass Technique,Verdict');
			expect(written).toContain('Original Payload');
			expect(written).toContain('Cloudflare,Double URL encoding,exposed');
		});

		it('should write HTML check reports with styling and content', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.html', 'html', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.html', expect.stringContaining('<!DOCTYPE html>'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.html', expect.stringContaining('WAF Audit Report'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.html', expect.stringContaining('test-sql'), 'utf8');
		});

		it('should write CSV batch reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('batch.csv', 'csv', 'batch', 'targets.txt', batchResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.csv', expect.stringContaining('Target URL,Success,Total Tests'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.csv', expect.stringContaining('https://example.com,Yes,10'), 'utf8');
		});

		it('should write HTML batch reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('batch.html', 'html', 'batch', 'targets.txt', batchResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.html', expect.stringContaining('WAF Batch Audit Report'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.html', expect.stringContaining('Connection failure'), 'utf8');
		});

		it('should create directories if they do not exist', () => {
			vi.mocked(fs.existsSync).mockReturnValue(false);
			vi.mocked(fs.mkdirSync).mockClear();

			writeReport('new-dir/report.json', 'json', 'check', 'https://example.com', checkResults);

			expect(fs.mkdirSync).toHaveBeenCalledWith('new-dir', { recursive: true });
		});

		it('should escape target URL in HTML report to prevent HTML injection/XSS', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			const maliciousUrl = 'https://example.com/</title><script>alert(1)</script>';
			writeReport('report.html', 'html', 'check', maliciousUrl, checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.html',
				expect.not.stringContaining(maliciousUrl),
				'utf8'
			);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.html',
				expect.stringContaining('https://example.com/&lt;/title&gt;&lt;script&gt;alert(1)&lt;/script&gt;'),
				'utf8'
			);
		});

		it('should escape CSV values containing carriage returns', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			const carriageReturnResults = [
				{ status: 200, method: 'GET', payload: 'test\rvalue', responseTime: 100, category: 'SQL Injection' }
			];
			writeReport('report.csv', 'csv', 'check', 'https://example.com', carriageReturnResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.csv',
				expect.stringContaining('"test\rvalue"'),
				'utf8'
			);
		});

		it('should include reverseEngineering data in JSON, Markdown, and HTML reports', () => {
			const mockReverseReport = {
				targetUrl: 'https://example.com',
				crsRules: [
					{
						ruleId: '942100',
						name: 'SQL Injection - Boolean Based',
						category: 'SQLi',
						paranoiaLevel: 1 as const,
						anomalyScore: 5,
						status: 'active' as const,
						probePayload: "' OR '1'='1",
						statusCode: 403,
						responseTime: 40,
					},
					{
						ruleId: '941100',
						name: 'XSS Filter - Script Tag',
						category: 'XSS',
						paranoiaLevel: 1 as const,
						anomalyScore: 5,
						status: 'disabled' as const,
						probePayload: '<script>alert(1)</script>',
						statusCode: 200,
						responseTime: 35,
					},
				],
				crsSummary: {
					total: 2,
					active: 1,
					disabled: 1,
					bypassed: 0,
					activePercent: 50,
				},
				bodyLimit: {
					limitBytes: 16384,
					limitFormatted: '16 KB',
					confidence: 95,
					detected: true,
				},
				anomalyScore: {
					mode: 'anomaly_scoring' as const,
					detectedThreshold: 5,
					confidence: 95,
				},
				rateLimit: {
					detected: true,
					thresholdRps: 20,
					retryAfterSeconds: 60,
					safeTestedMaxRps: 20,
				},
				timestamp: new Date().toISOString(),
			};

			// 1. JSON Report
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.json', 'json', 'check', 'https://example.com', checkResults, mockReverseReport as any);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.json',
				expect.stringContaining('"reverseEngineering"'),
				'utf8'
			);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.json',
				expect.stringContaining('16 KB'),
				'utf8'
			);

			// 2. Markdown Report
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.md', 'markdown', 'check', 'https://example.com', checkResults, mockReverseReport as any);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.md',
				expect.stringContaining('WAF Reverse Engineering & OWASP Core Rule Set (CRS)'),
				'utf8'
			);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.md',
				expect.stringContaining('16 KB'),
				'utf8'
			);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.md',
				expect.stringContaining('942100'),
				'utf8'
			);

			// 3. HTML Report
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.html', 'html', 'check', 'https://example.com', checkResults, mockReverseReport as any);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.html',
				expect.stringContaining('WAF Reverse Engineering & Core Rule Set (CRS)'),
				'utf8'
			);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.html',
				expect.stringContaining('16 KB'),
				'utf8'
			);
			expect(fs.writeFileSync).toHaveBeenCalledWith(
				'report.html',
				expect.stringContaining('942100'),
				'utf8'
			);
		});
	});
});
