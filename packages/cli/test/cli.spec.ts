import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// Mock the core package first
vi.mock('@waf-checker/core', async () => {
	const actual = await vi.importActual<typeof import('@waf-checker/core')>('@waf-checker/core');
	return {
		...actual,
		isValidTargetUrl: vi.fn((url: string) => {
			return !url.includes('restricted') && !url.includes('invalid') && url.startsWith('http');
		}),
		handleApiCheckFiltered: vi.fn().mockResolvedValue([
			{ status: 403, method: 'GET', payload: 'test', responseTime: 120, category: 'SQL Injection' }
		]),
		WAFDetector: {
			activeDetection: vi.fn().mockResolvedValue({
				detected: true,
				wafType: 'Cloudflare',
				confidence: 85,
				evidence: ['Mock header evidence'],
				suggestedBypassTechniques: ['Mock bypass technique']
			}),
			getSupportedWafs: () => ['Cloudflare', 'AWS WAF', 'Imperva']
		}
	};
});

let mockFileContent = '';

vi.mock('fs', async () => {
	const actual = await vi.importActual<typeof import('fs')>('fs');
	return {
		...actual,
		existsSync: vi.fn((path: string) => {
			if (path === 'targets.txt') return true;
			return actual.existsSync(path);
		}),
		readFileSync: vi.fn((path: any, options?: any) => {
			if (path === 'targets.txt') {
				return mockFileContent;
			}
			return actual.readFileSync(path, options);
		}),
		writeFileSync: vi.fn(),
		mkdirSync: vi.fn(),
	};
});

vi.mock('../src/report', async () => {
	const actual = await vi.importActual<typeof import('../src/report')>('../src/report');
	return {
		...actual,
		writeReport: vi.fn(),
	};
});

import * as fs from 'fs';
import { program } from '../src/index';
import * as core from '@waf-checker/core';
import { writeReport } from '../src/report';

describe('CLI Argument Processing', () => {
	let exitCode: number | null = null;
	let consoleErrorSpy: any;
	let consoleLogSpy: any;
	let consoleWarnSpy: any;

	beforeEach(() => {
		exitCode = null;
		vi.spyOn(process, 'exit').mockImplementation((code?: number) => {
			exitCode = code ?? 0;
			throw new Error(`process.exit(${exitCode})`);
		});

		consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

		// Reset commander option values to their defaults
		program.commands.forEach((cmd: any) => {
			const defaults: any = {};
			cmd.options.forEach((opt: any) => {
				defaults[opt.attributeName()] = opt.defaultValue;
			});
			cmd._optionValues = defaults;
		});
		const programDefaults: any = {};
		program.options.forEach((opt: any) => {
			programDefaults[opt.attributeName()] = opt.defaultValue;
		});
		(program as any)._optionValues = programDefaults;

		// Reset mocks
		vi.mocked(core.isValidTargetUrl).mockClear();
		vi.mocked(core.handleApiCheckFiltered).mockClear();
		vi.mocked(core.WAFDetector.activeDetection).mockClear();
		vi.mocked(writeReport).mockClear();
	});

	afterEach(() => {
		vi.clearAllMocks();
	});

	it('should register detect, check, and batch commands', () => {
		const commandNames = program.commands.map(cmd => cmd.name());
		expect(commandNames).toContain('detect');
		expect(commandNames).toContain('check');
		expect(commandNames).toContain('batch');
	});

	describe('detect command', () => {
		it('should succeed with valid URL and call activeDetection', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'detect', 'https://example.com'])
			).resolves.toBeDefined();

			expect(core.isValidTargetUrl).toHaveBeenCalledWith('https://example.com');
			expect(core.WAFDetector.activeDetection).toHaveBeenCalledWith('https://example.com', expect.any(Object));
			expect(exitCode).toBeNull();
		});

		it('should exit with 1 for invalid URL', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'detect', 'http://restricted.local'])
			).rejects.toThrow('process.exit(1)');

			expect(core.isValidTargetUrl).toHaveBeenCalledWith('http://restricted.local');
			expect(core.WAFDetector.activeDetection).not.toHaveBeenCalled();
			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid target URL'));
		});
	});

	describe('check command', () => {
		it('should parse defaults correctly', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com'])
			).resolves.toBeDefined();

			expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
				'https://example.com',
				0,
				['GET'],
				undefined,
				undefined,
				false,
				undefined,
				false,
				false,
				false,
				false,
				false,
				false,
				undefined,
				undefined,
				expect.any(Object)
			);
			expect(exitCode).toBeNull();
		});

		it('should parse custom methods, categories, and detected WAF', async () => {
			await expect(
				program.parseAsync([
					'node', 'index.js', 'check', 'https://example.com',
					'-m', 'GET,POST',
					'-c', 'SQL Injection,XSS',
					'--detected-waf', 'Cloudflare',
					'--follow-redirects',
					'--enhanced',
					'--advanced',
					'--encoding-variations',
					'--http-manipulation'
				])
			).resolves.toBeDefined();

			expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
				'https://example.com',
				0,
				['GET', 'POST'],
				['SQL Injection', 'XSS'],
				undefined,
				true,
				undefined,
				false,
				false,
				true,
				true,
				false,
				true,
				'Cloudflare',
				{
					enableParameterPollution: true,
					enableVerbTampering: true,
					enableContentTypeConfusion: true,
					enableInspectionLimitPadding: false,
					paddingSize: '16kb',
				},
				expect.any(Object)
			);
		});

		it('should parse --padding option correctly', async () => {
			await expect(
				program.parseAsync([
					'node', 'index.js', 'check', 'https://example.com',
					'--padding', '64kb'
				])
			).resolves.toBeDefined();

			expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
				'https://example.com',
				0,
				['GET'],
				undefined,
				undefined,
				false,
				undefined,
				false,
				false,
				false,
				false,
				false,
				false,
				undefined,
				{
					enableParameterPollution: false,
					enableVerbTampering: false,
					enableContentTypeConfusion: false,
					enableInspectionLimitPadding: true,
					paddingSize: '64kb',
				},
				expect.any(Object)
			);
		});

		it('should disable color when --no-color flag is passed', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--no-color'])
			).resolves.toBeDefined();

			expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
				expect.any(String),
				expect.any(Number),
				expect.any(Array),
				undefined,
				undefined,
				expect.any(Boolean),
				undefined,
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				undefined,
				undefined,
				expect.objectContaining({ color: false })
			);
		});

		it('should disable color when process.env.NO_COLOR is set', async () => {
			const originalNoColor = process.env.NO_COLOR;
			process.env.NO_COLOR = '1';
			try {
				await expect(
					program.parseAsync(['node', 'index.js', 'check', 'https://example.com'])
				).resolves.toBeDefined();

				expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
					expect.any(String),
					expect.any(Number),
					expect.any(Array),
					undefined,
					undefined,
					expect.any(Boolean),
					undefined,
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					undefined,
					undefined,
					expect.objectContaining({ color: false })
				);
			} finally {
				if (originalNoColor === undefined) {
					delete process.env.NO_COLOR;
				} else {
					process.env.NO_COLOR = originalNoColor;
				}
			}
		});

		it('should disable color when stdout is not a TTY', async () => {
			const originalIsTTY = process.stdout.isTTY;
			process.stdout.isTTY = false;
			try {
				await expect(
					program.parseAsync(['node', 'index.js', 'check', 'https://example.com'])
				).resolves.toBeDefined();

				expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
					expect.any(String),
					expect.any(Number),
					expect.any(Array),
					undefined,
					undefined,
					expect.any(Boolean),
					undefined,
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					expect.any(Boolean),
					undefined,
					undefined,
					expect.objectContaining({ color: false })
				);
			} finally {
				process.stdout.isTTY = originalIsTTY;
			}
		});

		it('should pass custom fetch when --proxy is set', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--proxy', 'http://127.0.0.1:8080'])
			).resolves.toBeDefined();

			expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
				expect.any(String),
				expect.any(Number),
				expect.any(Array),
				undefined,
				undefined,
				expect.any(Boolean),
				undefined,
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				undefined,
				undefined,
				expect.objectContaining({
					fetch: expect.any(Function)
				})
			);
		});

		it('should load custom headers from file when path exists', async () => {
			mockFileContent = 'X-Header: test\nCookie: name=value';
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--custom-headers', 'targets.txt'])
			).resolves.toBeDefined();

			expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
				expect.any(String),
				expect.any(Number),
				expect.any(Array),
				undefined,
				undefined,
				expect.any(Boolean),
				'X-Header: test\nCookie: name=value',
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				undefined,
				undefined,
				expect.any(Object)
			);
		});

		it('should block SSRF on check target and exit with 1', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'http://invalid.local'])
			).rejects.toThrow('process.exit(1)');

			expect(core.handleApiCheckFiltered).not.toHaveBeenCalled();
			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Invalid target URL'));
		});

		it('should write report when --output is specified', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--output', 'report.html'])
			).resolves.toBeDefined();

			expect(writeReport).toHaveBeenCalledWith('report.html', 'html', 'check', 'https://example.com', expect.any(Array), undefined, undefined);
		});

		it('should write sarif report when .sarif extension is specified', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--output', 'report.sarif'])
			).resolves.toBeDefined();

			expect(writeReport).toHaveBeenCalledWith('report.sarif', 'sarif', 'check', 'https://example.com', expect.any(Array), undefined, undefined);
		});

		it('should write multiple reports simultaneously when flags are specified', async () => {
			await expect(
				program.parseAsync([
					'node', 'index.js', 'check', 'https://example.com',
					'--sarif-output', 'results.sarif',
					'--markdown-output', 'summary.md',
					'--html-output', 'report.html',
				])
			).resolves.toBeDefined();

			expect(writeReport).toHaveBeenCalledWith('results.sarif', 'sarif', 'check', 'https://example.com', expect.any(Array), undefined, undefined);
			expect(writeReport).toHaveBeenCalledWith('summary.md', 'markdown', 'check', 'https://example.com', expect.any(Array), undefined, undefined);
			expect(writeReport).toHaveBeenCalledWith('report.html', 'html', 'check', 'https://example.com', expect.any(Array), undefined, undefined);
		});

		it('should execute reverse engineering audit when --reverse flag is set', async () => {
			const mockReverseReport = {
				targetUrl: 'https://example.com',
				crsRules: [],
				crsSummary: { total: 10, active: 8, disabled: 2, bypassed: 0, activePercent: 80 },
				bodyLimit: { detected: true, limitBytes: 16384, limitFormatted: '16 KB', confidence: 95 },
				anomalyScore: { mode: 'anomaly_scoring' as const, detectedThreshold: 5, confidence: 95 },
				rateLimit: { detected: false, thresholdRps: null, retryAfterSeconds: null, safeTestedMaxRps: 30 },
				timestamp: new Date().toISOString(),
			};
			vi.spyOn(core, 'runReverseEngineeringAudit').mockResolvedValueOnce(mockReverseReport);

			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--reverse', '--output', 'report.json'])
			).resolves.toBeDefined();

			expect(core.runReverseEngineeringAudit).toHaveBeenCalledWith('https://example.com', expect.any(Object));
			expect(writeReport).toHaveBeenCalledWith('report.json', 'json', 'check', 'https://example.com', expect.any(Array), mockReverseReport, undefined);
		});

		it('should pass quiet option when --quiet is set', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--quiet'])
			).resolves.toBeDefined();

			expect(core.handleApiCheckFiltered).toHaveBeenCalledWith(
				expect.any(String),
				expect.any(Number),
				expect.any(Array),
				undefined,
				undefined,
				expect.any(Boolean),
				undefined,
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				expect.any(Boolean),
				undefined,
				undefined,
				expect.objectContaining({
					quiet: true,
				})
			);
		});

		it('should exit with 1 when protection score is below --threshold', async () => {
			// 1 blocked, 1 bypassed -> 50% protection
			vi.mocked(core.handleApiCheckFiltered).mockResolvedValueOnce([
				{ status: 403, method: 'GET', payload: 'test', responseTime: 50, category: 'SQLi' },
				{ status: 200, method: 'GET', payload: 'bypass', responseTime: 80, category: 'XSS' },
			]);

			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--threshold', '90'])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('CI/CD Threshold Failed: Protection score 50% is below required threshold of 90%'));
		});

		it('should pass when protection score is above or equal to --threshold', async () => {
			// 2 blocked -> 100% protection
			vi.mocked(core.handleApiCheckFiltered).mockResolvedValueOnce([
				{ status: 403, method: 'GET', payload: 'test', responseTime: 50, category: 'SQLi' },
				{ status: 403, method: 'GET', payload: 'test2', responseTime: 40, category: 'XSS' },
			]);

			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--threshold', '90'])
			).resolves.toBeDefined();

			expect(exitCode).toBeNull();
		});

		it('should exit with 1 when invalid --threshold is provided', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--threshold', 'invalid'])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('Error: --threshold must be a valid number between 0 and 100'));
		});

		it('should exit with 1 on bypass when --fail-on-bypass is specified', async () => {
			vi.mocked(core.handleApiCheckFiltered).mockResolvedValueOnce([
				{ status: 200, method: 'GET', payload: 'bypass', responseTime: 80, category: 'SQL Injection' }
			]);

			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--fail-on-bypass'])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('CI/CD Check Failed'));
		});

		it('should exit with 0 if no bypasses and --fail-on-bypass is specified', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'check', 'https://example.com', '--fail-on-bypass'])
			).resolves.toBeDefined();

			expect(exitCode).toBeNull();
		});
	});

	describe('batch command', () => {
		let mockFile = 'targets.txt';

		beforeEach(() => {
			mockFileContent = 'https://example.com\nhttp://restricted.local\n# comment\nhttps://google.com';
		});

		it('should run batch and skip invalid targets', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'batch', mockFile, '--concurrency', '2'])
			).resolves.toBeDefined();

			expect(fs.existsSync).toHaveBeenCalledWith(mockFile);
			expect(fs.readFileSync).toHaveBeenCalledWith(mockFile, 'utf8');

			// One call for check, one call for batch target check
			expect(core.isValidTargetUrl).toHaveBeenCalledWith('https://example.com');
			expect(core.isValidTargetUrl).toHaveBeenCalledWith('http://restricted.local');
			expect(core.isValidTargetUrl).toHaveBeenCalledWith('https://google.com');

			// Only two valid URLs should be scanned
			expect(core.handleApiCheckFiltered).toHaveBeenCalledTimes(2);
			expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Skipping invalid or restricted target URL'));
			expect(exitCode).toBeNull();
		});

		it('should fail if no valid URLs found in file', async () => {
			mockFileContent = 'http://invalid.local\n# comment';

			await expect(
				program.parseAsync(['node', 'index.js', 'batch', mockFile])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('No valid URLs found in file'));
		});

		it('should write batch report when --output is specified', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'batch', mockFile, '--output', 'batch-report.html'])
			).resolves.toBeDefined();

			expect(writeReport).toHaveBeenCalledWith('batch-report.html', 'html', 'batch', mockFile, expect.any(Array));
		});

		it('should exit with 1 on bypass when --fail-on-bypass is specified', async () => {
			// Mock so first target returns blocked, second returns bypass
			vi.mocked(core.handleApiCheckFiltered)
				.mockResolvedValueOnce([
					{ status: 403, method: 'GET', payload: 'test', responseTime: 120, category: 'SQL Injection' }
				])
				.mockResolvedValueOnce([
					{ status: 200, method: 'GET', payload: 'bypass', responseTime: 80, category: 'SQL Injection' }
				]);

			await expect(
				program.parseAsync(['node', 'index.js', 'batch', mockFile, '--fail-on-bypass'])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('CI/CD Check Failed'));
		});

		it('should exit with 1 on batch threshold failure', async () => {
			// First target: 1 blocked, 0 bypassed (100%)
			// Second target: 0 blocked, 1 bypassed (0%)
			// Total: 1 blocked / 2 total = 50%
			vi.mocked(core.handleApiCheckFiltered)
				.mockResolvedValueOnce([
					{ status: 403, method: 'GET', payload: 'test', responseTime: 120, category: 'SQL Injection' }
				])
				.mockResolvedValueOnce([
					{ status: 200, method: 'GET', payload: 'bypass', responseTime: 80, category: 'SQL Injection' }
				]);

			await expect(
				program.parseAsync(['node', 'index.js', 'batch', mockFile, '--threshold', '80'])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('CI/CD Threshold Failed: Overall batch protection score 50% is below required threshold of 80%'));
		});

		it('should write batch multiple reports when specific flags are set', async () => {
			await expect(
				program.parseAsync([
					'node', 'index.js', 'batch', mockFile,
					'--markdown-output', 'batch-summary.md',
					'--html-output', 'batch-report.html',
				])
			).resolves.toBeDefined();

			expect(writeReport).toHaveBeenCalledWith('batch-summary.md', 'markdown', 'batch', mockFile, expect.any(Array));
			expect(writeReport).toHaveBeenCalledWith('batch-report.html', 'html', 'batch', mockFile, expect.any(Array));
		});

		it('should fail when targets file does not exist', async () => {
			vi.mocked(fs.existsSync).mockReturnValueOnce(false);

			await expect(
				program.parseAsync(['node', 'index.js', 'batch', 'non-existent-file.txt'])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('does not exist'));
		});

		it('should exit with 0 if no targets bypassed and --fail-on-bypass is specified', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'batch', mockFile, '--fail-on-bypass'])
			).resolves.toBeDefined();

			expect(exitCode).toBeNull();
		});
	});

	describe('patch command and virtual patching in check', () => {
		it('should generate virtual patches during check when --patch is specified', async () => {
			vi.spyOn(core, 'handleApiCheckFiltered').mockResolvedValueOnce([
				{
					category: 'SQL Injection',
					method: 'GET',
					payload: "' UNION SELECT 1",
					status: 200,
					responseTime: 50,
				},
			]);

			await expect(
				program.parseAsync([
					'node', 'index.js', 'check', 'https://example.com',
					'--patch', 'cloudflare',
					'--patch-output', 'cloudflare-patch.tf',
				])
			).resolves.toBeDefined();

			expect(fs.writeFileSync).toHaveBeenCalledWith(
				expect.stringContaining('cloudflare-patch.tf'),
				expect.stringContaining('cloudflare_ruleset'),
				'utf8'
			);
		});

		it('should fail patch command when input file does not exist', async () => {
			vi.mocked(fs.existsSync).mockReturnValueOnce(false);

			await expect(
				program.parseAsync(['node', 'index.js', 'patch', 'non-existent-report.json'])
			).rejects.toThrow('process.exit(1)');

			expect(exitCode).toBe(1);
			expect(consoleErrorSpy).toHaveBeenCalledWith(expect.stringContaining('does not exist'));
		});

		it('should generate patches from saved report file and output to terminal', async () => {
			vi.mocked(fs.existsSync).mockReturnValueOnce(true);
			vi.mocked(fs.readFileSync).mockReturnValueOnce(
				JSON.stringify({
					targetUrl: 'https://example.com/api',
					results: [
						{
							category: 'SQL Injection',
							method: 'GET',
							payload: "' UNION SELECT 1",
							status: 200,
							responseTime: 50,
						},
						{
							category: 'XSS',
							method: 'GET',
							payload: '<script>alert(1)</script>',
							status: 200,
							responseTime: 40,
						},
					],
				})
			);

			await expect(
				program.parseAsync(['node', 'index.js', 'patch', 'report.json', '--waf', 'aws'])
			).resolves.toBeDefined();

			expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('AWS'));
			expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('Detected Bypasses to Remediate: 2'));
		});

		it('should output json format when --json flag is passed to patch command', async () => {
			vi.mocked(fs.existsSync).mockReturnValueOnce(true);
			vi.mocked(fs.readFileSync).mockReturnValueOnce(
				JSON.stringify([
					{
						category: 'Path Traversal',
						method: 'GET',
						payload: '../../etc/passwd',
						status: 200,
						responseTime: 40,
					},
				])
			);

			await expect(
				program.parseAsync(['node', 'index.js', 'patch', 'report.json', '--json'])
			).resolves.toBeDefined();

			expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('"totalBypasses": 1'));
		});

		it('should write patches to specified output file', async () => {
			vi.mocked(fs.existsSync).mockReturnValueOnce(true);
			vi.mocked(fs.readFileSync).mockReturnValueOnce(
				JSON.stringify([
					{
						category: 'SQL Injection',
						method: 'GET',
						payload: "' OR 1=1--",
						status: 200,
						responseTime: 40,
					},
				])
			);

			await expect(
				program.parseAsync([
					'node', 'index.js', 'patch', 'report.json',
					'--waf', 'modsecurity',
					'--output', 'modsec-rules.conf',
				])
			).resolves.toBeDefined();

			expect(fs.writeFileSync).toHaveBeenCalledWith(
				expect.stringContaining('modsec-rules.conf'),
				expect.stringContaining('SecRule'),
				'utf8'
			);
		});

		it('should handle reports with 0 bypasses gracefully in patch command', async () => {
			vi.mocked(fs.existsSync).mockReturnValueOnce(true);
			vi.mocked(fs.readFileSync).mockReturnValueOnce(
				JSON.stringify([
					{
						category: 'SQL Injection',
						method: 'GET',
						payload: "' OR 1=1--",
						status: 403,
						responseTime: 40,
					},
				])
			);

			await expect(
				program.parseAsync(['node', 'index.js', 'patch', 'report.json'])
			).resolves.toBeDefined();

			expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('No bypasses detected'));
		});

		it('should generate patches for 404 responses when --include-misses is specified in patch command', async () => {
			vi.mocked(fs.existsSync).mockReturnValueOnce(true);
			vi.mocked(fs.readFileSync).mockReturnValueOnce(
				JSON.stringify([
					{
						category: 'Sensitive Files',
						method: 'GET',
						payload: '/.git/config',
						status: 404,
						responseTime: 40,
					},
				])
			);

			await expect(
				program.parseAsync([
					'node',
					'index.js',
					'patch',
					'report.json',
					'--include-misses',
					'--waf',
					'cloudflare',
				])
			).resolves.toBeDefined();

			expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('CLOUDFLARE'));
		});
	});
});
