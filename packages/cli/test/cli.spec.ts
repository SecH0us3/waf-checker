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
		})
	};
});

vi.mock('../src/report', () => {
	return {
		writeReport: vi.fn(),
		deduceFormat: vi.fn((path: string) => {
			if (path.endsWith('.json')) return 'json';
			if (path.endsWith('.csv')) return 'csv';
			return 'html';
		})
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

			expect(writeReport).toHaveBeenCalledWith('report.html', 'html', 'check', 'https://example.com', expect.any(Array));
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

		it('should exit with 0 if no targets bypassed and --fail-on-bypass is specified', async () => {
			await expect(
				program.parseAsync(['node', 'index.js', 'batch', mockFile, '--fail-on-bypass'])
			).resolves.toBeDefined();

			expect(exitCode).toBeNull();
		});
	});
});
