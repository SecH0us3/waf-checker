import { describe, it, expect, vi } from 'vitest';
import {
	runReverseEngineeringAudit,
	detectBodyInspectionLimit,
	detectAnomalyScoringMode,
	probeRateLimit,
	OWASP_CRS_RULES,
} from '../src/reverse-engineering';
import { classifyProbe } from '../src/reverse-engineering/probe-outcome';

describe('WAF Reverse Engineering & CRS Rule Mapping', () => {
	describe('OWASP CRS Database', () => {
		it('should contain comprehensive OWASP CRS v3/v4 rules with required metadata', () => {
			expect(OWASP_CRS_RULES.length).toBeGreaterThanOrEqual(20);
			for (const rule of OWASP_CRS_RULES) {
				expect(rule.ruleId).toMatch(/^9\d{5}$/);
				expect(rule.name).toBeTruthy();
				expect(rule.category).toBeTruthy();
				expect([1, 2, 3, 4]).toContain(rule.paranoiaLevel);
				expect(rule.anomalyScore).toBeGreaterThanOrEqual(1);
				expect(rule.probePayload).toBeTruthy();
			}
		});
	});

	describe('SSRF Protection in runReverseEngineeringAudit', () => {
		it('should reject invalid or private IP target URLs', async () => {
			await expect(runReverseEngineeringAudit('http://127.0.0.1/api')).rejects.toThrow(
				/Invalid URL or restricted IP/,
			);
			await expect(runReverseEngineeringAudit('http://169.254.169.254/latest')).rejects.toThrow(
				/Invalid URL or restricted IP/,
			);
			await expect(runReverseEngineeringAudit('not-a-valid-url')).rejects.toThrow(
				/Invalid URL or restricted IP/,
			);
		});
	});

	describe('Body Inspection Limit Detector (Binary Search)', () => {
		it('should return N/A if baseline attack payload is not blocked', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 200,
				text: async () => 'OK',
				headers: new Headers(),
			});

			const result = await detectBodyInspectionLimit('https://example.com/api', {
				fetch: mockFetch as any,
			});

			expect(result.detected).toBe(false);
			expect(result.limitFormatted).toContain('Baseline Attack Not Blocked');
			expect(result.limitBytes).toBeNull();
		});

		it('should report strict inspection if all probe sizes up to 128KB are blocked', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 403,
				text: async () => 'Blocked',
				headers: new Headers(),
			});

			const result = await detectBodyInspectionLimit('https://example.com/api', {
				fetch: mockFetch as any,
			});

			expect(result.detected).toBe(false);
			expect(result.limitFormatted).toContain('> 128 KB');
			expect(result.limitBytes).toBeNull();
		});

		it('should detect exact inspection limit boundary using binary search', async () => {
			const mockLimit = 16384; // 16 KB boundary
			const mockFetch = vi.fn().mockImplementation(async (url: string, init?: any) => {
				const bodyStr = init?.body ? String(init.body) : '';
				if (bodyStr.length > mockLimit) {
					// WAF buffer bypass: payload is beyond inspection window
					return {
						status: 200,
						text: async () => 'OK',
						headers: new Headers(),
					};
				}
				// Within inspection limit: blocked
				return {
					status: 403,
					text: async () => 'Forbidden',
					headers: new Headers(),
				};
			});

			const result = await detectBodyInspectionLimit('https://example.com/api', {
				fetch: mockFetch as any,
			});

			expect(result.detected).toBe(true);
			expect(result.limitBytes).toBeGreaterThanOrEqual(15000);
			expect(result.limitBytes).toBeLessThanOrEqual(18000);
			expect(result.confidence).toBeGreaterThanOrEqual(90);
			expect(result.limitFormatted).toBeTruthy();
		});
	});

	describe('Anomaly Scoring Mode Detector', () => {
		it('should detect traditional_regex mode if individual notice/warning rules block', async () => {
			const mockFetch = vi.fn().mockImplementation(async (url: string) => {
				const decoded = decodeURIComponent(url);
				if (decoded.includes('p1=alpha')) {
					return { status: 403, text: async () => 'Blocked', headers: new Headers() };
				}
				return { status: 200, text: async () => 'OK', headers: new Headers() };
			});

			const result = await detectAnomalyScoringMode('https://example.com/api', {
				fetch: mockFetch as any,
			});

			expect(result.mode).toBe('traditional_regex');
			expect(result.confidence).toBeGreaterThanOrEqual(80);
			expect(result.details).toContain('isolated low-score');
		});

		it('should detect anomaly_scoring mode with threshold 5 when combined signals trigger 403', async () => {
			const mockFetch = vi.fn().mockImplementation(async (url: string) => {
				const decoded = decodeURIComponent(url);
				const hasSignal1 = decoded.includes('p1=alpha');
				const hasSignal2 = decoded.includes('p2=test');

				// Combined signals trigger threshold 5
				if (hasSignal1 && hasSignal2) {
					return { status: 403, text: async () => 'Blocked by Anomaly Scoring', headers: new Headers() };
				}
				// Individual signals pass
				return { status: 200, text: async () => 'OK', headers: new Headers() };
			});

			const result = await detectAnomalyScoringMode('https://example.com/api', {
				fetch: mockFetch as any,
			});

			expect(result.mode).toBe('anomaly_scoring');
			expect(result.detectedThreshold).toBe(5);
			expect(result.confidence).toBeGreaterThanOrEqual(90);
		});

		it('should detect anomaly_scoring mode with threshold 10 when only high composite triggers 403', async () => {
			const mockFetch = vi.fn().mockImplementation(async (url: string) => {
				const decoded = decodeURIComponent(url);
				const hasSignal1 = decoded.includes('p1=alpha');
				const hasSignal2 = decoded.includes('p2=test');
				const hasCritical = decoded.includes('extra=');

				if (hasSignal1 && hasSignal2 && hasCritical) {
					return { status: 403, text: async () => 'Blocked', headers: new Headers() };
				}
				return { status: 200, text: async () => 'OK', headers: new Headers() };
			});

			const result = await detectAnomalyScoringMode('https://example.com/api', {
				fetch: mockFetch as any,
			});

			expect(result.mode).toBe('anomaly_scoring');
			expect(result.detectedThreshold).toBe(10);
		});
	});

	describe('Safe Rate Limit Prober', () => {
		it('should stop immediately upon encountering HTTP 429 and parse Retry-After', async () => {
			let totalCalls = 0;
			const mockFetch = vi.fn().mockImplementation(async () => {
				totalCalls++;
				if (totalCalls > 5) {
					const headers = new Headers();
					headers.set('retry-after', '60');
					return { status: 429, text: async () => 'Too Many Requests', headers };
				}
				return { status: 200, text: async () => 'OK', headers: new Headers() };
			});

			const result = await probeRateLimit('https://example.com/api', {
				fetch: mockFetch as any,
				maxRpsProbe: 30,
			});

			expect(result.detected).toBe(true);
			expect(result.thresholdRps).toBe(10);
			expect(result.retryAfterSeconds).toBe(60);
			// Should have aborted before reaching step 20 & 30
			expect(totalCalls).toBeLessThan(25);
		});

		it('should report no rate limiting if all stages pass up to max RPS', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 200,
				text: async () => 'OK',
				headers: new Headers(),
			});

			const result = await probeRateLimit('https://example.com/api', {
				fetch: mockFetch as any,
				maxRpsProbe: 10,
			});

			expect(result.detected).toBe(false);
			expect(result.thresholdRps).toBeNull();
			expect(result.safeTestedMaxRps).toBe(10);
		});
	});

	describe('Full Reverse Engineering Orchestrator', () => {
		it('should run complete CRS audit and aggregate summary statistics', async () => {
			const mockFetch = vi.fn().mockImplementation(async (url: string, init?: any) => {
				const urlStr = String(url);
				// Block SQLi and XSS rules, allow others
				if (urlStr.includes('script') || urlStr.includes('UNION') || urlStr.includes('1%3D1') || urlStr.includes("1'='1")) {
					return { status: 403, text: async () => 'Forbidden', headers: new Headers() };
				}
				return { status: 200, text: async () => 'OK', headers: new Headers() };
			});

			const report = await runReverseEngineeringAudit('https://example.com/api', {
				fetch: mockFetch as any,
				skipRateLimit: true,
				skipBodyLimit: true,
				skipAnomalyScore: true,
			});

			expect(report.targetUrl).toBe('https://example.com/api');
			expect(report.crsRules.length).toBe(OWASP_CRS_RULES.length);
			expect(report.crsSummary.total).toBe(OWASP_CRS_RULES.length);
			expect(report.crsSummary.active).toBeGreaterThan(0);
			expect(report.crsSummary.disabled).toBeGreaterThan(0);
			expect(report.crsSummary.activePercent).toBeGreaterThanOrEqual(0);
			expect(report.crsSummary.activePercent).toBeLessThanOrEqual(100);

			const sqliRule = report.crsRules.find((r) => r.ruleId === '942190');
			expect(sqliRule).toBeDefined();
			expect(sqliRule?.status).toBe('active');
		});
	});
});

describe('Reverse engineering block detection (rate limiting, non-403 blocks)', () => {
	const reply = (status: number, body = 'OK') => new Response(body, { status });
	const isSqli = (init?: any) => String(init?.body ?? '').includes('%27');

	describe('classifyProbe', () => {
		const res = (status: number | string, bodyText = '') => ({ status, bodyText, is_redirect: false, responseTime: 1, error: null }) as any;

		it('counts 403 and 406 as blocked', () => {
			expect(classifyProbe(res(403))).toBe('blocked');
			expect(classifyProbe(res(406))).toBe('blocked');
		});

		it('counts a 2xx block page as blocked and a plain 2xx as passed', () => {
			expect(classifyProbe(res(200, '<h1>Request blocked</h1>'))).toBe('blocked');
			expect(classifyProbe(res(200, 'Welcome'))).toBe('passed');
		});

		it('treats rate limiting, errors and unsent requests as inconclusive', () => {
			expect(classifyProbe(res(429))).toBe('inconclusive');
			expect(classifyProbe(res('ERR'))).toBe('inconclusive');
			expect(classifyProbe(res('BLOCKED'))).toBe('inconclusive');
			expect(classifyProbe(undefined)).toBe('inconclusive');
		});
	});

	describe('detectBodyInspectionLimit', () => {
		it('does not report a limit when padded probes are rate limited', async () => {
			let calls = 0;
			const mockFetch = vi.fn().mockImplementation(async () => (calls++ === 0 ? reply(403, 'Forbidden') : reply(429, 'Too Many Requests')));

			const result = await detectBodyInspectionLimit('https://example.com/api', { fetch: mockFetch as any });

			expect(result.detected).toBe(false);
			expect(result.limitBytes).toBeNull();
			expect(result.limitFormatted).toMatch(/inconclusive/i);
		});

		it('does not report a limit when the binary search gets rate limited', async () => {
			// The coarse grid finds a bypass between 8 KB and 16 KB; every probe after
			// that (the binary search) is rate limited.
			let rateLimited = false;
			const mockFetch = vi.fn().mockImplementation(async (_url: string, init?: any) => {
				if (rateLimited) return reply(429);
				if (String(init?.body ?? '').length > 12000) {
					rateLimited = true;
					return reply(200);
				}
				return reply(403, 'Forbidden');
			});

			const result = await detectBodyInspectionLimit('https://example.com/api', { fetch: mockFetch as any });

			expect(result.detected).toBe(false);
			expect(result.limitFormatted).toMatch(/inconclusive/i);
		});

		it('finds the limit on a WAF that blocks with 406', async () => {
			const mockLimit = 16384;
			const mockFetch = vi.fn().mockImplementation(async (_url: string, init?: any) =>
				String(init?.body ?? '').length > mockLimit ? reply(200) : reply(406, 'Not Acceptable'),
			);

			const result = await detectBodyInspectionLimit('https://example.com/api', { fetch: mockFetch as any });

			expect(result.detected).toBe(true);
			expect(result.limitBytes).toBeGreaterThanOrEqual(15000);
			expect(result.limitBytes).toBeLessThanOrEqual(18000);
		});

		it('sends the baseline attack raw, in the same encoding as the padded probes', async () => {
			const mockFetch = vi.fn().mockImplementation(async () => reply(403, 'Forbidden'));

			await detectBodyInspectionLimit('https://example.com/api', { fetch: mockFetch as any });

			const baselineBody = String(mockFetch.mock.calls[0][1].body);
			const paddedBody = String(mockFetch.mock.calls[1][1].body);
			expect(baselineBody).toBe("attack=" + encodeURIComponent("' OR '1'='1"));
			expect(paddedBody.endsWith(baselineBody)).toBe(true);
		});
	});

	describe('detectAnomalyScoringMode', () => {
		it('does not infer a scoring mode when the low-score probes were rate limited', async () => {
			let calls = 0;
			// The two single-signal probes hit 429; the composite one is blocked.
			const mockFetch = vi.fn().mockImplementation(async () => (calls++ < 2 ? reply(429) : reply(403, 'Forbidden')));

			const result = await detectAnomalyScoringMode('https://example.com/api', { fetch: mockFetch as any });

			expect(result.mode).toBe('unknown');
			expect(result.detectedThreshold).toBeNull();
		});

		it('does not infer a threshold when a later probe is rate limited', async () => {
			// Single-signal probes pass; the composite score-5 probe is rate limited.
			let calls = 0;
			const mockFetch = vi.fn().mockImplementation(async () => (calls++ < 2 ? reply(200) : reply(429)));

			const result = await detectAnomalyScoringMode('https://example.com/api', { fetch: mockFetch as any });

			expect(result.mode).toBe('unknown');
			expect(result.detectedThreshold).toBeNull();
			expect(result.details).toMatch(/inconclusive/i);
		});

		it('recognises blocks served as 406', async () => {
			const mockFetch = vi.fn().mockImplementation(async () => reply(406, 'Not Acceptable'));

			const result = await detectAnomalyScoringMode('https://example.com/api', { fetch: mockFetch as any });

			expect(result.mode).toBe('traditional_regex');
		});
	});

	describe('runReverseEngineeringAudit', () => {
		const onlyCrs = { skipRateLimit: true, skipBodyLimit: true, skipAnomalyScore: true };

		it('marks CRS rules active when the WAF answers with a 200 block page', async () => {
			const mockFetch = vi.fn().mockImplementation(async () => reply(200, '<html><h1>Request blocked</h1></html>'));

			const report = await runReverseEngineeringAudit('https://example.com/api', { fetch: mockFetch as any, ...onlyCrs });

			expect(report.crsSummary.disabled).toBe(0);
			expect(report.crsSummary.active).toBe(OWASP_CRS_RULES.length);
		});

		it('marks CRS rules active on 406 and unknown (not disabled) on 429', async () => {
			const blocking = await runReverseEngineeringAudit('https://example.com/api', {
				fetch: vi.fn().mockImplementation(async () => reply(406)) as any,
				...onlyCrs,
			});
			expect(blocking.crsSummary.active).toBe(OWASP_CRS_RULES.length);

			const limited = await runReverseEngineeringAudit('https://example.com/api', {
				fetch: vi.fn().mockImplementation(async () => reply(429)) as any,
				...onlyCrs,
			});
			expect(limited.crsSummary.active).toBe(0);
			expect(limited.crsSummary.disabled).toBe(0);
		});

		it('runs the rate-limit probe only after the body-limit and anomaly probes finish', async () => {
			const order: string[] = [];
			const mockFetch = vi.fn().mockImplementation(async (url: string, init?: any) => {
				order.push(String(url).includes('ratelimit_test_seq') ? 'rate' : 'other');
				return isSqli(init) ? reply(403, 'Forbidden') : reply(200);
			});

			await runReverseEngineeringAudit('https://example.com/api', { fetch: mockFetch as any, maxRpsProbe: 5 });

			const firstRate = order.indexOf('rate');
			expect(firstRate).toBeGreaterThan(-1);
			expect(order.lastIndexOf('other')).toBeLessThan(firstRate);
		});
	});
});
