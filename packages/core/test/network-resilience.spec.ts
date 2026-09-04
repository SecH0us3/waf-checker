import { describe, it, expect, vi } from 'vitest';
import { sendRequest, handleApiCheckFiltered } from '../src/check';
import { HTTPManipulator } from '../src/http-manipulation';
import { WAFDetector } from '../src/waf-detection';

describe('Network Resilience & Failure Scenarios', () => {
	describe('Socket Drops, Network Errors & Mid-Stream Aborts', () => {
		it('should cleanly handle immediate fetch network drop (ECONNRESET)', async () => {
			const mockFetch = vi.fn().mockRejectedValue(new Error('fetch failed: ECONNRESET'));

			const res = await sendRequest(
				'https://example.com/api',
				'GET',
				"' OR 1=1--",
				undefined,
				undefined,
				false,
				false,
				undefined,
				undefined,
				{ fetch: mockFetch as any, quiet: true }
			);

			expect(res).toEqual({
				status: 'ERR',
				is_redirect: false,
				responseTime: 0,
				error: 'connection_reset',
				bodyText: '',
			});
		});

		it('should handle AbortError when request exceeds timeout limit', async () => {
			const abortError = new Error('The operation was aborted');
			abortError.name = 'AbortError';
			const mockFetch = vi.fn().mockRejectedValue(abortError);

			const results = await handleApiCheckFiltered(
				'https://example.com/api',
				0,
				['GET'],
				['SQL Injection'],
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
				{ fetch: mockFetch as any, quiet: true }
			);

			expect(results.length).toBeGreaterThan(0);
			expect(results.every(r => r.status === 'ERR')).toBe(true);
		});

		it('should handle mid-response body stream aborts in activeDetection', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 200,
				headers: new Headers({ server: 'cloudflare' }),
				text: vi.fn().mockRejectedValue(new Error('ReadableStream aborted abruptly')),
			});

			const result = await WAFDetector.activeDetection('https://example.com/api', { fetch: mockFetch as any });
			expect(result.detected).toBe(false);
			expect(result.wafType).toBe('Unknown');
		});
	});

	describe('Redirect Edge Cases, Loops & SSRF Protections', () => {
		it('should terminate on infinite circular redirect loops (A -> B -> A)', async () => {
			let hop = 0;
			const mockFetch = vi.fn().mockImplementation((url: string) => {
				hop++;
				const target = url.includes('/page-a')
					? 'https://example.com/page-b'
					: 'https://example.com/page-a';
				return Promise.resolve({
					status: 302,
					headers: new Headers({ Location: target }),
					text: async () => 'redirecting'
				});
			});

			const res = await sendRequest(
				'https://example.com/page-a',
				'GET',
				undefined,
				undefined,
				undefined,
				true, // followRedirect
				false,
				undefined,
				undefined,
				{ fetch: mockFetch as any, quiet: true }
			);

			expect(hop).toBe(6); // 1 initial + 5 max redirects
			expect(res.is_redirect).toBe(true);
			expect(res.status).toBe(302);
		});

		it('should block redirects leading to private or cloud metadata IPs (SSRF via 302)', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 302,
				headers: new Headers({ Location: 'http://169.254.169.254/latest/meta-data/' }),
				text: async () => 'redirect'
			});

			const res = await sendRequest(
				'https://example.com/api',
				'GET',
				undefined,
				undefined,
				undefined,
				true, // followRedirect
				false,
				undefined,
				undefined,
				{ fetch: mockFetch as any, quiet: true }
			);

			expect(res.status).toBe('BLOCKED');
			expect(res.is_redirect).toBe(true);
		});

		it('should handle redirects with missing Location header gracefully', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 302,
				headers: new Headers(), // missing Location header
				text: async () => 'no location'
			});

			const res = await sendRequest(
				'https://example.com/api',
				'GET',
				undefined,
				undefined,
				undefined,
				true,
				false,
				undefined,
				undefined,
				{ fetch: mockFetch as any, quiet: true }
			);

			expect(res.status).toBe(302);
		});

		it('should preserve method and body on 307/308 temporary/permanent redirects', async () => {
			const requestedMethods: string[] = [];
			const mockFetch = vi.fn().mockImplementation((url: string, opts: any) => {
				requestedMethods.push(opts.method);
				if (requestedMethods.length === 1) {
					return Promise.resolve({
						status: 307,
						headers: new Headers({ Location: 'https://example.com/api/v2' }),
						text: async () => 'redirect'
					});
				}
				return Promise.resolve({
					status: 200,
					headers: new Headers(),
					text: async () => 'done'
				});
			});

			const res = await sendRequest(
				'https://example.com/api/v1',
				'POST',
				'test=1',
				undefined,
				undefined,
				true, // followRedirect
				false,
				undefined,
				undefined,
				{ fetch: mockFetch as any, quiet: true }
			);

			expect(requestedMethods).toEqual(['POST', 'POST']);
			expect(res.status).toBe(200);
		});
	});

	describe('Rate-Limit (429) & Backoff Stress Scenarios', () => {
		it('should recover when 429 Retry-After is malformed string or non-numeric', async () => {
			let attempts = 0;
			const mockFetch = vi.fn().mockImplementation(() => {
				attempts++;
				if (attempts === 1) {
					return Promise.resolve({
						status: 429,
						headers: new Headers({ 'retry-after': 'invalid-not-a-number' })
					});
				}
				return Promise.resolve({ status: 200, headers: new Headers() });
			});

			const reqs = [{ method: 'GET', url: 'https://example.com/1', headers: {}, technique: 't1', description: 'd1' }];
			const results = await HTTPManipulator.batchExecuteRequests(reqs, false, 1, 0, { fetch: mockFetch as any });

			expect(results.length).toBe(1);
			expect(results[0].status).toBe(200);
			expect(attempts).toBe(2);
		});

		it('should give up and return 429 when max retries are exceeded', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 429,
				headers: new Headers({ 'retry-after': '0' })
			});

			const reqs = [{ method: 'GET', url: 'https://example.com/rate-limited', headers: {}, technique: 't1', description: 'd1' }];
			const results = await HTTPManipulator.batchExecuteRequests(reqs, false, 1, 0, { fetch: mockFetch as any });

			expect(results.length).toBe(1);
			expect(results[0].status).toBe(429);
			expect(mockFetch).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
		});
	});

	describe('Malformed & Extreme Server Responses', () => {
		it('should handle giant response headers without blowing up heap', async () => {
			const hugeHeaders = new Headers();
			hugeHeaders.set('server', 'cloudflare');
			for (let i = 0; i < 50; i++) {
				hugeHeaders.append('x-custom-header', 'A'.repeat(500));
			}

			const mockFetch = vi.fn().mockResolvedValue({
				status: 200,
				headers: hugeHeaders,
				text: async () => 'OK'
			});

			const res = await sendRequest(
				'https://example.com/api',
				'GET',
				'test',
				undefined,
				undefined,
				false,
				false,
				undefined,
				undefined,
				{ fetch: mockFetch as any, quiet: true }
			);

			expect(res.status).toBe(200);
		});

		it('should handle response text exceeding 1MB limit by returning placeholder in WAF detection', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				status: 200,
				headers: new Headers({ 'content-length': '2097152' }), // 2MB
				text: vi.fn(),
			});

			const result = await WAFDetector.activeDetection('https://example.com/api', { fetch: mockFetch as any });
			expect(result.detected).toBe(false);
		});
	});
});
