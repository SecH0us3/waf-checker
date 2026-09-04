import { SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';

describe('WAF Checker API', () => {
	it('serves index page at /', async () => {
		const response = await SELF.fetch('https://example.com/');
		expect(response.status).toBe(200);
		const text = await response.text();
		expect(text).toContain('WAF Checker');
	});

	it('returns 400 for /api/check without url param', async () => {
		const response = await SELF.fetch('https://example.com/api/check');
		expect(response.status).toBe(400);
	});

	it('returns 400 for /api/waf-detect without url param', async () => {
		const response = await SELF.fetch('https://example.com/api/waf-detect');
		expect(response.status).toBe(400);
		const data = await response.json();
		expect(data.error).toBe('Missing url parameter');
	});

	it('returns 400 for /api/reverse-engineer without url param or SSRF restricted target', async () => {
		const responseNoUrl = await SELF.fetch('https://example.com/api/reverse-engineer');
		expect(responseNoUrl.status).toBe(400);

		const responseSsrf = await SELF.fetch('https://example.com/api/reverse-engineer?url=http://127.0.0.1:8080');
		expect(responseSsrf.status).toBe(400);
		const data = await responseSsrf.json();
		expect(data.error).toBe('Invalid URL or restricted IP');
	});

	it('returns 400 for /api/http-manipulation without url param', async () => {
		const response = await SELF.fetch('https://example.com/api/http-manipulation');
		expect(response.status).toBe(400);
		const data = await response.json();
		expect(data.error).toBe('Missing url parameter');
	});

	it('returns 404 for unknown routes', async () => {
		const response = await SELF.fetch('https://example.com/unknown');
		expect(response.status).toBe(404);
	});

	it('returns 400 for SSRF restricted target in /api/check', async () => {
		const response = await SELF.fetch('https://example.com/api/check?url=http://169.254.169.254/latest');
		expect(response.status).toBe(400);
		const data = await response.json();
		expect(data.error).toBe('Invalid URL or restricted IP');
	});

	it('returns 400 for SSRF restricted target in /api/waf-detect', async () => {
		const response = await SELF.fetch('https://example.com/api/waf-detect?url=http://127.0.0.1:8080');
		expect(response.status).toBe(400);
		const data = await response.json();
		expect(data.error).toBe('Invalid URL or restricted IP');
	});

	it('handles /api/check with query params and POST body', async () => {
		const response = await SELF.fetch('https://example.com/api/check?url=https://example.com&methods=GET&categories=User-Agent', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				customHeaders: 'X-Test: 1',
				detectedWAF: 'Cloudflare'
			})
		});
		expect(response.status).toBe(200);
		const data = await response.json();
		expect(Array.isArray(data)).toBe(true);
	});

	it('returns 400 for /api/batch/status without jobId', async () => {
		const response = await SELF.fetch('https://example.com/api/batch/status');
		expect(response.status).toBe(400);
	});

	it('returns 400 for /api/batch/stop without jobId', async () => {
		const response = await SELF.fetch('https://example.com/api/batch/stop', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({})
		});
		expect(response.status).toBe(400);
	});

	it('returns 405 for /api/virtual-patch with GET request', async () => {
		const response = await SELF.fetch('https://example.com/api/virtual-patch');
		expect(response.status).toBe(405);
	});

	it('returns 400 for /api/virtual-patch without results array', async () => {
		const response = await SELF.fetch('https://example.com/api/virtual-patch', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({}),
		});
		expect(response.status).toBe(400);
	});

	it('handles /api/virtual-patch and returns generated patches', async () => {
		const response = await SELF.fetch('https://example.com/api/virtual-patch', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				results: [
					{
						category: 'SQL Injection',
						method: 'GET',
						payload: "' UNION SELECT 1",
						status: 200,
						responseTime: 40,
					},
				],
				options: {
					vendor: 'cloudflare',
					targetUrl: 'https://example.com/api',
				},
			}),
		});
		expect(response.status).toBe(200);
		const data: any = await response.json();
		expect(data.totalBypasses).toBe(1);
		expect(data.bundles.cloudflare).toBeDefined();
		expect(data.bundles.cloudflare.ruleCount).toBeGreaterThan(0);
	});

	it('returns 400 for /api/virtual-patch with SSRF restricted targetUrl', async () => {
		const response = await SELF.fetch('https://example.com/api/virtual-patch', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				results: [{ category: 'SQLi', method: 'GET', payload: 'test', status: 200, responseTime: 10 }],
				options: {
					targetUrl: 'http://169.254.169.254/latest',
				},
			}),
		});
		expect(response.status).toBe(400);
		const data = await response.json();
		expect(data.error).toBe('Invalid URL or restricted IP');
	});

	it('serves main.js and renderReport renders table with responseTime without errors', async () => {
		const response = await SELF.fetch('https://example.com/main.js');
		expect(response.status).toBe(200);
		const code = await response.text();

		const sandbox = {
			window: {} as any,
			document: {
				querySelectorAll: () => [],
				getElementById: () => null,
				addEventListener: () => {},
				createElement: () => ({ set textContent(v: string) { (this as any)._v = v; }, get innerHTML() { return (this as any)._v; } }),
			} as any,
			setTimeout: (fn: Function) => fn(),
		};
		const fn = new Function('window', 'document', 'setTimeout', code + '\nreturn renderReport;');
		const renderReport = fn(sandbox.window, sandbox.document, sandbox.setTimeout);
		const html = renderReport([
			{ category: 'SQL Injection', method: 'GET', payload: 'union select', status: 200, responseTime: 120 },
			{ category: 'Sensitive Files', method: 'GET', payload: '/.git/config', status: 404, responseTime: 95 },
		], false);
		expect(html).toContain('120ms');
		expect(html).toContain('95ms');
		expect(html).toContain('btn-outline-danger');
		expect(html).toContain('btn-outline-warning');
		expect(html).toContain('showVirtualPatchModal(\'misses\')');
	});

	it('handles /api/virtual-patch with includeMisses: true for 404 status vectors', async () => {
		const response = await SELF.fetch('https://example.com/api/virtual-patch', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				results: [
					{ category: 'Sensitive Files', method: 'GET', payload: '/.git/config', status: 404, responseTime: 30 },
				],
				options: {
					vendor: 'cloudflare',
					includeMisses: true,
				},
			}),
		});
		expect(response.status).toBe(200);
		const data: any = await response.json();
		expect(data.totalBypasses).toBe(1);
		expect(data.bundles.cloudflare.ruleCount).toBeGreaterThan(0);
		expect(data.bundles.cloudflare.native).toContain('.git');
	});

	it('returns 422 with SELF_SCAN_REFUSED when targeting secmy.org or subdomains', async () => {
		const resApex = await SELF.fetch('https://example.com/api/check?url=https://secmy.org/');
		expect(resApex.status).toBe(422);
		const dataApex: any = await resApex.json();
		expect(dataApex.code).toBe('SELF_SCAN_REFUSED');

		const resSub = await SELF.fetch('https://example.com/api/check?url=https://waf-checker.secmy.org/api');
		expect(resSub.status).toBe(422);
		const dataSub: any = await resSub.json();
		expect(dataSub.code).toBe('SELF_SCAN_REFUSED');
	});

	it('does NOT refuse URLs merely containing secmy in path or unrelated domain', async () => {
		const res = await SELF.fetch('https://example.com/api/check?url=https://example.com/secmy-test');
		// Should not be 422
		expect(res.status).not.toBe(422);
	});

	it('returns a pagination envelope for /api/check when ?envelope=1 is provided', async () => {
		const response = await SELF.fetch('https://example.com/api/check?url=https://example.com&categories=User-Agent&envelope=1&pageSize=5');
		expect(response.status).toBe(200);
		const data: any = await response.json();
		expect(data).toHaveProperty('results');
		expect(data).toHaveProperty('page', 0);
		expect(data).toHaveProperty('pageSize', 5);
		expect(data).toHaveProperty('total');
		expect(data).toHaveProperty('hasMore');
		expect(Array.isArray(data.results)).toBe(true);
		expect(data.results.length).toBeLessThanOrEqual(5);

		if (data.results.length > 0) {
			expect(data.results[0]).toHaveProperty('blocked');
			expect(data.results[0]).toHaveProperty('verdict');
		}
	});

	it('exposes confidencePercent and confidenceThreshold on /api/waf-detect', async () => {
		const response = await SELF.fetch('https://example.com/api/waf-detect?url=https://example.com');
		expect(response.status).toBe(200);
		const data: any = await response.json();
		expect(data).toHaveProperty('detection');
		expect(data.detection).toHaveProperty('confidence');
		expect(data.detection).toHaveProperty('confidencePercent');
		expect(data.detection).toHaveProperty('confidenceThreshold', 40);
		expect(data.detection.confidencePercent).toBeGreaterThanOrEqual(0);
		expect(data.detection.confidencePercent).toBeLessThanOrEqual(100);
	});

	it('handles /api/audit single-step audit endpoint and returns detection, results, and patches', async () => {
		const response = await SELF.fetch('https://example.com/api/audit?url=https://example.com&categories=SQL Injection');
		expect(response.status).toBe(200);
		const data: any = await response.json();
		expect(data).toHaveProperty('detection');
		expect(data).toHaveProperty('results');
		expect(data).toHaveProperty('patches');
		expect(Array.isArray(data.results)).toBe(true);
		expect(data.patches).toHaveProperty('bundles');
	});
});
