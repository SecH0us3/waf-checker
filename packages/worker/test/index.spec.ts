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
});
