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

	it('returns 400 for /api/batch/start without body', async () => {
		const response = await SELF.fetch('https://example.com/api/batch/start', {
			method: 'POST',
			body: JSON.stringify({}),
		});
		expect(response.status).toBe(400);
	});
});
