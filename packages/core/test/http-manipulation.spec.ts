import { describe, it, expect, vi } from 'vitest';
import { HTTPManipulator } from '../src/http-manipulation';

describe('HTTPManipulator', () => {
	it('should return uncommon methods', () => {
		const methods = HTTPManipulator.getUncommonMethods();
		expect(methods).toContain('TRACE');
		expect(methods).toContain('OPTIONS');
		expect(methods).toContain('PROPFIND');
		expect(methods.length).toBeGreaterThan(5);
	});

	it('should generate method overrides', () => {
		const overrides = HTTPManipulator.generateMethodOverrides('GET', 'POST');
		expect(overrides).toBeInstanceOf(Array);
		expect(overrides.length).toBeGreaterThan(0);
		
		const hasXHttpOverride = overrides.some(o => o['X-HTTP-Method-Override'] === 'POST');
		expect(hasXHttpOverride).toBe(true);
	});

	it('should generate parameter pollution variations', () => {
		const variations = HTTPManipulator.generateParameterPollution('id', '1=1');
		expect(variations).toBeInstanceOf(Array);
		expect(variations.some(v => v.includes('id=1%3D1&id=safe'))).toBe(true);
		expect(variations.some(v => v.includes('id[]=1%3D1'))).toBe(true);
	});

	it('should get content type variations', () => {
		const variations = HTTPManipulator.getContentTypeVariations();
		expect(variations).toBeInstanceOf(Array);
		expect(variations.some(v => v['Content-Type']?.includes('application/x-www-form-urlencoded'))).toBe(true);
		expect(variations.some(v => v['Content-Type']?.includes('application/json'))).toBe(true);
	});

	it('should generate request smuggling headers', () => {
		const headers = HTTPManipulator.generateRequestSmugglingHeaders();
		expect(headers).toBeInstanceOf(Array);
		expect(headers.some(h => Object.keys(h).includes('Transfer-Encoding') || Object.keys(h).includes('Content-Length'))).toBe(true);
	});

	it('should generate host header variations', () => {
		const variations = HTTPManipulator.generateHostHeaderVariations('target.com', 'evil.com');
		expect(variations).toBeInstanceOf(Array);
		expect(variations.some(v => v['Host'] === 'target.com' && v['X-Forwarded-Host'] === 'evil.com')).toBe(true);
		expect(variations.some(v => v['Host'] === 'evil.com')).toBe(true);
	});

	it('should generate manipulated requests based on options', () => {
		const requests = HTTPManipulator.generateManipulatedRequests('http://example.com/api', 'GET', '1=1', {
			enableVerbTampering: true,
			enableParameterPollution: true,
			enableContentTypeConfusion: true,
		});
		
		expect(requests).toBeInstanceOf(Array);
		expect(requests.length).toBeGreaterThan(0);
		
		// Should contain some method overrides (which happens if enableVerbTampering is true)
		const overrides = requests.filter(r => Object.keys(r.headers || {}).some(k => k.toLowerCase().includes('override')));
		expect(overrides.length).toBeGreaterThan(0);
		
		// Should contain parameter pollution
		const pollution = requests.filter(r => r.url.includes('safe') && r.url.includes('test'));
		expect(pollution.length).toBeGreaterThan(0);
	});

	it('should execute a manipulated request successfully', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			status: 200,
			headers: new Headers({ 'x-test': 'value' }),
		});

		const req = {
			method: 'POST',
			url: 'https://example.com/api',
			headers: { 'X-HTTP-Method-Override': 'PUT' },
			technique: 'Method Override',
			description: 'Testing override'
		};

		const result = await HTTPManipulator.executeManipulatedRequest(req, false, { fetch: mockFetch as any });
		expect(result.status).toBe(200);
		expect(result.method).toBe('POST');
		expect(result.headers['x-test']).toBe('value');
	});

	it('should handle execution errors and return client blocked status', async () => {
		const mockFetch = vi.fn().mockRejectedValue(new Error('Protocol error'));
		const req = {
			method: 'GET',
			url: 'https://example.com/api',
			headers: {},
			technique: 'Test',
			description: 'Test error'
		};

		const result = await HTTPManipulator.executeManipulatedRequest(req, false, { fetch: mockFetch as any });
		expect(result.status).toBe('Blocked (Client)');
		expect(result.error).toContain('Protocol error');
	});

	it('should prevent SSRF in executeManipulatedRequest', async () => {
		const req = {
			method: 'GET',
			url: 'http://169.254.169.254/latest/meta-data/',
			headers: {},
			technique: 'SSRF',
			description: 'Test SSRF'
		};
		const result = await HTTPManipulator.executeManipulatedRequest(req);
		expect(result.status).toBe('BLOCKED');
		expect(result.error).toContain('SSRF');
	});

	it('should batch execute requests with rate limit backoff', async () => {
		let callCount = 0;
		const mockFetch = vi.fn().mockImplementation(() => {
			callCount++;
			if (callCount === 1) {
				return Promise.resolve({
					status: 429,
					headers: new Headers({ 'retry-after': '1' })
				});
			}
			return Promise.resolve({ status: 200, headers: new Headers() });
		});

		const reqs = [
			{ method: 'GET', url: 'https://example.com/1', headers: {}, technique: 't1', description: 'd1' }
		];

		const results = await HTTPManipulator.batchExecuteRequests(reqs, false, 1, 0, { fetch: mockFetch as any });
		expect(results.length).toBe(1);
		expect(results[0].status).toBe(200); // Because it retried
		expect(callCount).toBe(2);
	});

	it('should analyze results and categorize them', () => {
		const results = [
			{ status: 200, technique: 'Bypass1' },
			{ status: 403, technique: 'Blocked1' },
			{ status: 500, technique: 'Error1' }, // 500 is considered successful bypass (server error)
			{ status: 400, technique: 'Suspicious1' },
		];

		const analysis = HTTPManipulator.analyzeResults(results);
		expect(analysis.successfulTechniques).toContain('Bypass1');
		expect(analysis.successfulTechniques).toContain('Error1');
		expect(analysis.suspiciousTechniques).toContain('Suspicious1');
		expect(analysis.recommendations.length).toBeGreaterThan(0);
	});
});
