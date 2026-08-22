import { describe, it, expect, vi } from 'vitest';
import { sendRequest, handleApiCheckFiltered } from '../src/check';

describe('check.ts', () => {
	it('should send a basic request', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			status: 200,
			headers: new Headers(),
		});

		const result = await sendRequest('http://example.com/api', 'GET', 'test-payload', {}, undefined, false, false, undefined, undefined, { fetch: mockFetch as any });
		expect(mockFetch).toHaveBeenCalled();
		expect(result).toHaveProperty('status', 200);
	});

	it('should block invalid SSRF URLs in sendRequest', async () => {
		const mockFetch = vi.fn();
		const result = await sendRequest('http://169.254.169.254/latest', 'GET', undefined, undefined, undefined, false, false, undefined, undefined, { fetch: mockFetch as any });
		expect(result).toHaveProperty('status', 'BLOCKED');
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it('should substitute {PAYLOAD} in URL if provided', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ status: 200, headers: new Headers() });
		await sendRequest('http://example.com/api?q={PAYLOAD}', 'GET', 'test-payload', {}, undefined, false, false, undefined, undefined, { fetch: mockFetch as any });
		const calledUrl = mockFetch.mock.calls[0][0];
		expect(calledUrl).toContain('test-payload');
	});

	it('should handle API check filtered with basic mock', async () => {
		const mockFetch = vi.fn().mockImplementation((url, options) => {
			if (url.includes('malicious')) {
				return Promise.resolve({ status: 403, headers: new Headers() });
			}
			return Promise.resolve({ status: 200, headers: new Headers() });
		});

		const results = await handleApiCheckFiltered('http://example.com/api', 10, ['GET'], ['sqli'], undefined, false, undefined, false, false, false, false, false, false, undefined, undefined, { fetch: mockFetch as any, quiet: true });
		
		expect(results).toBeInstanceOf(Array);
		// It should run tests and return objects with status, payload, category
		const firstResult = results[0];
		if (firstResult) {
			expect(firstResult).toHaveProperty('status');
		}
	});

	it('should execute auto-detect WAF before testing', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 403, 
			headers: new Headers({ 'server': 'cloudflare' }),
			text: vi.fn().mockResolvedValue('blocked')
		});

		const results = await handleApiCheckFiltered('http://example.com/api', 1, ['GET'], ['sqli'], undefined, false, undefined, false, false, false, false, true, false, undefined, undefined, { fetch: mockFetch as any, quiet: true });
		
		expect(mockFetch).toHaveBeenCalled();
		// Since it auto-detects, WAF Detection logic will trigger
	});
});
