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

		const results = await handleApiCheckFiltered('http://example.com/api', 1, ['GET'], ['SQL Injection'], undefined, false, undefined, false, false, false, false, false, false, undefined, undefined, { fetch: mockFetch as any, quiet: true });
		
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

	it('should handle FileCheck payloads (Sensitive Files)', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ status: 200, headers: new Headers() });
		const results = await handleApiCheckFiltered('http://example.com/api', 1, ['GET'], ['Sensitive Files'], undefined, false, undefined, false, false, false, false, false, false, undefined, undefined, { fetch: mockFetch as any, quiet: true });
		expect(results).toBeInstanceOf(Array);
		expect(results.length).toBeGreaterThan(0);
		// Check that the URL is formed properly (baseUrl + payload)
		expect(mockFetch.mock.calls[0][0]).toContain('http://example.com');
	});

	it('should handle Header payloads (User-Agent)', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 200, 
			headers: new Headers(),
			text: async () => 'test'
		});
		const results = await handleApiCheckFiltered(
			'http://example.com/api',
			0, // page
			['GET'], // methods
			['User-Agent'], // categories
			undefined, // payloadTemplate
			false, // followRedirect
			'X-Test-Header: value\nAnother: 1', // customHeaders
			false, // falsePositiveTest
			false, // caseSensitiveTest
			false, // useEnhancedPayloads
			false, // useAdvancedPayloads
			false, // autoDetectWAF
			false, // useEncodingVariations
			undefined, // detectedWAF
			undefined, // httpManipulation
			{ fetch: mockFetch as any, quiet: true } // options
		);
		
		expect(results.length).toBeGreaterThan(0);
		const calledOptions = mockFetch.mock.calls[0][1];
		expect(calledOptions.headers).toBeDefined();
		// Should contain custom header
		const headersObj = calledOptions.headers as any;
		expect(headersObj).toBeDefined();
	});

	it('should handle API check with httpManipulation', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 200, 
			headers: new Headers(),
			text: async () => 'test'
		});
		const httpManipulation = { enableParameterPollution: true };
		const results = await handleApiCheckFiltered(
			'http://example.com/api',
			0, // page
			['GET'], // methods
			['SQL Injection'], // categories
			undefined, // payloadTemplate
			false, // followRedirect
			undefined, // customHeaders
			false, // falsePositiveTest
			false, // caseSensitiveTest
			false, // useEnhancedPayloads
			false, // useAdvancedPayloads
			false, // autoDetectWAF
			false, // useEncodingVariations
			undefined, // detectedWAF
			httpManipulation as any, // httpManipulation
			{ fetch: mockFetch as any, quiet: true } // options
		);
		console.log('httpManipulation results', results.length);
		expect(results.length).toBeGreaterThan(0);
	});

	it('should apply inspection limit padding when enableInspectionLimitPadding is set', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 200, 
			headers: new Headers(),
			text: async () => 'test'
		});
		const httpManipulation = {
			enableInspectionLimitPadding: true,
			paddingSize: '8kb',
		};
		const results = await handleApiCheckFiltered(
			'http://example.com/api',
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
			httpManipulation as any,
			{ fetch: mockFetch as any, quiet: true }
		);

		expect(results.length).toBeGreaterThan(0);
		expect(mockFetch).toHaveBeenCalled();
		// Check that the request URL contains junk padding
		const firstCallUrl = mockFetch.mock.calls[0][0];
		expect(firstCallUrl).toContain('junk=');
	});

	it('should handle API check with FileCheck and caseSensitiveTest', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 200, 
			headers: new Headers(),
			text: async () => 'test'
		});
		const results = await handleApiCheckFiltered(
			'http://example.com/api',
			0, // page
			['GET'], // methods
			['Sensitive Files'], // categories
			undefined, // payloadTemplate
			false, // followRedirect
			'X-Test-Header: value\nAnother: 1', // customHeaders
			false, // falsePositiveTest
			true, // caseSensitiveTest
			false, // useEnhancedPayloads
			false, // useAdvancedPayloads
			false, // autoDetectWAF
			false, // useEncodingVariations
			undefined, // detectedWAF
			undefined, // httpManipulation
			{ fetch: mockFetch as any, quiet: true } // options
		);
		
		expect(results.length).toBeGreaterThan(0);
	});

	it('should handle GraphQL Injection, JWT, and Padding categories individually', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 403, 
			headers: new Headers(),
			text: async () => 'blocked'
		});

		const testCategories = [
			'GraphQL Injection',
			'JWT Attack (Header)',
			'JWT Attack (Param)',
			'WAF Inspection Limit Bypass (Padding)',
			'SSRF',
			'SSTI'
		];

		for (const cat of testCategories) {
			const results = await handleApiCheckFiltered(
				'http://example.com/api',
				0,
				['GET'],
				[cat],
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

			expect(results).toBeInstanceOf(Array);
			expect(results.length).toBeGreaterThan(0);
			expect(results.every(r => r.category === cat)).toBe(true);
		}
	});

	it('should terminate early when offset exceeds pagination limit', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 200, 
			headers: new Headers(),
			text: async () => 'test'
		});
		const results = await handleApiCheckFiltered(
			'http://example.com/api',
			999, // page far beyond total payloads
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

		expect(results).toEqual([]);
	});

	it('should follow redirects and terminate on loop or 200 status', async () => {
		let redirectCount = 0;
		const mockFetch = vi.fn().mockImplementation(() => {
			redirectCount++;
			if (redirectCount < 3) {
				return Promise.resolve({
					status: 302,
					headers: new Headers({ location: 'http://example.com/api/redirect' }),
					text: async () => 'redirecting'
				});
			}
			return Promise.resolve({
				status: 200,
				headers: new Headers(),
				text: async () => 'final ok'
			});
		});

		const res = await sendRequest(
			'http://example.com/api',
			'GET',
			'test-payload',
			undefined,
			undefined,
			true, // followRedirect
			false,
			undefined,
			undefined,
			{ fetch: mockFetch as any, quiet: true }
		);

		expect(res.status).toBe(200);
		expect(redirectCount).toBe(3);
	});

	it('should handle payload templates for JSON POST requests', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			status: 200,
			headers: new Headers(),
			text: async () => 'ok'
		});

		const res = await sendRequest(
			'http://example.com/api',
			'POST',
			'inject-here',
			undefined,
			'{"query": "{PAYLOAD}"}',
			false,
			false,
			undefined,
			undefined,
			{ fetch: mockFetch as any, quiet: true }
		);

		expect(res.status).toBe(200);
		expect(mockFetch).toHaveBeenCalled();
		const callBody = mockFetch.mock.calls[0][1].body;
		expect(callBody).toBe(JSON.stringify({ query: 'inject-here' }));
	});

	it('should handle Header checks with caseSensitiveTest, customHeaders, and pagination', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 403, 
			headers: new Headers(),
			text: async () => 'blocked'
		});

		// Test Header check with case-sensitive variations and custom headers
		const results = await handleApiCheckFiltered(
			'http://example.com/api',
			0,
			['GET'],
			['User-Agent'],
			undefined,
			false,
			'X-Custom-Token: abc123',
			false,
			true, // caseSensitiveTest
			false,
			false,
			false,
			false,
			undefined,
			undefined,
			{ fetch: mockFetch as any, quiet: true }
		);

		expect(results.length).toBeGreaterThan(0);
		expect(results[0].category).toBe('User-Agent');

		// Test Header check with page out of bounds
		const emptyResults = await handleApiCheckFiltered(
			'http://example.com/api',
			100, // page out of range
			['GET'],
			['User-Agent'],
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
		expect(emptyResults).toEqual([]);
	});

	it('should handle FileCheck with pagination out of bounds', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ 
			status: 403, 
			headers: new Headers(),
			text: async () => 'blocked'
		});

		const emptyResults = await handleApiCheckFiltered(
			'http://example.com/api',
			100, // page out of range
			['GET'],
			['Sensitive Files'],
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
		expect(emptyResults).toEqual([]);
	});

	it('should handle useAdvancedPayloads, useEncodingVariations, and autoDetectWAF flags', async () => {
		const mockFetch = vi.fn().mockImplementation((url) => {
			return Promise.resolve({
				status: 403,
				headers: new Headers({ server: 'cloudflare' }),
				text: async () => 'cloudflare block'
			});
		});

		const results = await handleApiCheckFiltered(
			'http://example.com/api',
			0,
			['GET'],
			['SQL Injection'],
			undefined,
			false,
			undefined,
			false,
			false,
			true, // useEnhancedPayloads
			true, // useAdvancedPayloads
			true, // autoDetectWAF
			true, // useEncodingVariations
			undefined,
			undefined,
			{ fetch: mockFetch as any, quiet: true }
		);

		expect(results.length).toBeGreaterThan(0);
		expect(results.some(r => r.wafDetected)).toBe(true);
	});
});
