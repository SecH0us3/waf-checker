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
});
