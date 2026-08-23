import { describe, it, expect, vi } from 'vitest';
import { WAFDetector } from '../src/waf-detection';

describe('WAFDetector', () => {
	it('should return supported WAFs', () => {
		const wafs = WAFDetector.getSupportedWafs();
		expect(wafs).toContain('Cloudflare');
		expect(wafs).toContain('AWS WAF');
		expect(wafs).toContain('DDoS-Guard');
		expect(wafs).toContain('Signal Sciences');
		expect(wafs).not.toContain('Generic WAF'); // Generic should be filtered out
	});

	it('should detect Cloudflare WAF from headers', async () => {
		const mockResponse = {
			status: 403,
			headers: {
				get: (name: string) => {
					if (name.toLowerCase() === 'server') return 'cloudflare';
					if (name.toLowerCase() === 'cf-ray') return '123456789';
					return null;
				},
			},
		} as unknown as Response;

		const result = await WAFDetector.detectFromResponse(mockResponse);
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('Cloudflare');
		expect(result.confidence).toBeGreaterThan(40);
		expect(result.evidence.length).toBeGreaterThan(0);
		expect(result.suggestedBypassTechniques.length).toBeGreaterThan(0);
	});

	it('should detect DDoS-Guard WAF from headers and cookies', async () => {
		const mockResponse = {
			status: 403,
			headers: {
				get: (name: string) => {
					if (name.toLowerCase() === 'server') return 'ddos-guard';
					if (name.toLowerCase() === 'set-cookie') return '__ddg1_=abc123; Path=/';
					return null;
				},
			},
		} as unknown as Response;

		const result = await WAFDetector.detectFromResponse(mockResponse);
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('DDoS-Guard');
		expect(result.confidence).toBeGreaterThan(40);
		expect(result.evidence.length).toBeGreaterThan(0);
		expect(result.suggestedBypassTechniques.length).toBeGreaterThan(0);
	});

	it('should detect AWS WAF from headers', async () => {
		const mockResponse = {
			status: 403,
			headers: {
				get: (name: string) => {
					if (name.toLowerCase() === 'x-amzn-requestid') return '123';
					return null;
				},
			},
		} as unknown as Response;

		const result = await WAFDetector.detectFromResponse(mockResponse);
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('AWS WAF');
	});

	it('should return Unknown if no signatures match confidently', async () => {
		const mockResponse = {
			status: 200,
			headers: {
				get: () => null,
			},
		} as unknown as Response;

		const result = await WAFDetector.detectFromResponse(mockResponse);
		expect(result.detected).toBe(false);
		expect(result.wafType).toBe('Unknown');
	});

	it('should perform active detection using mock fetch', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			status: 403,
			headers: {
				get: (name: string) => (name.toLowerCase() === 'server' ? 'cloudflare' : null),
			},
			text: vi.fn().mockResolvedValue('cloudflare block page'),
		});

		const result = await WAFDetector.activeDetection('http://example.com/api', { fetch: mockFetch as any });

		expect(mockFetch).toHaveBeenCalled();
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('Cloudflare');
	});

	it('should throw an error during active detection for invalid URLs', async () => {
		await expect(WAFDetector.activeDetection('http://127.0.0.1')).rejects.toThrow('Invalid URL or restricted IP');
	});

	it('should detect bypass opportunities using mock fetch', async () => {
		const mockFetch = vi.fn().mockImplementation((url, options) => {
			if (options.method === 'TRACE') {
				return Promise.resolve({ status: 200 }); // Not 405 -> httpMethodsBypass = true
			}
			if (options.headers && options.headers['X-Original-URL']) {
				return Promise.resolve({ status: 200 }); // headerBypass = true
			}
			if (url.includes('test=safe&test=malicious')) {
				return Promise.resolve({ status: 200 }); // parameterPollution = true
			}
			if (url.includes('%2527')) {
				return Promise.resolve({ status: 200 }); // encodingBypass = true
			}
			return Promise.resolve({ status: 403 });
		});

		const result = await WAFDetector.detectBypassOpportunities('http://example.com/api', { fetch: mockFetch as any });

		expect(result.httpMethodsBypass).toBe(true);
		expect(result.headerBypass).toBe(true);
		expect(result.encodingBypass).toBe(true);
		expect(result.parameterPollution).toBe(true);
	});
	
	it('should throw an error during bypass detection for invalid URLs', async () => {
		await expect(WAFDetector.detectBypassOpportunities('http://169.254.169.254')).rejects.toThrow('Invalid URL or restricted IP');
	});
});
