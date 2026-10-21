import { describe, it, expect, vi } from 'vitest';
import { sendRequest, handleApiCheckFiltered } from '../src/check';

function readHeader(options: any, name: string): string | undefined {
	const h = options?.headers;
	if (!h) return undefined;
	if (typeof h.get === 'function') return h.get(name) ?? undefined;
	const foundKey = Object.keys(h).find((k) => k.toLowerCase() === name.toLowerCase());
	return foundKey ? h[foundKey] : undefined;
}

describe('Origin IP Override bypass test (sendRequest)', () => {
	it('connects to the origin IP but presents the target hostname as the Host header', async () => {
		let seenUrl = '';
		let seenHost: string | undefined;
		let seenCf: any;
		const mockFetch = vi.fn().mockImplementation(async (url: string, options: any) => {
			seenUrl = url;
			seenHost = readHeader(options, 'Host');
			seenCf = options?.cf;
			return { status: 200, headers: new Headers(), text: async () => 'ok' };
		});

		const res = await sendRequest(
			'https://example.com/path',
			'GET',
			undefined,
			undefined,
			undefined,
			false,
			false,
			undefined,
			undefined,
			{ fetch: mockFetch as any, quiet: true, originIpOverride: '8.8.8.8' },
		);

		expect(res.status).toBe(200);
		expect(seenUrl).toBe('https://8.8.8.8/path');
		expect(seenHost).toBe('example.com');
		// Worker platform hint is set so Cloudflare forces the DNS lookup to the IP.
		expect(seenCf?.resolveOverride).toBe('8.8.8.8');
	});

	it('refuses (BLOCKED) a private/restricted origin IP without issuing the request', async () => {
		const mockFetch = vi.fn();
		const res = await sendRequest(
			'https://example.com/',
			'GET',
			undefined,
			undefined,
			undefined,
			false,
			false,
			undefined,
			undefined,
			{ fetch: mockFetch as any, quiet: true, originIpOverride: '169.254.169.254' },
		);
		expect(res.status).toBe('BLOCKED');
		expect(res.error).toBe('invalid_origin_ip');
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it('threads the override through the scan pipeline so every probe hits the IP', async () => {
		const seenUrls = new Set<string>();
		const mockFetch = vi.fn().mockImplementation(async (url: string, options: any) => {
			seenUrls.add(new URL(url).hostname);
			// Only the direct-to-origin host answers 200; the WAF-fronted domain would 403.
			const host = readHeader(options, 'Host');
			const status = host === 'example.com' ? 200 : 403;
			return { status, headers: new Headers(), text: async () => '' };
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
			false,
			false,
			false,
			false,
			undefined,
			undefined,
			{ fetch: mockFetch as any, quiet: true, pageSize: 3, originIpOverride: '8.8.8.8' },
		);

		expect(results.length).toBeGreaterThan(0);
		// All connections went to the origin IP, never the WAF-fronted hostname.
		expect(seenUrls.has('8.8.8.8')).toBe(true);
		expect(seenUrls.has('example.com')).toBe(false);
	});
});
