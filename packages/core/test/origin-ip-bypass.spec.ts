import { describe, it, expect, vi } from 'vitest';
import { sendRequest, handleApiCheckFiltered } from '../src/check';

describe('Origin IP Override bypass test (sendRequest)', () => {
	it('keeps the request URL on the domain and steers DNS to the IP via cf.resolveOverride', async () => {
		let seenUrl = '';
		let seenCf: any;
		const mockFetch = vi.fn().mockImplementation(async (url: string, options: any) => {
			seenUrl = url;
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
		// URL (and therefore Host + TLS SNI) stays on the target domain, never the IP.
		expect(seenUrl).toBe('https://example.com/path');
		// Only the DNS lookup is overridden, via the Cloudflare platform hint.
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

	it('threads the override through the scan pipeline so every probe carries resolveOverride', async () => {
		const seenHosts = new Set<string>();
		let everyProbeHadOverride = true;
		const mockFetch = vi.fn().mockImplementation(async (url: string, options: any) => {
			seenHosts.add(new URL(url).hostname);
			if (options?.cf?.resolveOverride !== '8.8.8.8') everyProbeHadOverride = false;
			return { status: 200, headers: new Headers(), text: async () => '' };
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
		// The request URL always stays on the target domain; the IP rides in cf only.
		expect([...seenHosts]).toEqual(['example.com']);
		expect(everyProbeHadOverride).toBe(true);
	});
});
