import { describe, it, expect, vi } from 'vitest';
import {
	TRUSTED_IP_HEADERS,
	resolveTrustedIpHeaders,
	TrustedIpHeader,
} from '../src/payloads-data/trusted-ip-headers';
import {
	handleApiCheckFiltered,
	handleApiCheckWithEnvelope,
	maxWorkerPageSize,
	UA_PROBE_CONCURRENCY,
} from '../src/check';

function readHeader(options: any, name: string): string | undefined {
	const h = options?.headers;
	if (!h) return undefined;
	if (typeof h.get === 'function') return h.get(name) ?? undefined;
	const foundKey = Object.keys(h).find((k) => k.toLowerCase() === name.toLowerCase());
	return foundKey ? h[foundKey] : undefined;
}

describe('Trusted IP / Proxy Header Definitions (trusted-ip-headers.ts)', () => {
	it('provides the curated TRUSTED_IP_HEADERS list with X-Forwarded-For 127.0.0.1 first', () => {
		expect(TRUSTED_IP_HEADERS.length).toBeGreaterThanOrEqual(8);
		expect(TRUSTED_IP_HEADERS[0]).toEqual({
			name: 'XFF-Loopback',
			headerName: 'X-Forwarded-For',
			headerValue: '127.0.0.1',
		});
		const headerNames = TRUSTED_IP_HEADERS.map((h) => h.headerName);
		expect(headerNames).toContain('X-Real-IP');
		expect(headerNames).toContain('True-Client-IP');
		expect(headerNames).toContain('CF-Connecting-IP');
		expect(headerNames).toContain('Forwarded');
	});

	it('resolves boolean and custom array options properly via resolveTrustedIpHeaders', () => {
		expect(resolveTrustedIpHeaders(undefined)).toEqual([]);
		expect(resolveTrustedIpHeaders(false)).toEqual([]);
		expect(resolveTrustedIpHeaders(true)).toEqual(TRUSTED_IP_HEADERS);

		const custom: TrustedIpHeader[] = [
			{ name: 'Custom-IP', headerName: 'X-Custom-IP', headerValue: '10.10.10.10' },
		];
		expect(resolveTrustedIpHeaders(custom)).toEqual(custom);
	});
});

describe('Trusted IP Header Bypass Probing in check.ts', () => {
	it('flags a bypass immediately (tested: 1) when X-Forwarded-For: 127.0.0.1 bypasses a 403 block', async () => {
		const mockFetch = vi.fn().mockImplementation(async (_url: string, options: any) => {
			const xff = readHeader(options, 'X-Forwarded-For');
			const status = xff === '127.0.0.1' ? 200 : 403;
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
			{ fetch: mockFetch as any, quiet: true, pageSize: 3, spoofIpHeaders: true },
		);

		expect(results).toHaveLength(3);
		for (const r of results) {
			expect(r.status).toBe(403);
			expect(r.ipHeaderBypass).toBeDefined();
			expect(r.ipHeaderBypass!.bypassed).toBe(true);
			expect(r.ipHeaderBypass!.tested).toBe(1);
			expect(r.ipHeaderBypass!.hits[0]).toMatchObject({
				name: 'XFF-Loopback',
				headerName: 'X-Forwarded-For',
				headerValue: '127.0.0.1',
				status: 200,
			});
		}
	});

	it('probes subsequent headers via concurrency pool when first header stays blocked', async () => {
		const mockFetch = vi.fn().mockImplementation(async (_url: string, options: any) => {
			const trueClientIp = readHeader(options, 'True-Client-IP');
			const status = trueClientIp === '127.0.0.1' ? 200 : 403;
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
			{ fetch: mockFetch as any, quiet: true, pageSize: 2, spoofIpHeaders: true },
		);

		expect(results).toHaveLength(2);
		for (const r of results) {
			expect(r.ipHeaderBypass).toBeDefined();
			expect(r.ipHeaderBypass!.bypassed).toBe(true);
			expect(r.ipHeaderBypass!.hits.map((h) => h.name)).toContain('True-Client-IP');
			expect(r.ipHeaderBypass!.tested).toBeLessThanOrEqual(5 + UA_PROBE_CONCURRENCY);
		}
	});

	it('accounts for trustedIpHeaderCount in maxWorkerPageSize', () => {
		const sizeWithoutIp = maxWorkerPageSize({ legitUserAgentCount: 0, followRedirect: false });
		const sizeWithIp = maxWorkerPageSize({
			legitUserAgentCount: 0,
			trustedIpHeaderCount: TRUSTED_IP_HEADERS.length,
			followRedirect: false,
		});
		expect(sizeWithIp).toBeLessThan(sizeWithoutIp);
		expect(sizeWithIp).toBeGreaterThanOrEqual(50);
	});

	it('executes scan items in parallel while preserving exact order when concurrency > 1', async () => {
		let inFlight = 0;
		let maxInFlight = 0;
		const mockFetch = vi.fn().mockImplementation(async () => {
			inFlight++;
			maxInFlight = Math.max(maxInFlight, inFlight);
			await new Promise((r) => setTimeout(r, 5));
			inFlight--;
			return { status: 403, headers: new Headers(), text: async () => '' };
		});

		const sequential = await handleApiCheckWithEnvelope(
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
			{ fetch: mockFetch as any, quiet: true, pageSize: 8, concurrency: 1 },
		);

		maxInFlight = 0;
		const parallel = await handleApiCheckWithEnvelope(
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
			{ fetch: mockFetch as any, quiet: true, pageSize: 8, concurrency: 4 },
		);

		expect(maxInFlight).toBeGreaterThanOrEqual(2);
		expect(maxInFlight).toBeLessThanOrEqual(4);
		expect(parallel.results.map((r) => r.payload)).toEqual(sequential.results.map((r) => r.payload));
	});
});
