import { describe, it, expect, vi } from 'vitest';
import { determineOwnershipMode, verifyHttpOwnership, challengeUrlFor } from '../src/services/ownership';

describe('Domain Ownership Service (Hybrid Mode)', () => {
	it('matches domain on exact match or subdomain (fast-track)', () => {
		expect(determineOwnershipMode('admin@example.com', 'https://example.com')).toBe('fast-track');
		expect(determineOwnershipMode('dev@sub.example.com', 'https://sub.example.com')).toBe('fast-track');
		expect(determineOwnershipMode('security@example.com', 'https://shop.example.com')).toBe('fast-track');
	});

	it('routes personal or different domains to external mode', () => {
		expect(determineOwnershipMode('user@gmail.com', 'https://example.com')).toBe('external');
		expect(determineOwnershipMode('admin@attacker.com', 'https://target.com')).toBe('external');
	});

	it('verifies HTTP ownership file challenge at /.well-known/secmy-check.txt', async () => {
		const mockFetch = vi.fn().mockResolvedValue(new Response('expected-token-123\n', { status: 200 }));
		const ok = await verifyHttpOwnership('https://example.com', 'expected-token-123', mockFetch as any);
		expect(ok).toBe(true);
		expect(mockFetch).toHaveBeenCalledWith(
			'https://example.com/.well-known/secmy-check.txt',
			expect.objectContaining({ redirect: 'manual' })
		);
	});

	it('fails HTTP ownership when redirected to link-local / cloud metadata (SSRF)', async () => {
		const redirectResponse = new Response(null, {
			status: 302,
			headers: { Location: 'http://169.254.169.254/latest/meta-data/' },
		});
		const mockFetch = vi.fn().mockResolvedValue(redirectResponse);

		const ok = await verifyHttpOwnership('https://example.com', 'expected-token-123', mockFetch as any);
		expect(ok).toBe(false);
		expect(mockFetch).toHaveBeenCalledTimes(1);
	});

	it('fails HTTP ownership when redirected to out-of-scope host', async () => {
		const redirectResponse = new Response(null, {
			status: 302,
			headers: { Location: 'https://attacker.com/.well-known/secmy-check.txt' },
		});
		const mockFetch = vi.fn().mockResolvedValue(redirectResponse);

		const ok = await verifyHttpOwnership('https://example.com', 'expected-token-123', mockFetch as any);
		expect(ok).toBe(false);
		expect(mockFetch).toHaveBeenCalledTimes(1);
	});

	it('follows valid in-scope redirect and verifies token', async () => {
		const redirectResponse = new Response(null, {
			status: 301,
			headers: { Location: 'https://www.example.com/.well-known/secmy-check.txt' },
		});
		const successResponse = new Response('expected-token-123\n', { status: 200 });
		const mockFetch = vi
			.fn()
			.mockResolvedValueOnce(redirectResponse)
			.mockResolvedValueOnce(successResponse);

		const ok = await verifyHttpOwnership('https://example.com', 'expected-token-123', mockFetch as any);
		expect(ok).toBe(true);
		expect(mockFetch).toHaveBeenCalledTimes(2);
		expect(mockFetch).toHaveBeenNthCalledWith(
			2,
			'https://www.example.com/.well-known/secmy-check.txt',
			expect.objectContaining({ redirect: 'manual' })
		);
	});

	it('fails HTTP ownership when token does not match or returns 404', async () => {
		const mockFetch404 = vi.fn().mockResolvedValue(new Response('Not found', { status: 404 }));
		const ok404 = await verifyHttpOwnership('https://example.com', 'token', mockFetch404 as any);
		expect(ok404).toBe(false);

		const mockFetchWrong = vi.fn().mockResolvedValue(new Response('wrong-token', { status: 200 }));
		const okWrong = await verifyHttpOwnership('https://example.com', 'token', mockFetchWrong as any);
		expect(okWrong).toBe(false);
	});
});

describe('Challenge location and empty-token handling', () => {
	it('derives the challenge URL origin-relative, ignoring path and query', () => {
		expect(challengeUrlFor('https://example.com/api?q=1')).toBe(
			'https://example.com/.well-known/secmy-check.txt'
		);
		expect(challengeUrlFor('https://example.com:8443/deep/path')).toBe(
			'https://example.com:8443/.well-known/secmy-check.txt'
		);
	});

	it('never verifies an empty expected token against an empty body', async () => {
		// `''.split(/\r?\n/)` is `['']`, so a blank challenge file would otherwise
		// "contain" an empty token and any host serving an empty 200 would pass.
		const fetchFn = vi.fn().mockResolvedValue(new Response('', { status: 200 }));
		await expect(verifyHttpOwnership('https://example.com', '', fetchFn)).resolves.toBe(false);
		expect(fetchFn).not.toHaveBeenCalled();
	});
});
