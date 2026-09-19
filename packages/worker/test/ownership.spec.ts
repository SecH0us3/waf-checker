import { describe, it, expect, vi } from 'vitest';
import { determineOwnershipMode, verifyHttpOwnership } from '../src/services/ownership';

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
			expect.objectContaining({ redirect: 'follow' })
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
