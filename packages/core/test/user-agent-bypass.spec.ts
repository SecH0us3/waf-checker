import { describe, it, expect, vi } from 'vitest';
import { handleApiCheckFiltered } from '../src/check';
import { LEGIT_USER_AGENTS, resolveLegitUserAgents } from '../src/payloads-data/legit-user-agents';

// Trusted identities we treat as "legitimate" in these tests.
const TRUSTED = /Googlebot|Slackbot|bingbot|facebookexternalhit|Discordbot|Twitterbot|YandexBot|Applebot|UptimeRobot|Pingdom|LinkedInBot|TelegramBot|WhatsApp|DuckDuckBot|Google-InspectionTool/i;

function readUserAgent(options: any): string | undefined {
	const h = options?.headers;
	if (!h) return undefined;
	if (typeof h.get === 'function') return h.get('User-Agent') ?? undefined;
	return h['User-Agent'];
}

describe('resolveLegitUserAgents', () => {
	it('returns empty list when disabled', () => {
		expect(resolveLegitUserAgents(false)).toEqual([]);
		expect(resolveLegitUserAgents(undefined)).toEqual([]);
	});

	it('returns the curated list when true', () => {
		expect(resolveLegitUserAgents(true)).toBe(LEGIT_USER_AGENTS);
		expect(resolveLegitUserAgents(true).length).toBeGreaterThan(0);
	});

	it('passes through a custom list', () => {
		const custom = [{ name: 'Custom', userAgent: 'Custom/1.0' }];
		expect(resolveLegitUserAgents(custom)).toBe(custom);
	});
});

describe('legitimate User-Agent bypass test', () => {
	it('flags a bypass when a blocked (403) request passes under a trusted UA', async () => {
		const mockFetch = vi.fn().mockImplementation((_url: string, options: any) => {
			const ua = readUserAgent(options);
			const status = ua && TRUSTED.test(ua) ? 200 : 403;
			return Promise.resolve({ status, headers: new Headers() });
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
			{ fetch: mockFetch as any, quiet: true, spoofUserAgents: true },
		);

		expect(results.length).toBeGreaterThan(0);
		// Every baseline was 403, so every item should have been probed and bypassed.
		for (const r of results) {
			expect(r.status).toBe(403);
			expect(r.userAgentBypass).toBeDefined();
			expect(r.userAgentBypass!.bypassed).toBe(true);
			expect(r.userAgentBypass!.tested).toBe(LEGIT_USER_AGENTS.length);
			expect(r.userAgentBypass!.hits.length).toBeGreaterThan(0);
			expect(r.userAgentBypass!.hits[0]).toHaveProperty('name');
			expect(r.userAgentBypass!.hits[0]).toHaveProperty('userAgent');
		}
	});

	it('does NOT flag a bypass when the WAF blocks trusted UAs too', async () => {
		// Everything is blocked regardless of User-Agent → no allow-list bypass.
		const mockFetch = vi.fn().mockResolvedValue({ status: 403, headers: new Headers() });

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
			{ fetch: mockFetch as any, quiet: true, spoofUserAgents: true },
		);

		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			expect(r.userAgentBypass).toBeDefined();
			expect(r.userAgentBypass!.bypassed).toBe(false);
			expect(r.userAgentBypass!.hits).toEqual([]);
		}
	});

	it('does NOT probe when the baseline was not blocked (200)', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ status: 200, headers: new Headers() });

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
			{ fetch: mockFetch as any, quiet: true, spoofUserAgents: true },
		);

		const baselineCalls = mockFetch.mock.calls.length;
		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			expect(r.userAgentBypass).toBeUndefined();
		}
		// No probe requests were added on top of the baseline (one call per result).
		expect(baselineCalls).toBe(results.length);
	});

	it('is disabled by default (no probing, no annotation)', async () => {
		const mockFetch = vi.fn().mockResolvedValue({ status: 403, headers: new Headers() });

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
			{ fetch: mockFetch as any, quiet: true }, // spoofUserAgents omitted
		);

		expect(results.length).toBeGreaterThan(0);
		// One request per result, no extra probe requests.
		expect(mockFetch.mock.calls.length).toBe(results.length);
		for (const r of results) {
			expect(r.userAgentBypass).toBeUndefined();
		}
	});
});
