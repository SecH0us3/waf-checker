import { describe, it, expect, vi } from 'vitest';
import { handleApiCheckFiltered, resolveWorkerPageSize, UA_PROBE_CONCURRENCY, MAX_REDIRECTS, WORKER_SUBREQUEST_LIMIT } from '../src/check';
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
			// The first concurrent batch all passes, so probing stops after it.
			expect(r.userAgentBypass!.tested).toBe(UA_PROBE_CONCURRENCY);
			expect(r.userAgentBypass!.hits[0].name).toBe('Googlebot');
			expect(r.userAgentBypass!.hits[0]).toHaveProperty('name');
			expect(r.userAgentBypass!.hits[0]).toHaveProperty('userAgent');
		}
	});

	it('probes the full identity list on the Worker (regression: a slice capped it to search crawlers)', async () => {
		// Only Slackbot gets through — exactly the kind of allow-list a publishing
		// site (medium.com) has. A previous worker-only optimisation probed just the
		// first few identities (all search crawlers), so this social-unfurler bypass
		// was silently missed. With the paid-plan subrequest budget the worker now
		// probes the whole list, same as the CLI.
		const mockFetch = vi.fn().mockImplementation((_url: string, options: any) => {
			const ua = readUserAgent(options);
			const status = ua === 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)' ? 200 : 403;
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
			{ fetch: mockFetch as any, quiet: true, spoofUserAgents: true, isWorker: true },
		);

		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			expect(r.userAgentBypass).toBeDefined();
			expect(r.userAgentBypass!.bypassed).toBe(true);
			expect(r.userAgentBypass!.hits.map((h) => h.name)).toContain('Slackbot');
		}
	});

	it('does NOT cap the probed identities on the Worker when nothing bypasses', async () => {
		// Everything stays blocked, so the probe exhausts the list. isWorker must not
		// shrink the set of identities tried — all of them are probed, as on the CLI.
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
			{ fetch: mockFetch as any, quiet: true, spoofUserAgents: true, isWorker: true },
		);

		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			expect(r.userAgentBypass!.bypassed).toBe(false);
			expect(r.userAgentBypass!.tested).toBe(LEGIT_USER_AGENTS.length);
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
			expect(r.userAgentBypass!.tested).toBe(LEGIT_USER_AGENTS.length);
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

function scanSqli(mockFetch: any, extra: Record<string, unknown> = {}) {
	return handleApiCheckFiltered(
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
		{ fetch: mockFetch as any, quiet: true, spoofUserAgents: true, ...extra },
	);
}

describe('User-Agent bypass probe verdicts', () => {
	// A trusted UA that does not get a 2xx has not reached the origin, so it is
	// not a bypass — regardless of whether the response is a WAF block.
	it.each([
		['a network error', () => Promise.reject(new Error('connection reset'))],
		['a 503 from an overloaded origin', () => Promise.resolve({ status: 503, headers: new Headers() })],
		['a 404', () => Promise.resolve({ status: 404, headers: new Headers() })],
		['an unfollowed redirect', () => Promise.resolve({ status: 302, headers: new Headers({ Location: '/login' }) })],
	])('does NOT report a bypass for %s under a trusted UA', async (_label, probeResponse) => {
		const mockFetch = vi.fn().mockImplementation((_url: string, options: any) => {
			const ua = readUserAgent(options);
			return ua && TRUSTED.test(ua) ? probeResponse() : Promise.resolve({ status: 403, headers: new Headers() });
		});

		const results = await scanSqli(mockFetch);

		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			expect(r.userAgentBypass!.bypassed).toBe(false);
			expect(r.userAgentBypass!.hits).toEqual([]);
			expect(r.userAgentBypass!.tested).toBe(LEGIT_USER_AGENTS.length);
		}
	});

	it('probes identities concurrently, but never more than UA_PROBE_CONCURRENCY at once', async () => {
		let inFlight = 0;
		let peak = 0;
		const mockFetch = vi.fn().mockImplementation(async (_url: string, options: any) => {
			const ua = readUserAgent(options);
			if (!ua || !TRUSTED.test(ua)) return { status: 403, headers: new Headers() };
			inFlight++;
			peak = Math.max(peak, inFlight);
			await new Promise((resolve) => setTimeout(resolve, 1));
			inFlight--;
			return { status: 403, headers: new Headers() };
		});

		await scanSqli(mockFetch);

		expect(peak).toBe(UA_PROBE_CONCURRENCY);
	});
});

describe('resolveWorkerPageSize', () => {
	const worstCase = (pageSize: number, legitUserAgentCount: number, followRedirect: boolean) =>
		pageSize * (1 + legitUserAgentCount) * (followRedirect ? MAX_REDIRECTS + 1 : 1);

	it('keeps the default page of 50 when the full trusted-UA list fits the budget', () => {
		expect(resolveWorkerPageSize(undefined, { legitUserAgentCount: LEGIT_USER_AGENTS.length, followRedirect: false })).toBe(50);
	});

	it('shrinks the page when redirects multiply every request', () => {
		const size = resolveWorkerPageSize(50, { legitUserAgentCount: LEGIT_USER_AGENTS.length, followRedirect: true });
		expect(size).toBeLessThan(50);
		expect(worstCase(size, LEGIT_USER_AGENTS.length, true)).toBeLessThanOrEqual(WORKER_SUBREQUEST_LIMIT);
	});

	it('clamps an oversized pageSize from the query string', () => {
		const size = resolveWorkerPageSize(1000, { legitUserAgentCount: LEGIT_USER_AGENTS.length, followRedirect: false });
		expect(worstCase(size, LEGIT_USER_AGENTS.length, false)).toBeLessThanOrEqual(WORKER_SUBREQUEST_LIMIT);
	});

	it('falls back to the default for a missing, invalid or non-positive pageSize', () => {
		const opts = { legitUserAgentCount: 0, followRedirect: false };
		expect(resolveWorkerPageSize(undefined, opts)).toBe(50);
		expect(resolveWorkerPageSize(NaN, opts)).toBe(50);
		expect(resolveWorkerPageSize(0, opts)).toBe(50);
		expect(resolveWorkerPageSize(-5, opts)).toBe(50);
		expect(resolveWorkerPageSize(5, opts)).toBe(5);
	});

	it('stays within budget for any page size and identity count, including a grown list', () => {
		for (const legitUserAgentCount of [0, LEGIT_USER_AGENTS.length, 40]) {
			for (const followRedirect of [false, true]) {
				for (const requested of [1, 15, 50, 500, 100000]) {
					const size = resolveWorkerPageSize(requested, { legitUserAgentCount, followRedirect });
					expect(size).toBeGreaterThanOrEqual(1);
					expect(worstCase(size, legitUserAgentCount, followRedirect)).toBeLessThanOrEqual(WORKER_SUBREQUEST_LIMIT);
				}
			}
		}
	});
});
