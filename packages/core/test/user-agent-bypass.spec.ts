import { describe, it, expect, vi } from 'vitest';
import {
	handleApiCheckFiltered,
	handleApiCheckWithEnvelope,
	maxWorkerPageSize,
	UA_PROBE_CONCURRENCY,
	MAX_REDIRECTS,
	WORKER_SUBREQUEST_LIMIT,
} from '../src/check';
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
			// The first identity gets through, so it is the only probe sent.
			expect(r.userAgentBypass!.tested).toBe(1);
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

	it.each([
		{ description: 'FileCheck (Sensitive Files)', category: 'Sensitive Files', shouldProbe: true },
		{ description: 'Header checks (IP Bypass)', category: 'IP Bypass', shouldProbe: true },
		{ description: 'User-Agent category exclusion', category: 'User-Agent', shouldProbe: false },
	])('probes User-Agent bypass appropriately for $description', async ({ category, shouldProbe }) => {
		const mockFetch = vi.fn().mockImplementation((_url: string, options: any) => {
			const ua = readUserAgent(options);
			const status = ua === 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)' ? 200 : 403;
			return Promise.resolve({ status, headers: new Headers() });
		});

		const results = await handleApiCheckFiltered(
			'http://example.com/api',
			0,
			['GET'],
			[category],
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
			{ fetch: mockFetch as any, quiet: true, spoofUserAgents: true, isWorker: true, pageSize: 5 },
		);

		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			if (shouldProbe) {
				expect(r.userAgentBypass).toBeDefined();
				expect(r.userAgentBypass!.bypassed).toBe(true);
				expect(r.userAgentBypass!.hits.map((h) => h.name)).toContain('Slackbot');
			} else {
				// Category is User-Agent itself: must not overwrite attack header with legit bot probes
				expect(r.userAgentBypass).toBeUndefined();
			}
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
	const blocked403 = () => Promise.resolve({ status: 403, headers: new Headers() });

	// A network error or timeout says nothing about the WAF trusting the UA.
	it('does NOT report a bypass when trusted-UA probes fail with a network error', async () => {
		const mockFetch = vi.fn().mockImplementation((_url: string, options: any) => {
			const ua = readUserAgent(options);
			return ua && TRUSTED.test(ua) ? Promise.reject(new Error('connection reset')) : blocked403();
		});

		const results = await scanSqli(mockFetch);

		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			expect(r.userAgentBypass!.bypassed).toBe(false);
			expect(r.userAgentBypass!.hits).toEqual([]);
			expect(r.userAgentBypass!.tested).toBe(LEGIT_USER_AGENTS.length);
		}
	});

	// Blocked with a normal UA, but under a trusted UA the WAF let the request
	// through, whatever the origin then answered: that is the bypass.
	it.each([
		['a 500 from a payload that broke a query', 500],
		['a 404 for a path the origin does not have', 404],
		['a 401 from the origin', 401],
		['a redirect from the origin', 302],
	])('reports a bypass when the trusted UA gets %s', async (_label, status) => {
		const mockFetch = vi.fn().mockImplementation((_url: string, options: any) => {
			const ua = readUserAgent(options);
			return ua && TRUSTED.test(ua) ? Promise.resolve({ status, headers: new Headers({ Location: '/login' }) }) : blocked403();
		});

		const results = await scanSqli(mockFetch);

		expect(results.length).toBeGreaterThan(0);
		for (const r of results) {
			expect(r.userAgentBypass!.bypassed).toBe(true);
			expect(r.userAgentBypass!.hits[0].status).toBe(status);
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

	it('starts no new probes once one identity got through', async () => {
		// Only the 8th identity is trusted. Probes already in flight finish, but the
		// pool must not keep going through the rest of the list.
		const trusted = LEGIT_USER_AGENTS[7].userAgent;
		const mockFetch = vi.fn().mockImplementation(async (_url: string, options: any) => {
			const ua = readUserAgent(options);
			await new Promise((resolve) => setTimeout(resolve, 1));
			return { status: ua === trusted ? 200 : 403, headers: new Headers() };
		});

		const results = await scanSqli(mockFetch);

		for (const r of results) {
			expect(r.userAgentBypass!.bypassed).toBe(true);
			expect(r.userAgentBypass!.hits.map((h) => h.name)).toContain(LEGIT_USER_AGENTS[7].name);
			expect(r.userAgentBypass!.tested).toBeLessThanOrEqual(8 + UA_PROBE_CONCURRENCY - 1);
			expect(r.userAgentBypass!.tested).toBeLessThan(LEGIT_USER_AGENTS.length);
		}
	});
});

describe('Worker page size', () => {
	const worstCase = (pageSize: number, legitUserAgentCount: number, followRedirect: boolean) =>
		pageSize * (1 + legitUserAgentCount) * (followRedirect ? MAX_REDIRECTS + 1 : 1);

	it('fits the full trusted-UA list at 50 per page even with redirects', () => {
		expect(maxWorkerPageSize({ legitUserAgentCount: LEGIT_USER_AGENTS.length, followRedirect: true })).toBeGreaterThanOrEqual(50);
	});

	it('stays within the subrequest budget for any identity count', () => {
		for (const legitUserAgentCount of [0, LEGIT_USER_AGENTS.length, 40, 5000]) {
			for (const followRedirect of [false, true]) {
				const size = maxWorkerPageSize({ legitUserAgentCount, followRedirect });
				expect(size).toBeGreaterThanOrEqual(1);
				if (size > 1) expect(worstCase(size, legitUserAgentCount, followRedirect)).toBeLessThanOrEqual(WORKER_SUBREQUEST_LIMIT);
			}
		}
	});

	const envelope = (pageSize: number | undefined, spoofUserAgents: any, followRedirect: boolean, isWorker = true) =>
		handleApiCheckWithEnvelope(
			'http://example.com/api',
			0,
			['GET'],
			['SQL Injection'],
			undefined,
			followRedirect,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined,
			undefined,
			{ fetch: vi.fn().mockResolvedValue({ status: 200, headers: new Headers() }) as any, quiet: true, isWorker, pageSize, spoofUserAgents },
		);

	it('clamps an oversized Worker page in core, using the scan’s own identity list', async () => {
		// A custom list longer than the curated one must shrink the page accordingly.
		const custom = Array.from({ length: 200 }, (_, i) => ({ name: `Bot${i}`, userAgent: `Bot${i}/1.0` }));
		const env = await envelope(100000, custom, true);
		expect(env.pageSize).toBe(maxWorkerPageSize({ legitUserAgentCount: 200, followRedirect: true }));
		expect(worstCase(env.pageSize, 200, true)).toBeLessThanOrEqual(WORKER_SUBREQUEST_LIMIT);
	});

	it('keeps a valid requested Worker page and falls back to 50 for an invalid one', async () => {
		expect((await envelope(5, true, false)).pageSize).toBe(5);
		expect((await envelope(NaN, true, false)).pageSize).toBe(50);
		expect((await envelope(-5, true, false)).pageSize).toBe(50);
		expect((await envelope(undefined, true, false)).pageSize).toBe(50);
	});

	it('does not clamp outside the Worker', async () => {
		expect((await envelope(100000, true, true, false)).pageSize).toBe(100000);
	});
});
