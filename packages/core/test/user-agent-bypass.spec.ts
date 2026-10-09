import { describe, it, expect, vi } from 'vitest';
import { handleApiCheckFiltered } from '../src/check';
import {
	LEGIT_USER_AGENTS,
	resolveLegitUserAgents,
	selectWorkerProbeAgents,
	WORKER_PROBE_PRIORITY,
} from '../src/payloads-data/legit-user-agents';

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

describe('selectWorkerProbeAgents', () => {
	it('spans categories instead of returning only search crawlers', () => {
		const picked = selectWorkerProbeAgents(LEGIT_USER_AGENTS);
		const names = picked.map((a) => a.name);
		// Regression guard: the worker previously probed a positional slice(0, 3),
		// which was Googlebot, Google-InspectionTool, Bingbot — all search engine
		// crawlers — so social/link-unfurler allow-list bypasses (e.g. medium.com
		// trusting Slackbot/facebookexternalhit) were never detected.
		expect(names).toContain('Googlebot');
		expect(names).toContain('Slackbot');
		expect(names).toContain('facebookexternalhit');
		expect(names).not.toContain('Google-InspectionTool');
	});

	it('orders the prioritized identities first', () => {
		const picked = selectWorkerProbeAgents(LEGIT_USER_AGENTS);
		expect(picked.map((a) => a.name)).toEqual([...WORKER_PROBE_PRIORITY]);
	});

	it('respects the limit', () => {
		expect(selectWorkerProbeAgents(LEGIT_USER_AGENTS, 2)).toHaveLength(2);
		expect(selectWorkerProbeAgents(LEGIT_USER_AGENTS, 5)).toHaveLength(5);
	});

	it('degrades gracefully for a custom list without the named identities', () => {
		const custom = [
			{ name: 'A', userAgent: 'A/1.0' },
			{ name: 'B', userAgent: 'B/1.0' },
			{ name: 'C', userAgent: 'C/1.0' },
			{ name: 'D', userAgent: 'D/1.0' },
		];
		expect(selectWorkerProbeAgents(custom)).toEqual(custom.slice(0, 3));
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
			expect(r.userAgentBypass!.tested).toBe(1);
			expect(r.userAgentBypass!.hits.length).toBeGreaterThan(0);
			expect(r.userAgentBypass!.hits[0]).toHaveProperty('name');
			expect(r.userAgentBypass!.hits[0]).toHaveProperty('userAgent');
		}
	});

	it('detects a social-bot-only bypass on the Worker (regression: slice missed it)', async () => {
		// Only Slackbot gets through — exactly the kind of allow-list a publishing
		// site (medium.com) has. The old worker code probed a positional slice that
		// never sent Slackbot, so this bypass was silently missed.
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
