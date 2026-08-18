import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleApiCheckFiltered } from '../src/check';

describe('Prototype Pollution WAF Bypass Integration Tests', () => {
	let mockWafType: string | null = null;

	const simulateWaf = (urlStr: string, options?: RequestInit): Response => {
		const url = new URL(urlStr);
		const params: string[] = [];

		// Extract GET search params
		for (const [key, val] of url.searchParams.entries()) {
			params.push(key);
			params.push(val);
		}

		// Extract POST/PUT body params
		if (options?.body) {
			if (typeof options.body === 'string') {
				params.push(options.body);
				try {
					const parsed = JSON.parse(options.body);
					for (const [k, v] of Object.entries(parsed)) {
						params.push(k);
						if (typeof v === 'string') params.push(v);
						else if (typeof v === 'object' && v !== null) {
							params.push(JSON.stringify(v));
						}
					}
				} catch {
					try {
						const search = new URLSearchParams(options.body);
						for (const [key, val] of search.entries()) {
							params.push(key);
							params.push(val);
						}
					} catch {}
				}
			}
		}

		let blocked = false;

		if (mockWafType) {
			for (const p of params) {
				const decoded = decodeURIComponent(p);

				switch (mockWafType.toLowerCase()) {
					case 'cloudflare':
						// Block if contains __proto__ or constructor, unless it's a bypass
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							const hasBypass =
								decoded.includes('__pr\\u006f\\u0074o__') ||
								decoded.includes('\\u005f\\u005fproto\\u005f\\u005f') ||
								decoded.includes('__pro__proto__to__') ||
								decoded.includes('const\\u0072uctor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;

					case 'aws':
					case 'aws waf':
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							const hasBypass =
								decoded.includes('__pr\\u006f\\u0074o__') ||
								decoded.includes('const\\u0072uctor[prot\\u006ftype]') ||
								decoded.includes('const\\u0072uctor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;

					case 'modsecurity':
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							const hasBypass =
								decoded.includes('__pr/**/oto__') ||
								decoded.includes('__pr/*comment*/oto__') ||
								decoded.includes('const/**/ructor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;

					case 'akamai':
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							// Akamai bypasses double URL encode characters
							const hasBypass =
								decoded.includes('%255f%255fproto%255f%255f') ||
								decoded.includes('%2563onstructor') ||
								decoded.includes('%255b') ||
								decoded.includes('%255d') ||
								// Also check literal double URL encoded forms in raw string
								p.includes('%255f%255fproto%255f%255f') ||
								p.includes('%2563onstructor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;

					case 'azure':
					case 'azure front door':
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							const hasBypass =
								decoded.includes('__PrOtO__') ||
								decoded.includes('CoNsTrUcToR') ||
								decoded.includes('__pr/**/oto__') ||
								decoded.includes('const/**/ructor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;

					case 'imperva':
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							const hasBypass =
								decoded.includes('__pr\\u006f\\u0074o__') ||
								decoded.includes('%5f%5fproto%5f%5f') ||
								p.includes('%5f%5fproto%5f%5f') ||
								decoded.includes('const\\u0072uctor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;

					case 'f5':
					case 'f5 big-ip':
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							const hasBypass =
								decoded.includes('__PrOtO__') ||
								decoded.includes('__pr/**/oto__') ||
								decoded.includes('CoNsTrUcToR') ||
								decoded.includes('const/**/ructor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;

					case 'google':
					case 'google cloud armor':
						if (/__proto__/i.test(decoded) || /constructor/i.test(decoded)) {
							const hasBypass =
								decoded.includes('__pr\\u006f\\u0074o__') ||
								decoded.includes('%255f%255fproto%255f%255f') ||
								p.includes('%255f%255fproto%255f%255f') ||
								decoded.includes('const\\u0072uctor') ||
								decoded.includes('%2563onstructor') ||
								p.includes('%2563onstructor');
							if (!hasBypass) {
								blocked = true;
							}
						}
						break;
				}
			}
		}

		if (blocked) {
			const headers = new Headers();
			if (mockWafType?.toLowerCase() === 'cloudflare') {
				headers.set('server', 'cloudflare');
				headers.set('cf-ray', '1234567890abcdef-IAD');
			} else if (mockWafType?.toLowerCase() === 'aws waf') {
				headers.set('server', 'awselb/2.0');
			} else if (mockWafType?.toLowerCase() === 'akamai') {
				headers.set('server', 'AkamaiGHost');
			} else if (mockWafType?.toLowerCase() === 'azure front door') {
				headers.set('x-azure-ref', 'azure-ref-123');
			} else if (mockWafType?.toLowerCase() === 'imperva') {
				headers.set('x-cdn', 'Incapsula');
			} else if (mockWafType?.toLowerCase() === 'f5 big-ip') {
				headers.set('server', 'BIG-IP');
			} else if (mockWafType?.toLowerCase() === 'google cloud armor') {
				headers.set('server', 'GSE');
			}
			return new Response('Blocked by WAF', { status: 403, headers });
		}

		return new Response('OK', { status: 200 });
	};

	beforeEach(() => {
		mockWafType = null;
		vi.restoreAllMocks();
	});

	it('should bypass Cloudflare Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'cloudflare';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		// 1. Without bypass: standard payload is blocked
		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		// 2. With Cloudflare bypass
		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'Cloudflare'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should bypass AWS WAF Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'aws waf';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'AWS WAF'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should bypass ModSecurity Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'modsecurity';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'ModSecurity'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should bypass Akamai Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'akamai';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'Akamai'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should bypass Azure Front Door Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'azure front door';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'Azure Front Door'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should support JSON Body prototype pollution checks', async () => {
		mockWafType = 'cloudflare';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['POST'],
			['Prototype Pollution (JSON Body)'],
			'{"test": "{PAYLOAD}"}',
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '{"__proto__":{"polluted":true}}');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['POST'],
			['Prototype Pollution (JSON Body)'],
			'{"test": "{PAYLOAD}"}',
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'Cloudflare'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should bypass Imperva Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'imperva';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'Imperva'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should bypass F5 BIG-IP Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'f5 big-ip';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'F5 BIG-IP'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});

	it('should bypass Google Cloud Armor Prototype Pollution rules when WAF is specified', async () => {
		mockWafType = 'google cloud armor';
		const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
			return simulateWaf(url.toString(), options);
		});

		const resultsBlocked = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			undefined
		);
		expect(resultsBlocked.length).toBeGreaterThan(0);
		const standardBlocked = resultsBlocked.find(r => r.payload === '__proto__[polluted]=true');
		expect(standardBlocked).toBeDefined();
		expect(standardBlocked!.status).toBe(403);

		const resultsBypassed = await handleApiCheckFiltered(
			'https://example.com/api/check',
			0,
			['GET'],
			['Prototype Pollution (URL/Param)'],
			undefined,
			false,
			undefined,
			false,
			false,
			false,
			false,
			false,
			false,
			'Google Cloud Armor'
		);
		expect(resultsBypassed.length).toBeGreaterThan(0);
		const successes = resultsBypassed.filter(r => r.status === 200);
		expect(successes.length).toBeGreaterThan(0);

		fetchSpy.mockRestore();
	});
});
