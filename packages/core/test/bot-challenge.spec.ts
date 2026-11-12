import { describe, it, expect } from 'vitest';
import { detectBotChallenge, evaluateWAFVerdict } from '../src/check';
import { calculateAuditStats, AuditResultItem } from '../src/reports/types';
import { WAFDetector } from '../src/waf-detection';

describe('detectBotChallenge', () => {
	describe('high-confidence response headers', () => {
		it('flags a Cloudflare JS challenge via cf-mitigated: challenge', () => {
			const headers = new Headers({ 'cf-mitigated': 'challenge' });
			const res = detectBotChallenge(403, '', headers);
			expect(res.isChallenge).toBe(true);
			expect(res.vendor).toBe('Cloudflare');
			expect(res.mechanism).toBe('js');
		});

		it('does NOT flag cf-mitigated: block as a challenge (that is a hard block)', () => {
			const headers = new Headers({ 'cf-mitigated': 'block' });
			expect(detectBotChallenge(403, '', headers).isChallenge).toBe(false);
		});

		it('flags DataDome via x-datadome header', () => {
			const headers = new Headers({ 'x-datadome': 'protected' });
			const res = detectBotChallenge(403, '', headers);
			expect(res.isChallenge).toBe(true);
			expect(res.vendor).toBe('DataDome');
		});

		it('flags Kasada via x-kpsdk-ct header', () => {
			const headers = new Headers({ 'x-kpsdk-ct': 'abc' });
			const res = detectBotChallenge(429, '', headers);
			expect(res.isChallenge).toBe(true);
			expect(res.vendor).toBe('Kasada');
		});

		it('flags Vercel via x-vercel-mitigated: challenge header', () => {
			const headers = new Headers({ 'x-vercel-mitigated': 'challenge' });
			const res = detectBotChallenge(403, '', headers);
			expect(res.isChallenge).toBe(true);
			expect(res.vendor).toBe('Vercel');
		});
	});

	describe('Set-Cookie markers', () => {
		it('flags DataDome via datadome cookie', () => {
			const headers = new Headers({ 'set-cookie': 'datadome=xyz; Path=/; Secure' });
			expect(detectBotChallenge(403, '', headers).vendor).toBe('DataDome');
		});

		it('flags HUMAN/PerimeterX via _pxvid cookie', () => {
			const headers = new Headers({ 'set-cookie': '_pxvid=abc123; Path=/' });
			expect(detectBotChallenge(403, '', headers).vendor).toBe('HUMAN (PerimeterX)');
		});

		it('flags Vercel via _vcrcs cookie', () => {
			const headers = new Headers({ 'set-cookie': '_vcrcs=1; Path=/' });
			expect(detectBotChallenge(403, '', headers).vendor).toBe('Vercel');
		});
	});

	describe('body fingerprints', () => {
		it('flags a Cloudflare JS interstitial body', () => {
			const body = '<html><head><title>Just a moment...</title></head><body><div id="cf-chl"></div><script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script></body></html>';
			const res = detectBotChallenge(403, body);
			expect(res.isChallenge).toBe(true);
			expect(res.vendor).toBe('Cloudflare');
		});

		it('flags a PerimeterX Press & Hold body', () => {
			const body = '<html><body>Please verify you are a human: <div id="px-captcha"></div> Press & Hold</body></html>';
			expect(detectBotChallenge(200, body).vendor).toBe('HUMAN (PerimeterX)');
		});

		it('flags an Arkose Labs / FunCaptcha body', () => {
			const body = '<html><script src="https://client-api.arkoselabs.com/v2/api.js"></script></html>';
			expect(detectBotChallenge(403, body).vendor).toBe('Arkose Labs');
		});

		it('flags a DataDome captcha-delivery body', () => {
			const body = '<html><script src="https://geo.captcha-delivery.com/captcha/"></script></html>';
			expect(detectBotChallenge(403, body).vendor).toBe('DataDome');
		});

		it('returns isChallenge:false for a benign page with no challenge markers', () => {
			const body = '<html><body><h1>Welcome</h1><p>Nothing to see here.</p></body></html>';
			expect(detectBotChallenge(200, body).isChallenge).toBe(false);
		});

		it('does not flag benign documentation mentions of captcha hosts', () => {
			const body = '<html><body>Visit hcaptcha.com or google.com/recaptcha documentation.</body></html>';
			expect(detectBotChallenge(200, body).isChallenge).toBe(false);
		});
	});
});

describe('evaluateWAFVerdict — challenge verdict', () => {
	it('returns verdict "challenge" (blocked:true) for a cf-mitigated challenge header', () => {
		const headers = new Headers({ 'cf-mitigated': 'challenge' });
		const v = evaluateWAFVerdict(403, '', undefined, headers);
		expect(v.verdict).toBe('challenge');
		expect(v.blocked).toBe(true);
	});

	it('returns verdict "challenge" for a DataDome header even on a 200 response', () => {
		const headers = new Headers({ 'x-datadome': 'protected' });
		const v = evaluateWAFVerdict(200, '', undefined, headers);
		expect(v.verdict).toBe('challenge');
		expect(v.blocked).toBe(true);
	});

	it('still returns a plain "blocked" verdict for a hard 403 without challenge markers', () => {
		const v = evaluateWAFVerdict(403, 'Forbidden', undefined, new Headers({ server: 'cloudflare' }));
		expect(v.verdict).toBe('blocked');
	});
});

describe('calculateAuditStats — challenged count', () => {
	it('counts a challenge toward blocked/protectionScore and tracks it separately', () => {
		const results: AuditResultItem[] = [
			{ category: 'XSS', payload: '<script>', method: 'GET', status: 403, responseTime: 1, blocked: true, verdict: 'blocked' },
			{ category: 'SQLi', payload: "' OR 1=1", method: 'GET', status: 403, responseTime: 1, blocked: true, verdict: 'challenge' },
			{ category: 'LFI', payload: '../../etc/passwd', method: 'GET', status: 200, responseTime: 1, blocked: false, verdict: 'exposed' },
		];
		const stats = calculateAuditStats(results, 'https://example.com');
		expect(stats.total).toBe(3);
		expect(stats.blocked).toBe(2); // hard block + challenge both protect
		expect(stats.challenged).toBe(1);
		expect(stats.bypassed).toBe(1); // the exposed (200) leak
		expect(stats.protectionScore).toBe(67); // 2/3
	});
});

describe('WAFDetector — new bot-management vendors', () => {
	function mockResponse(status: number, headers: Record<string, string>): Response {
		const lower: Record<string, string> = {};
		for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
		return {
			status,
			headers: { get: (name: string) => lower[name.toLowerCase()] ?? null },
		} as unknown as Response;
	}

	it('detects DataDome with 100% confidence via the definitive x-datadome header', async () => {
		const result = await WAFDetector.detectFromResponse(mockResponse(403, { 'x-datadome': 'protected' }));
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('DataDome');
		expect(result.confidence).toBe(100);
	});

	it('detects Kasada via the definitive x-kpsdk-ct header', async () => {
		const result = await WAFDetector.detectFromResponse(mockResponse(429, { 'x-kpsdk-ct': 'abc' }));
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('Kasada');
	});

	it('detects HUMAN (PerimeterX) via x-px header, status, and cookie', async () => {
		const result = await WAFDetector.detectFromResponse(
			mockResponse(403, { 'x-px': 'block', 'set-cookie': '_pxhd=foo; Path=/' }),
		);
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('HUMAN (PerimeterX)');
		expect(result.confidence).toBeGreaterThan(40);
	});

	it('detects Vercel via x-vercel-id on a 403', async () => {
		const result = await WAFDetector.detectFromResponse(mockResponse(403, { 'x-vercel-id': 'iad::abc' }));
		expect(result.detected).toBe(true);
		expect(result.wafType).toBe('Vercel');
	});
});
