import { describe, it, expect, vi } from 'vitest';
import {
	computeBodySignature,
	areBodiesStructurallySimilar,
	isSoftBlockBody,
	BaselineProfile,
} from '../src/baseline';
import {
	evaluateWAFVerdict,
	captureBaseline,
	handleApiCheckWithEnvelope,
} from '../src/check';

describe('Baseline Calibration & Structural Diffing (baseline.ts)', () => {
	describe('computeBodySignature', () => {
		it('produces identical signatures for JSON responses differing only in requestId or timestamp', () => {
			const body1 = JSON.stringify({
				error: 'Forbidden',
				message: 'Authentication token is missing',
				requestId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
				timestamp: '2026-10-17T23:50:01.123Z',
			});
			const body2 = JSON.stringify({
				error: 'Forbidden',
				message: 'Authentication token is missing',
				requestId: '99887766-5544-3322-1100-aabbccddeeff',
				timestamp: '2026-10-17T23:55:59.999Z',
			});

			expect(computeBodySignature(body1)).toBe(computeBodySignature(body2));
		});

		it('produces identical signatures for HTML pages differing only in dynamic nonces or numbers', () => {
			const html1 = '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><div class="err">Access Denied (Ray: 89abcdef12345678)</div></body></html>';
			const html2 = '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><div class="err">Access Denied (Ray: 1122334455667788)</div></body></html>';

			expect(computeBodySignature(html1)).toBe(computeBodySignature(html2));
		});

		it('produces distinct signatures for structurally different HTML documents', () => {
			const normalPage = '<!DOCTYPE html><html><body><main><article><h1>Welcome to our store</h1><p>Catalog items here</p></article></main></body></html>';
			const blockPage = '<!DOCTYPE html><html><body><div class="waf-error"><h1>Request Rejected</h1><p>Security policy violation</p></div></body></html>';

			expect(computeBodySignature(normalPage)).not.toBe(computeBodySignature(blockPage));
		});
	});

	describe('areBodiesStructurallySimilar', () => {
		it('returns true when signatures match and lengths are within 15%', () => {
			const bodyA = '{"status":"error","code":403,"message":"Unauthorized access to endpoint","trace":"123456"}';
			const bodyB = '{"status":"error","code":403,"message":"Unauthorized access to endpoint","trace":"987654"}';
			const sigA = computeBodySignature(bodyA);
			const sigB = computeBodySignature(bodyB);

			expect(areBodiesStructurallySimilar(sigA, bodyA.length, sigB, bodyB.length)).toBe(true);
		});

		it('returns false when signatures differ or lengths diverge significantly', () => {
			const bodyA = '<html><body><h1>Home</h1><p>' + 'welcome '.repeat(200) + '</p></body></html>';
			const bodyB = '<html><body><h1>Blocked</h1></body></html>';
			const sigA = computeBodySignature(bodyA);
			const sigB = computeBodySignature(bodyB);

			expect(areBodiesStructurallySimilar(sigA, bodyA.length, sigB, bodyB.length)).toBe(false);
		});
	});

	describe('isSoftBlockBody', () => {
		it('detects common custom soft-block phrases in 200/400 responses', () => {
			expect(isSoftBlockBody('<html><body><h1>Request Rejected</h1><p>Your support ID is: 1234567890</p></body></html>')).toBe(true);
			expect(isSoftBlockBody('{"error": "Blocked by security policy", "code": "SEC_VIOLATION"}')).toBe(true);
			expect(isSoftBlockBody('Malicious input detected by application firewall')).toBe(true);
		});

		it('does not flag normal application pages or generic 404/validation messages', () => {
			expect(isSoftBlockBody('<html><body><h1>Welcome to Example</h1><p>Browse our products</p></body></html>')).toBe(false);
			expect(isSoftBlockBody('{"items": [], "total": 0}')).toBe(false);
		});

		it('processes adversarial inputs with repeated "<" or whitespace in linear time without ReDoS', () => {
			const start = Date.now();
			const pathologicalHtml = '<html>' + '<'.repeat(50_000);
			const pathologicalSupport = 'your support id is' + ' '.repeat(50_000) + '!';

			expect(computeBodySignature(pathologicalHtml)).toMatch(/^html:html\|/);
			expect(isSoftBlockBody(pathologicalSupport)).toBe(false);
			expect(Date.now() - start).toBeLessThan(200);
		});
	});

	describe('evaluateWAFVerdict with BaselineProfile', () => {
		it('disambiguates Origin-403 from WAF-403 when benign baseline is already an identical 403', () => {
			const origin403Body = '{"error":"Forbidden","message":"Missing API key","requestId":"11111111"}';
			const baseline: BaselineProfile = {
				status: 403,
				contentType: 'application/json',
				bodyLength: origin403Body.length,
				bodySignature: computeBodySignature(origin403Body),
				wafBlockedOnBenign: false,
				isOriginBlocked: true,
			};

			const attackRespBody = '{"error":"Forbidden","message":"Missing API key","requestId":"22222222"}';
			const res = evaluateWAFVerdict(403, attackRespBody, undefined, new Headers(), "' OR 1=1--", baseline);

			expect(res.blocked).toBe(false);
			expect(res.verdict).toBe('passed');
			expect(res.baselineNote).toBe('origin_blocked');
		});

		it('still reports a real WAF block (403) when WAF headers or block body differ from Origin-403 baseline', () => {
			const origin403Body = '{"error":"Forbidden","message":"Missing API key"}';
			const baseline: BaselineProfile = {
				status: 403,
				contentType: 'application/json',
				bodyLength: origin403Body.length,
				bodySignature: computeBodySignature(origin403Body),
				wafBlockedOnBenign: false,
				isOriginBlocked: true,
			};

			// Case 1: Cloudflare header present
			const cfHeaders = new Headers({ 'cf-mitigated': 'block' });
			const res1 = evaluateWAFVerdict(403, origin403Body, undefined, cfHeaders, "' OR 1=1--", baseline);
			expect(res1.blocked).toBe(true);
			expect(res1.verdict).toBe('blocked');

			// Case 2: Different WAF HTML block page returned instead of JSON auth error
			const wafHtml = '<html><body><h1>403 Forbidden</h1><p>Request blocked by Web Application Firewall</p></body></html>';
			const res2 = evaluateWAFVerdict(403, wafHtml, undefined, new Headers(), "' OR 1=1--", baseline);
			expect(res2.blocked).toBe(true);
			expect(res2.verdict).toBe('blocked');
		});

		it('detects custom soft-block page (200 OK) when body diverges from 200 baseline and contains security block indicators', () => {
			const normalHtml = '<!DOCTYPE html><html><body><main><h1>Search Results</h1><p>No items matched your query.</p></main></body></html>';
			const baseline: BaselineProfile = {
				status: 200,
				contentType: 'text/html',
				bodyLength: normalHtml.length,
				bodySignature: computeBodySignature(normalHtml),
				wafBlockedOnBenign: false,
				isOriginBlocked: false,
			};

			const softBlockHtml = '<!DOCTYPE html><html><body><div class="alert"><h1>Request Rejected</h1><p>Blocked by security policy. Your support ID is: 987654321</p></div></body></html>';
			const res = evaluateWAFVerdict(200, softBlockHtml, undefined, new Headers(), '<script>alert(1)</script>', baseline);

			expect(res.blocked).toBe(true);
			expect(res.verdict).toBe('blocked');
			expect(res.baselineNote).toBe('custom_block_page');
		});
	});

	describe('captureBaseline & handleApiCheckWithEnvelope integration', () => {
		it('captures baseline once and attaches it to CheckResultEnvelope when calibrateBaseline is enabled', async () => {
			const originAuthBody = '{"error":"Forbidden","message":"Bearer token required"}';
			const mockFetch = vi.fn().mockImplementation(async () => ({
				status: 403,
				headers: new Headers({ 'content-type': 'application/json' }),
				text: async () => originAuthBody,
			}));

			const envelope = await handleApiCheckWithEnvelope(
				'http://example.com/api/private',
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
				{
					fetch: mockFetch as any,
					quiet: true,
					pageSize: 3,
					calibrateBaseline: true,
				},
			);

			expect(envelope.baseline).toBeDefined();
			expect(envelope.baseline!.isOriginBlocked).toBe(true);
			expect(envelope.results).toHaveLength(3);
			for (const r of envelope.results) {
				expect(r.status).toBe(403);
				expect(r.blocked).toBe(false);
				expect(r.verdict).toBe('passed');
				expect(r.baselineNote).toBe('origin_blocked');
			}
		});
	});
});
