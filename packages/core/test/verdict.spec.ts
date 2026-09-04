import { describe, it, expect } from 'vitest';
import { evaluateWAFVerdict, handleApiCheckWithEnvelope } from '../src/check';
import { WAFDetector, WAFDetectionResult } from '../src/waf-detection';

describe('WAF Verdict Evaluation', () => {
	it('should mark Cloudflare 403 block page as blocked', async () => {
		const headers = new Headers({
			server: 'cloudflare',
			'cf-ray': '12345678-SJC',
		});
		const mockResponse = new Response('<html><title>Attention Required! | Cloudflare</title></html>', {
			status: 403,
			headers,
		});
		const detection = await WAFDetector.detectFromResponse(
			mockResponse,
			'<html><title>Attention Required! | Cloudflare</title></html>'
		);
		const verdict = evaluateWAFVerdict(403, '<html><title>Attention Required! | Cloudflare</title></html>', detection);

		expect(verdict.blocked).toBe(true);
		expect(verdict.verdict).toBe('blocked');
	});

	it('should mark Imperva 200 interstitial page as blocked', async () => {
		const headers = new Headers({
			'set-cookie': 'nlbi_123=abc; _incap_ses_123=xyz',
		});
		const body = '<html>Incident ID: 123456789-0<br>Your request was blocked.</html>';
		const mockResponse = new Response(body, {
			status: 200,
			headers,
		});
		const detection = await WAFDetector.detectFromResponse(mockResponse, body);
		const verdict = evaluateWAFVerdict(200, body, detection);

		expect(verdict.blocked).toBe(true);
		expect(verdict.verdict).toBe('blocked');
	});

	it('should mark origin 404 Not Found as passed (not blocked, no leak)', async () => {
		const body = '404 Not Found';
		const mockResponse = new Response(body, { status: 404 });
		const detection = await WAFDetector.detectFromResponse(mockResponse, body);
		const verdict = evaluateWAFVerdict(404, body, detection);

		expect(verdict.blocked).toBe(false);
		expect(verdict.verdict).toBe('passed');
	});

	it('should mark origin 200 with real content as exposed', async () => {
		const body = '{"status": "success", "data": "sensitive config data"}';
		const mockResponse = new Response(body, { status: 200 });
		const detection = await WAFDetector.detectFromResponse(mockResponse, body);
		const verdict = evaluateWAFVerdict(200, body, detection);

		expect(verdict.blocked).toBe(false);
		expect(verdict.verdict).toBe('exposed');
	});

	it('should mark origin 200 with empty body as passed', async () => {
		const body = '   ';
		const mockResponse = new Response('', { status: 200 });
		const detection = await WAFDetector.detectFromResponse(mockResponse, '');
		const verdict = evaluateWAFVerdict(200, body, detection);

		expect(verdict.blocked).toBe(false);
		expect(verdict.verdict).toBe('passed');
	});

	it('should mark origin 500 server error as passed', async () => {
		const body = '500 Internal Server Error';
		const mockResponse = new Response(body, { status: 500 });
		const detection = await WAFDetector.detectFromResponse(mockResponse, body);
		const verdict = evaluateWAFVerdict(500, body, detection);

		expect(verdict.blocked).toBe(false);
		expect(verdict.verdict).toBe('passed');
	});

	it('should return a valid CheckResultEnvelope with total, hasMore, and verdicts in items', async () => {
		const mockFetch = async () => new Response('404 Not Found', { status: 404 });
		const envelope = await handleApiCheckWithEnvelope(
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
			{ fetch: mockFetch as any, quiet: true, pageSize: 5 }
		);

		expect(envelope).toBeDefined();
		expect(envelope.page).toBe(0);
		expect(envelope.pageSize).toBe(5);
		expect(envelope.results.length).toBe(5);
		expect(envelope.total).toBeGreaterThan(5);
		expect(envelope.hasMore).toBe(true);

		// Assert per-result verdict and blocked fields
		for (const item of envelope.results) {
			expect(item.blocked).toBe(false);
			expect(item.verdict).toBe('passed');
			expect(item.error).toBeNull();
		}
	});

	it('should not mark ordinary application status/error page mentioning incident id as blocked without WAF context', () => {
		const body = '<html><h1>Service Status</h1><p>Incident ID: INC-98765. Our team is investigating.</p></html>';
		const verdict = evaluateWAFVerdict(200, body);

		expect(verdict.blocked).toBe(false);
		expect(verdict.verdict).toBe('exposed');
	});

	describe('Domain-level detection object reuse (regression test for false-negative leaks)', () => {
		// Real evidence array returned by live service for https://x.com
		const domainDetection: WAFDetectionResult = {
			detected: true,
			wafType: 'Cloudflare',
			confidence: 100,
			evidence: [
				'Status code: 403',
				'Cookie pattern match: /__cf_bm/i',
				'Body pattern match: /attention required! | cloudflare/i',
				'Body pattern match: /Cloudflare Ray ID:/i',
			],
		};

		it('should mark genuinely leaked sensitive file (200 with content) as exposed even when domain has WAF detected', () => {
			const leakContent = 'DB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE';
			const verdict = evaluateWAFVerdict(200, leakContent, domainDetection);

			expect(verdict.blocked).toBe(false);
			expect(verdict.verdict).toBe('exposed');
		});

		it('should mark clean 404 Not Found as passed even when domain has WAF detected', () => {
			const verdict = evaluateWAFVerdict(404, '404 Not Found', domainDetection);

			expect(verdict.blocked).toBe(false);
			expect(verdict.verdict).toBe('passed');
		});

		it('should mark 403 block page as blocked when domain has WAF detected', () => {
			const blockHtml = '<html><title>Attention Required! | Cloudflare</title><body>Cloudflare Ray ID: 123456</body></html>';
			const verdict = evaluateWAFVerdict(403, blockHtml, domainDetection);

			expect(verdict.blocked).toBe(true);
			expect(verdict.verdict).toBe('blocked');
		});

		it('should not mark 400 Bad Request as blocked even when domain has WAF detected', () => {
			const verdict = evaluateWAFVerdict(400, '400 Bad Request: malformed syntax', domainDetection);

			expect(verdict.blocked).toBe(false);
			expect(verdict.verdict).toBe('passed');
		});
	});
});
