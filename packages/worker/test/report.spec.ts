import { SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { handleSarifReport, sarifFilename, MAX_SARIF_BODY_BYTES, MAX_SARIF_TARGETS } from '../src/handlers/report';

const ENDPOINT = 'https://example.com/api/report/sarif';

const bypass = { category: 'SQL Injection', payload: "' OR 1=1 --", method: 'GET', status: 200, responseTime: 12 };
const blocked = { category: 'XSS', payload: '<script>alert(1)</script>', method: 'GET', status: 403, responseTime: 8, blocked: true };

function post(body: unknown, init: RequestInit = {}) {
	return SELF.fetch(ENDPOINT, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: typeof body === 'string' ? body : JSON.stringify(body),
		...init,
	});
}

/** Minimal structural check of a SARIF 2.1.0 log. */
function expectSarif210(doc: any, runCount: number) {
	expect(doc.version).toBe('2.1.0');
	expect(doc.$schema).toMatch(/sarif-schema-2\.1\.0\.json$/);
	expect(Array.isArray(doc.runs)).toBe(true);
	expect(doc.runs).toHaveLength(runCount);
	for (const run of doc.runs) {
		expect(typeof run.tool?.driver?.name).toBe('string');
		expect(Array.isArray(run.tool.driver.rules)).toBe(true);
		expect(Array.isArray(run.results)).toBe(true);
		for (const result of run.results) {
			expect(typeof result.ruleId).toBe('string');
			expect(typeof result.message?.text).toBe('string');
			expect(run.tool.driver.rules[result.ruleIndex]?.id).toBe(result.ruleId);
		}
	}
}

describe('POST /api/report/sarif', () => {
	it('returns a single-run SARIF document for { targetUrl, results }', async () => {
		const response = await post({ targetUrl: 'https://target.example.com/app', results: [bypass, blocked] });
		expect(response.status).toBe(200);
		expect(response.headers.get('content-type')).toBe('application/sarif+json');
		expect(response.headers.get('content-disposition')).toMatch(
			/^attachment; filename="waf-checker_target\.example\.com_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.sarif"$/,
		);

		const doc: any = JSON.parse(await response.text());
		expectSarif210(doc, 1);
		// Only the unblocked 200 is a finding.
		expect(doc.runs[0].results).toHaveLength(1);
		expect(doc.runs[0].results[0].properties.payload).toBe(bypass.payload);
		expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('https://target.example.com/app');
	});

	it('accepts results without targetUrl and passes reverseEngineering through', async () => {
		const reverseEngineering = { bodyLimit: { maxBytes: 8192 } };
		const response = await post({ results: [bypass], reverseEngineering });
		expect(response.status).toBe(200);
		expect(response.headers.get('content-disposition')).toContain('waf-checker_results_');
		const doc: any = await response.json();
		expectSarif210(doc, 1);
		expect(doc.runs[0].properties?.reverseEngineering).toEqual(reverseEngineering);
	});

	it('returns one run per target for { targets }', async () => {
		const response = await post({
			targets: [
				{ targetUrl: 'https://a.example.com', results: [bypass, blocked] },
				{ targetUrl: 'https://b.example.com', results: [blocked] },
				{ targetUrl: 'https://c.example.com', results: [] },
			],
		});
		expect(response.status).toBe(200);
		expect(response.headers.get('content-type')).toBe('application/sarif+json');
		expect(response.headers.get('content-disposition')).toContain('waf-checker_batch_');

		const doc: any = await response.json();
		expectSarif210(doc, 3);
		expect(doc.runs.map((r: any) => r.results.length)).toEqual([1, 0, 0]);
		expect(doc.runs.map((r: any) => r.automationDetails?.id)).toEqual([
			'waf-checker/a.example.com/',
			'waf-checker/b.example.com/',
			'waf-checker/c.example.com/',
		]);
	});

	it('uses the supplied scan times for the invocation', async () => {
		const single = await post({
			targetUrl: 'https://a.example.com',
			results: [bypass],
			startTimeUtc: '2026-11-24T10:00:00.000Z',
			endTimeUtc: '2026-11-24T10:05:00.000Z',
		});
		expect(single.status).toBe(200);
		const singleDoc: any = await single.json();
		expect(singleDoc.runs[0].invocations[0].startTimeUtc).toBe('2026-11-24T10:00:00.000Z');
		expect(singleDoc.runs[0].invocations[0].endTimeUtc).toBe('2026-11-24T10:05:00.000Z');

		const multi = await post({
			targets: [
				{ targetUrl: 'https://a.example.com', results: [], startTimeUtc: '2026-11-24T10:00:00.000Z', endTimeUtc: '2026-11-24T10:01:00.000Z' },
				{ targetUrl: 'https://b.example.com', results: [], startTimeUtc: '2026-11-24T10:02:00.000Z', endTimeUtc: '2026-11-24T10:03:00.000Z' },
			],
		});
		expect(multi.status).toBe(200);
		const multiDoc: any = await multi.json();
		expect(multiDoc.runs.map((r: any) => [r.invocations[0].startTimeUtc, r.invocations[0].endTimeUtc])).toEqual([
			['2026-11-24T10:00:00.000Z', '2026-11-24T10:01:00.000Z'],
			['2026-11-24T10:02:00.000Z', '2026-11-24T10:03:00.000Z'],
		]);
	});

	it('names a one-target multi report after its host', async () => {
		const response = await post({ targets: [{ targetUrl: 'https://only.example.com', results: [bypass] }] });
		expect(response.status).toBe(200);
		expect(response.headers.get('content-disposition')).toContain('waf-checker_only.example.com_');
	});

	it('accepts {PAYLOAD} templates in targetUrl', async () => {
		const response = await post({ targetUrl: 'https://{PAYLOAD}.example.com/', results: [bypass] });
		expect(response.status).toBe(200);
	});

	describe('rejects restricted or invalid target URLs', () => {
		for (const targetUrl of ['http://127.0.0.1:8080', 'http://169.254.169.254/latest/meta-data', 'http://localhost/', 'not a url', 'file:///etc/passwd']) {
			it(`single: ${targetUrl}`, async () => {
				const response = await post({ targetUrl, results: [bypass] });
				expect(response.status).toBe(400);
				expect(((await response.json()) as any).error).toBe('Invalid URL or restricted IP');
			});
		}

		it('multi: any restricted target fails the whole request', async () => {
			const response = await post({
				targets: [
					{ targetUrl: 'https://a.example.com', results: [bypass] },
					{ targetUrl: 'http://10.0.0.1/', results: [bypass] },
				],
			});
			expect(response.status).toBe(400);
			expect(((await response.json()) as any).error).toBe('Invalid URL or restricted IP');
		});

		it('multi: targetUrl is required', async () => {
			const response = await post({ targets: [{ results: [bypass] }] });
			expect(response.status).toBe(400);
		});
	});

	describe('rejects malformed bodies with 400', () => {
		const cases: Array<[string, unknown]> = [
			['invalid JSON', '{"results": ['],
			['non-object body', '[1,2,3]'],
			['neither results nor targets', { targetUrl: 'https://a.example.com' }],
			['both results and targets', { results: [bypass], targets: [] }],
			['results not an array', { results: { 0: bypass } }],
			['result item not an object', { results: ['x'] }],
			['result item missing category', { results: [{ ...bypass, category: undefined }] }],
			['result item with numeric payload', { results: [{ ...bypass, payload: 1 }] }],
			['result item with object status', { results: [{ ...bypass, status: {} }] }],
			['bypass info without hits', { results: [{ ...bypass, ipHeaderBypass: { bypassed: true } }] }],
			['targetUrl not a string', { targetUrl: 42, results: [bypass] }],
			['reverseEngineering not an object', { results: [bypass], reverseEngineering: 'x' }],
			['unparseable startTimeUtc', { results: [bypass], startTimeUtc: 'yesterday-ish' }],
			['numeric endTimeUtc', { results: [bypass], endTimeUtc: 1700000000000 }],
			['start after end', { results: [bypass], startTimeUtc: '2026-11-24T11:00:00Z', endTimeUtc: '2026-11-24T10:00:00Z' }],
			['bad per-target time', { targets: [{ targetUrl: 'https://a.example.com', results: [], startTimeUtc: 'nope' }] }],
			['targets not an array', { targets: {} }],
			['empty targets', { targets: [] }],
			['target not an object', { targets: ['https://a.example.com'] }],
			['target results not an array', { targets: [{ targetUrl: 'https://a.example.com', results: 'x' }] }],
		];
		for (const [name, body] of cases) {
			it(name, async () => {
				const response = await post(body);
				expect(response.status).toBe(400);
				expect(typeof ((await response.json()) as any).error).toBe('string');
			});
		}

		it(`more than ${MAX_SARIF_TARGETS} targets`, async () => {
			const targets = Array.from({ length: MAX_SARIF_TARGETS + 1 }, (_, i) => ({ targetUrl: `https://t${i}.example.com`, results: [] }));
			const response = await post({ targets });
			expect(response.status).toBe(400);
			expect(((await response.json()) as any).error).toContain('Too many targets');
		});
	});

	it('returns 413 when the body exceeds the size limit', async () => {
		const huge = 'A'.repeat(MAX_SARIF_BODY_BYTES);
		const response = await post({ results: [{ ...bypass, payload: huge }] });
		expect(response.status).toBe(413);
		expect(((await response.json()) as any).error).toContain('too large');
	});

	it('returns 413 for an oversized streamed body without content-length', async () => {
		const chunk = new Uint8Array(1024 * 1024).fill(0x20);
		let sent = 0;
		const stream = new ReadableStream<Uint8Array>({
			pull(controller) {
				if (sent > MAX_SARIF_BODY_BYTES) return controller.close();
				sent += chunk.byteLength;
				controller.enqueue(chunk);
			},
		});
		const request = new Request(ENDPOINT, { method: 'POST', body: stream, duplex: 'half' } as RequestInit);
		expect(request.headers.get('content-length')).toBeNull();
		const response = await handleSarifReport(request);
		expect(response.status).toBe(413);
	});

	it('returns 405 for GET', async () => {
		const response = await SELF.fetch(ENDPOINT);
		expect(response.status).toBe(405);
		expect(response.headers.get('allow')).toBe('POST');
	});

	it('builds sanitised file names', () => {
		const now = new Date('2026-11-24T10:20:30.456Z');
		expect(sarifFilename([{ targetUrl: 'https://x.example.com:8443/a', results: [] }], now)).toBe(
			'waf-checker_x.example.com_2026-11-24T10-20-30.sarif',
		);
		expect(sarifFilename([{ targetUrl: 'garbage', results: [] }], now)).toBe('waf-checker_results_2026-11-24T10-20-30.sarif');
		expect(
			sarifFilename(
				[
					{ targetUrl: 'https://a.example.com', results: [] },
					{ targetUrl: 'https://b.example.com', results: [] },
				],
				now,
			),
		).toBe('waf-checker_batch_2026-11-24T10-20-30.sarif');
	});
});
