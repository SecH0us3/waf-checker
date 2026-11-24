import {
	isValidTargetUrl,
	generateSARIFReport,
	generateMultiTargetSARIFReport,
	type AuditResultItem,
	type SarifTarget,
} from '@waf-checker/core';

/**
 * POST /api/report/sarif
 *
 * Turns results the client already holds into a SARIF 2.1.0 document. Nothing
 * is fetched over the network: target URLs are only used as strings inside the
 * report, but are still validated with isValidTargetUrl like every other
 * URL-accepting endpoint.
 *
 * Body: { targetUrl?, results, reverseEngineering? }  (one run)
 *    or { targets: [{ targetUrl, results, reverseEngineering? }, ...] }  (one run per target)
 */

/** Largest accepted request body. A full single-target audit is well under 1 MB. */
export const MAX_SARIF_BODY_BYTES = 5 * 1024 * 1024;
/** Most targets in one multi-target report. */
export const MAX_SARIF_TARGETS = 100;
/** Most result items across the whole request. */
export const MAX_SARIF_RESULTS = 20000;

const JSON_HEADERS = { 'content-type': 'application/json; charset=UTF-8' };

class RequestError extends Error {
	constructor(
		readonly status: number,
		message: string,
	) {
		super(message);
	}
}

function jsonError(status: number, error: string): Response {
	return new Response(JSON.stringify({ error }), { status, headers: JSON_HEADERS });
}

/** Reads the body as text, refusing to buffer more than `limit` bytes. */
async function readBodyWithLimit(request: Request, limit: number): Promise<string> {
	const declared = request.headers.get('content-length');
	if (declared !== null) {
		const length = Number(declared);
		if (Number.isFinite(length) && length > limit) {
			throw new RequestError(413, `Request body too large (limit ${limit} bytes)`);
		}
	}
	if (!request.body) return '';

	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let received = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		received += value.byteLength;
		if (received > limit) {
			await reader.cancel().catch(() => {});
			throw new RequestError(413, `Request body too large (limit ${limit} bytes)`);
		}
		chunks.push(value);
	}
	const bytes = new Uint8Array(received);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new TextDecoder().decode(bytes);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The {PAYLOAD} placeholder is valid in scan URLs; substitute it before validating, as /api/check does. */
function validateTargetUrl(value: unknown, where: string, required: boolean): string | undefined {
	if (value === undefined || value === null || value === '') {
		if (required) throw new RequestError(400, `${where}: targetUrl is required`);
		return undefined;
	}
	if (typeof value !== 'string') throw new RequestError(400, `${where}: targetUrl must be a string`);
	if (!isValidTargetUrl(value.replace(/\{PAYLOAD\}/g, 'test-payload'))) {
		throw new RequestError(400, 'Invalid URL or restricted IP');
	}
	return value;
}

function validateBypassInfo(value: unknown, where: string): void {
	if (value === undefined || value === null) return;
	if (!isPlainObject(value)) throw new RequestError(400, `${where} must be an object`);
	if (value.bypassed && !Array.isArray(value.hits)) throw new RequestError(400, `${where}.hits must be an array`);
}

/** Checks the fields the SARIF generator dereferences, so malformed input is a 400 rather than a crash. */
function validateResults(value: unknown, where: string): AuditResultItem[] {
	if (!Array.isArray(value)) throw new RequestError(400, `${where}: results must be an array`);
	value.forEach((item, i) => {
		const at = `${where}: results[${i}]`;
		if (!isPlainObject(item)) throw new RequestError(400, `${at} must be an object`);
		if (typeof item.category !== 'string' || item.category === '') throw new RequestError(400, `${at}.category must be a non-empty string`);
		// Scan output always carries these, but tolerate their absence and only reject wrong types.
		if (item.method !== undefined && typeof item.method !== 'string') throw new RequestError(400, `${at}.method must be a string`);
		if (item.payload !== undefined && typeof item.payload !== 'string') throw new RequestError(400, `${at}.payload must be a string`);
		if (item.status !== undefined && item.status !== null && typeof item.status !== 'number' && typeof item.status !== 'string') {
			throw new RequestError(400, `${at}.status must be a number or string`);
		}
		validateBypassInfo(item.ipHeaderBypass, `${at}.ipHeaderBypass`);
		validateBypassInfo(item.userAgentBypass, `${at}.userAgentBypass`);
	});
	return value as AuditResultItem[];
}

function validateReverseEngineering(value: unknown, where: string): any {
	if (value === undefined || value === null) return undefined;
	if (!isPlainObject(value)) throw new RequestError(400, `${where}: reverseEngineering must be an object`);
	return value;
}

interface ParsedSarifRequest {
	targets: SarifTarget[];
	/** Single-target form: emit through generateSARIFReport, where targetUrl may be absent. */
	single?: { targetUrl?: string };
}

export function parseSarifRequestBody(body: unknown): ParsedSarifRequest {
	if (!isPlainObject(body)) throw new RequestError(400, 'Request body must be a JSON object');

	const hasTargets = body.targets !== undefined;
	const hasResults = body.results !== undefined;
	if (hasTargets && hasResults) throw new RequestError(400, 'Send either results or targets, not both');
	if (!hasTargets && !hasResults) throw new RequestError(400, 'Missing results array or targets array in request body');

	if (hasResults) {
		const targetUrl = validateTargetUrl(body.targetUrl, 'body', false);
		const results = validateResults(body.results, 'body');
		if (results.length > MAX_SARIF_RESULTS) throw new RequestError(400, `Too many results (limit ${MAX_SARIF_RESULTS})`);
		const reverseEngineering = validateReverseEngineering(body.reverseEngineering, 'body');
		return {
			targets: [{ targetUrl: targetUrl ?? '', results, ...(reverseEngineering ? { reverseEngineering } : {}) }],
			single: { targetUrl },
		};
	}

	if (!Array.isArray(body.targets)) throw new RequestError(400, 'targets must be an array');
	if (body.targets.length === 0) throw new RequestError(400, 'targets must not be empty');
	if (body.targets.length > MAX_SARIF_TARGETS) throw new RequestError(400, `Too many targets (limit ${MAX_SARIF_TARGETS})`);

	let total = 0;
	const targets = body.targets.map((target, i): SarifTarget => {
		const where = `targets[${i}]`;
		if (!isPlainObject(target)) throw new RequestError(400, `${where} must be an object`);
		const targetUrl = validateTargetUrl(target.targetUrl, where, true) as string;
		const results = validateResults(target.results, where);
		total += results.length;
		if (total > MAX_SARIF_RESULTS) throw new RequestError(400, `Too many results (limit ${MAX_SARIF_RESULTS})`);
		const reverseEngineering = validateReverseEngineering(target.reverseEngineering, where);
		return { targetUrl, results, ...(reverseEngineering ? { reverseEngineering } : {}) };
	});
	return { targets };
}

function hostForFilename(targets: SarifTarget[]): string {
	if (targets.length !== 1) return 'batch';
	try {
		const host = new URL(targets[0].targetUrl.replace(/\{PAYLOAD\}/g, 'payload')).hostname;
		return host.replace(/[^a-zA-Z0-9.-]/g, '_') || 'results';
	} catch {
		return 'results';
	}
}

export function sarifFilename(targets: SarifTarget[], now: Date = new Date()): string {
	const timestamp = now.toISOString().replace(/[:.]/g, '-').substring(0, 19);
	return `waf-checker_${hostForFilename(targets)}_${timestamp}.sarif`;
}

export async function handleSarifReport(request: Request): Promise<Response> {
	if (request.method !== 'POST') {
		return new Response(JSON.stringify({ error: 'Method not allowed. Use POST.' }), {
			status: 405,
			headers: { ...JSON_HEADERS, allow: 'POST' },
		});
	}

	let parsed: ParsedSarifRequest;
	try {
		const text = await readBodyWithLimit(request, MAX_SARIF_BODY_BYTES);
		let body: unknown;
		try {
			body = JSON.parse(text);
		} catch {
			throw new RequestError(400, 'Request body must be valid JSON');
		}
		parsed = parseSarifRequestBody(body);
	} catch (err) {
		if (err instanceof RequestError) return jsonError(err.status, err.message);
		return jsonError(400, 'Could not read request body');
	}

	let sarif: string;
	try {
		sarif = parsed.single
			? generateSARIFReport(parsed.targets[0].results, parsed.single.targetUrl, parsed.targets[0].reverseEngineering)
			: generateMultiTargetSARIFReport(parsed.targets);
	} catch (err) {
		console.error('SARIF generation failed:', err);
		return jsonError(500, 'Failed to generate SARIF report');
	}

	return new Response(sarif, {
		headers: {
			'content-type': 'application/sarif+json',
			'content-disposition': `attachment; filename="${sarifFilename(parsed.targets)}"`,
			'x-content-type-options': 'nosniff',
			'cache-control': 'no-store',
		},
	});
}
