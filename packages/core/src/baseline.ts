/**
 * Baseline Calibration & Structural Response Diffing
 *
 * Captures a benign reference profile of a target endpoint prior to payload
 * scanning so that:
 * 1. Endpoints that natively return 403/401/406 on benign requests (e.g. closed
 *    API endpoints requiring auth) are not falsely reported as WAF blocks when
 *    attack payloads return the exact same origin response.
 * 2. Custom soft-block pages returning 200 OK or 400 Bad Request with security
 *    rejection messaging are accurately flagged as blocked.
 */

export interface BaselineProfile {
	/** HTTP status code of the benign baseline request (e.g. 200, 403, 404, or 'ERR'). */
	status: number | string;
	/** Normalized Content-Type header (e.g. 'text/html', 'application/json'). */
	contentType: string;
	/** Length of the response body in characters. */
	bodyLength: number;
	/** Structural fingerprint of the body (stripped of dynamic timestamps/UUIDs/nonces). */
	bodySignature: string;
	/** True if the benign request itself was blocked by a recognized WAF signature/challenge. */
	wafBlockedOnBenign: boolean;
	/**
	 * True if the benign request returned 401/403/406 WITHOUT WAF block markers,
	 * indicating the origin application itself rejects unauthenticated/all requests.
	 */
	isOriginBlocked: boolean;
}

const MAX_SIGNATURE_SCAN_CHARS = 8192;

/**
 * Collapses each run of ASCII whitespace (space, \t \n \v \f \r) into one
 * space and drops leading and trailing whitespace.
 */
function collapseWhitespace(input: string): string {
	const out = input.replace(/[\t-\r ]+/g, ' ');
	const from = out.startsWith(' ') ? 1 : 0;
	const to = out.length > from && out.endsWith(' ') ? out.length - 1 : out.length;
	return from === 0 && to === out.length ? out : out.slice(from, to);
}

/**
 * Replaces every '<' and '>' with a space and drops whatever lies between a '<'
 * and the next '>'. Linear: copies runs of text as slices, not char by char.
 */
function stripHtmlTagsLinear(input: string): string {
	const parts: string[] = [];
	let inTag = false;
	let runStart = 0;
	for (let i = 0; i < input.length; i++) {
		const code = input.charCodeAt(i);
		if (code === 60 /* < */ || code === 62 /* > */) {
			if (!inTag) parts.push(input.slice(runStart, i));
			parts.push(' ');
			inTag = code === 60;
			runStart = i + 1;
		}
	}
	if (!inTag) parts.push(input.slice(runStart));
	return parts.join('');
}

/**
 * Strips volatile tokens (UUIDs, ISO dates, hex ray IDs, numbers >= 4 digits)
 * and extracts a deterministic structural fingerprint of an HTTP response body.
 */
export function computeBodySignature(bodyText: string): string {
	if (!bodyText) return 'empty:0';
	const trimmed = bodyText.slice(0, MAX_SIGNATURE_SCAN_CHARS).trim();
	if (trimmed.length === 0) return 'empty:0';

	// 1. JSON structural fingerprint: top-level keys + normalized error/code/status values
	if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
		try {
			const parsed = JSON.parse(trimmed);
			if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
				const keys = Object.keys(parsed).sort();
				const staticMarkers: string[] = [];
				for (const k of ['error', 'code', 'status', 'statusCode', 'type', 'title']) {
					if (k in parsed && (typeof parsed[k] === 'string' || typeof parsed[k] === 'number')) {
						staticMarkers.push(`${k}=${String(parsed[k]).toLowerCase().slice(0, 48)}`);
					}
				}
				return `json:${keys.join(',')}|${staticMarkers.join(';')}`;
			}
		} catch {
			// Fall through to text/HTML normalization
		}
	}

	// 2. HTML structural fingerprint: sequence of up to 24 opening tags + normalized text prefix
	const isHtml = /^(?:<!doctype\s+html|<html[\s>]|<[a-z0-9]+[\s>])/i.test(trimmed);
	const scrubDynamic = (s: string) =>
		collapseWhitespace(
			s
				// ISO timestamps
				.replace(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b/g, '<TS>')
				// UUIDs
				.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<UUID>')
				// Long hex strings (8+ chars, e.g. Ray IDs, trace IDs, hashes)
				.replace(/\b[0-9a-f]{8,64}\b/gi, '<HEX>')
				// Numbers with 4+ digits
				.replace(/\b\d{4,}\b/g, '<NUM>'),
		);

	if (isHtml) {
		const tags = (trimmed.match(/<([a-zA-Z][a-zA-Z0-9-]*)/g) || [])
			.slice(0, 24)
			.map((t) => t.slice(1).toLowerCase())
			.join('>');
		const textOnly = scrubDynamic(stripHtmlTagsLinear(trimmed))
			.toLowerCase()
			.slice(0, 120);
		return `html:${tags}|${textOnly}`;
	}

	// 3. Plain text fallback
	const normalized = scrubDynamic(trimmed).toLowerCase().slice(0, 160);
	return `text:${normalized}`;
}

/**
 * Determines whether two HTTP response bodies share the same structural signature
 * and comparable body length (within 15% or <= 64 chars difference).
 */
export function areBodiesStructurallySimilar(
	sigA: string,
	lenA: number,
	sigB: string,
	lenB: number,
): boolean {
	if (!sigA || !sigB) return false;
	if (sigA !== sigB) return false;

	const diff = Math.abs(lenA - lenB);
	if (diff <= 64) return true;
	const maxLen = Math.max(lenA, lenB, 1);
	return diff / maxLen <= 0.15;
}

const SOFT_BLOCK_PHRASES = [
	'request rejected',
	'malicious input',
	'security violation',
	'blocked by security policy',
	'security policy violation',
	'automated access is prohibited',
	'web application firewall',
];

/**
 * Checks whether a 200 OK or 400 Bad Request body that diverged from a valid
 * baseline contains explicit custom WAF / security rejection indicators.
 */
export function isSoftBlockBody(bodyText: string): boolean {
	if (!bodyText) return false;
	const normalized = collapseWhitespace(bodyText.slice(0, MAX_SIGNATURE_SCAN_CHARS).toLowerCase());
	if (normalized.length === 0) return false;

	for (const phrase of SOFT_BLOCK_PHRASES) {
		if (normalized.includes(phrase)) return true;
	}

	const supportPrefix = 'your support id is';
	const supportIdx = normalized.indexOf(supportPrefix);
	if (supportIdx !== -1) {
		const tail = normalized.slice(supportIdx + supportPrefix.length, supportIdx + supportPrefix.length + 32);
		if (/^ ?[:#]? ?\d{6}/.test(tail)) return true;
	}

	return false;
}
