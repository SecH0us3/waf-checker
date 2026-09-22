import { isValidTargetUrl, isInScopeRedirect, normalizeHostname } from '@waf-checker/core';
import { OwnershipMode } from '../types/monitor';

/**
 * A challenge file holds one token. Anything beyond this is either a
 * misconfiguration or a host trying to make the verifier buffer an unbounded
 * response, so the read stops at the cap rather than trusting Content-Length.
 */
const MAX_CHALLENGE_BYTES = 64 * 1024;

async function readCapped(resp: Response, maxBytes: number): Promise<string> {
	if (!resp.body) return '';
	const reader = resp.body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		while (total < maxBytes) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value) continue;
			chunks.push(value);
			total += value.byteLength;
		}
	} finally {
		await reader.cancel().catch(() => {});
	}

	const merged = new Uint8Array(Math.min(total, maxBytes));
	let offset = 0;
	for (const chunk of chunks) {
		if (offset >= merged.length) break;
		const slice = chunk.subarray(0, merged.length - offset);
		merged.set(slice, offset);
		offset += slice.byteLength;
	}
	return new TextDecoder().decode(merged);
}

export function extractHost(urlStr: string): string | null {
	try {
		// Same normalizer the redirect-scope check and the URL validator use, so
		// the blind index, the scope comparison and the deny-list can never
		// disagree about what host this is.
		return normalizeHostname(new URL(urlStr).hostname);
	} catch {
		return null;
	}
}

/** Canonical form of an address for keying. Addresses differing only by case
 *  are the same mailbox, and must not produce two distinct subscriptions. */
export function normalizeEmail(email: string): string {
	return email.trim().toLowerCase();
}

export function determineOwnershipMode(email: string, targetUrl: string): OwnershipMode {
	const emailDomain = normalizeEmail(email).split('@')[1];
	const targetHost = extractHost(targetUrl);
	if (!emailDomain || !targetHost) {
		return 'external';
	}
	if (targetHost === emailDomain || targetHost.endsWith('.' + emailDomain)) {
		return 'fast-track';
	}
	return 'external';
}

export async function verifyHttpOwnership(
	targetUrl: string,
	expectedToken: string,
	fetchFn: typeof fetch = globalThis.fetch
): Promise<boolean> {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 7000);

	try {
		const parsed = new URL(targetUrl);
		const challengeUrl = `${parsed.protocol}//${parsed.host}/.well-known/secmy-check.txt`;

		if (!isValidTargetUrl(challengeUrl)) {
			return false;
		}

		let currentUrl = challengeUrl;
		let resp: Response | undefined;
		const maxRedirects = 3;

		for (let hop = 0; hop <= maxRedirects; hop++) {
			resp = await fetchFn(currentUrl, {
				method: 'GET',
				signal: controller.signal,
				redirect: 'manual',
				headers: { 'User-Agent': 'secmy-verification/1.0' },
			});

			if (resp.status >= 300 && resp.status < 400) {
				if (hop === maxRedirects) {
					return false;
				}

				const location = resp.headers.get('Location');
				if (!location) {
					return false;
				}

				let nextUrl: string;
				try {
					nextUrl = new URL(location, currentUrl).href;
				} catch {
					return false;
				}

				if (!isValidTargetUrl(nextUrl) || !isInScopeRedirect(currentUrl, nextUrl)) {
					return false;
				}

				currentUrl = nextUrl;
				continue;
			}

			break;
		}

		if (!resp || resp.status !== 200) {
			return false;
		}

		const body = (await readCapped(resp, MAX_CHALLENGE_BYTES)).trim();
		const lines = body.split(/\r?\n/).map((line) => line.trim());
		return lines.includes(expectedToken.trim());
	} catch {
		return false;
	} finally {
		clearTimeout(timeout);
	}
}
