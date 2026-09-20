import { isValidTargetUrl, isInScopeRedirect } from '@waf-checker/core';
import { OwnershipMode } from '../types/monitor';

export function extractHost(urlStr: string): string | null {
	try {
		return new URL(urlStr).hostname.toLowerCase();
	} catch {
		return null;
	}
}

export function determineOwnershipMode(email: string, targetUrl: string): OwnershipMode {
	const emailDomain = email.split('@')[1]?.toLowerCase().trim();
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

		const body = (await resp.text()).trim();
		const lines = body.split(/\r?\n/).map((line) => line.trim());
		return lines.includes(expectedToken.trim());
	} catch {
		return false;
	} finally {
		clearTimeout(timeout);
	}
}
