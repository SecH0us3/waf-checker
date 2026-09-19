import { isValidTargetUrl } from '@waf-checker/core';
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
	try {
		const parsed = new URL(targetUrl);
		const challengeUrl = `${parsed.protocol}//${parsed.host}/.well-known/secmy-check.txt`;

		if (!isValidTargetUrl(challengeUrl)) {
			return false;
		}

		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 7000);

		const resp = await fetchFn(challengeUrl, {
			method: 'GET',
			signal: controller.signal,
			redirect: 'follow',
			headers: { 'User-Agent': 'secmy-verification/1.0' },
		});
		clearTimeout(timeout);

		if (resp.status !== 200) {
			return false;
		}

		const body = (await resp.text()).trim();
		const lines = body.split(/\r?\n/).map((line) => line.trim());
		return lines.includes(expectedToken.trim());
	} catch {
		return false;
	}
}
