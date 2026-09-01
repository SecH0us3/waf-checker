import { BodyLimitResult, ReverseEngineeringOptions } from './types';
import { sendRequest } from '../check';

function formatBytes(bytes: number): string {
	if (bytes >= 1024 * 1024) {
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}
	if (bytes >= 1024) {
		return `${Math.round(bytes / 1024)} KB`;
	}
	return `${bytes} B`;
}

/**
 * Detects the WAF request body inspection size boundary using binary search probing.
 * Probes between 8KB and 128KB to find where the WAF stops scanning incoming payload bodies.
 */
export async function detectBodyInspectionLimit(
	url: string,
	options?: ReverseEngineeringOptions,
): Promise<BodyLimitResult> {
	const attackPayload = "' OR '1'='1";

	// 1. Baseline check without padding: verify WAF blocks this attack payload
	const baselineRes = await sendRequest(
		url,
		'POST',
		`attack=${encodeURIComponent(attackPayload)}`,
		undefined,
		undefined,
		false,
		false,
		undefined,
		undefined,
		{ fetch: options?.fetch, quiet: true },
	);

	if (!baselineRes || baselineRes.status !== 403) {
		return {
			detected: false,
			limitBytes: null,
			limitFormatted: 'N/A (Baseline Attack Not Blocked)',
			confidence: 0,
		};
	}

	// 2. Coarse grid probing across standard WAF buffer limits
	const bounds = [8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024, 128 * 1024];
	let lowerBlocked = 0;
	let upperBypassed = -1;

	for (const size of bounds) {
		const paddedBody = `junk=${'a'.repeat(size)}&attack=${encodeURIComponent(attackPayload)}`;
		const res = await sendRequest(
			url,
			'POST',
			paddedBody,
			undefined,
			undefined,
			false,
			false,
			undefined,
			undefined,
			{ fetch: options?.fetch, quiet: true },
		);

		if (res && res.status !== 403 && res.status !== 'ERR' && res.status !== 'BLOCKED') {
			upperBypassed = size;
			break;
		} else {
			lowerBlocked = size;
		}
	}

	// If even 128KB is blocked, WAF inspects beyond our maximum probe limit
	if (upperBypassed === -1) {
		return {
			detected: false,
			limitBytes: null,
			limitFormatted: '> 128 KB (Strict Full Inspection)',
			confidence: 90,
		};
	}

	// 3. Binary search between [lowerBlocked, upperBypassed] to narrow down to ~1KB resolution
	let low = lowerBlocked;
	let high = upperBypassed;
	const precision = 1024; // 1 KB

	while (high - low > precision) {
		const mid = Math.floor((low + high) / 2);
		const paddedBody = `junk=${'a'.repeat(mid)}&attack=${encodeURIComponent(attackPayload)}`;
		const res = await sendRequest(
			url,
			'POST',
			paddedBody,
			undefined,
			undefined,
			false,
			false,
			undefined,
			undefined,
			{ fetch: options?.fetch, quiet: true },
		);

		if (res && res.status !== 403 && res.status !== 'ERR' && res.status !== 'BLOCKED') {
			high = mid; // Bypassed, limit is at or below mid
		} else {
			low = mid; // Still blocked, limit is above mid
		}
	}

	const exactLimitBytes = high;

	return {
		detected: true,
		limitBytes: exactLimitBytes,
		limitFormatted: formatBytes(exactLimitBytes),
		confidence: 95,
		bypassPayloadSize: exactLimitBytes + attackPayload.length + 10,
	};
}
