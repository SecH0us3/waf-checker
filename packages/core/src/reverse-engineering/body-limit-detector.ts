import { BodyLimitResult, ReverseEngineeringOptions } from './types';
import { sendRequest } from '../check';
import { classifyProbe } from './probe-outcome';

function formatBytes(bytes: number): string {
	if (bytes >= 1024 * 1024) {
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}
	if (bytes >= 1024) {
		return `${Math.round(bytes / 1024)} KB`;
	}
	return `${bytes} B`;
}

// A rate-limited or failed probe tells us nothing about inspection depth. Stop
// rather than guess: counting it as a bypass invented a limit, and counting it
// as blocked hid a real one.
const INCONCLUSIVE: BodyLimitResult = {
	detected: false,
	limitBytes: null,
	limitFormatted: 'Inconclusive (probes were rate limited or failed)',
	confidence: 0,
};

/**
 * Detects the WAF request body inspection size boundary using binary search probing.
 * Probes between 8KB and 128KB to find where the WAF stops scanning incoming payload bodies.
 */
export async function detectBodyInspectionLimit(
	url: string,
	options?: ReverseEngineeringOptions,
): Promise<BodyLimitResult> {
	const attackPayload = "' OR '1'='1";

	// 1. Baseline check without padding: verify WAF blocks this attack payload.
	// Sent raw like the padded probes below, so all of them carry the attack in
	// the same encoding (without rawPayload it went out wrapped in `test=` and
	// encoded a second time).
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
		{ fetch: options?.fetch, quiet: true, rawPayload: true, allowLocal: options?.allowLocal },
	);

	const baseline = classifyProbe(baselineRes);
	if (baseline === 'inconclusive') {
		return INCONCLUSIVE;
	}
	if (baseline === 'passed') {
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
			{ fetch: options?.fetch, quiet: true, allowLocal: options?.allowLocal },
		);

		const outcome = classifyProbe(res);
		if (outcome === 'inconclusive') {
			return INCONCLUSIVE;
		}
		if (outcome === 'passed') {
			upperBypassed = size;
			break;
		}
		lowerBlocked = size;
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
			{ fetch: options?.fetch, quiet: true, allowLocal: options?.allowLocal },
		);

		const outcome = classifyProbe(res);
		if (outcome === 'inconclusive') {
			return INCONCLUSIVE;
		}
		if (outcome === 'passed') {
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
