import { RateLimitResult, ReverseEngineeringOptions } from './types';
import { sendRequest } from '../check';

/**
 * Safely probes for WAF Rate Limiting / DoS protection thresholds using a gradual ramp-up.
 * Tests at 5, 10, 20, up to 30 req/s with immediate early termination upon encountering HTTP 429.
 */
export async function probeRateLimit(
	url: string,
	options?: ReverseEngineeringOptions,
): Promise<RateLimitResult> {
	const maxProbeRps = options?.maxRpsProbe || 30;
	const stages = [5, 10, 20, 30].filter((rps) => rps <= maxProbeRps);

	let detectedRps: number | null = null;
	let retryAfterSec: number | null = null;
	let lastCompletedRps = 0;

	for (const rps of stages) {
		const requestPromises = Array.from({ length: rps }).map((_, i) =>
			sendRequest(
				url,
				'GET',
				`ratelimit_test_seq_${i}`,
				undefined,
				undefined,
				false,
				false,
				undefined,
				undefined,
				{ fetch: options?.fetch, quiet: true },
			),
		);

		const results = await Promise.all(requestPromises);
		const rateLimited = results.find((r) => r && (r.status === 429 || r.status === '429'));

		if (rateLimited) {
			detectedRps = rps;
			if (rateLimited.response && rateLimited.response.headers) {
				const retryHeader = rateLimited.response.headers.get('retry-after');
				if (retryHeader) {
					if (/^\d+$/.test(retryHeader)) {
						retryAfterSec = parseInt(retryHeader, 10);
					}
				}
			}
			break;
		}

		lastCompletedRps = rps;

		// Gentle cooldown between stages
		await new Promise((resolve) => setTimeout(resolve, 200));
	}

	return {
		detected: detectedRps !== null,
		thresholdRps: detectedRps,
		retryAfterSeconds: retryAfterSec,
		safeTestedMaxRps: detectedRps !== null ? detectedRps : lastCompletedRps,
	};
}
