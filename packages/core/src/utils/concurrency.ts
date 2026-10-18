/**
 * Deterministic, Order-Preserving Concurrency Pool with Adaptive Rate-Limit Backoff.
 *
 * Used by the core scan loop to execute HTTP probes in parallel up to a safe
 * ceiling (e.g. 4 on Cloudflare Workers, configurable in CLI) while guaranteeing
 * that `results[i]` always corresponds to `items[i]`.
 *
 * When a rate-limit response (429) is observed via `isRateLimited`, active worker
 * lanes above the stepped-down target gracefully park or exit, preventing
 * cascading 429 floods against the target.
 */

export interface ConcurrencyPoolOptions<R = any> {
	/** Maximum number of tasks in flight simultaneously (clamped >= 1). */
	concurrency: number;
	/** Optional predicate invoked on each result to detect rate-limiting (e.g. status === 429). */
	isRateLimited?: (result: R) => boolean;
	/** Optional pause in ms when rate-limiting is detected (default: 0). */
	backoffMs?: number;
}

export async function mapWithConcurrency<T, R>(
	items: T[],
	concurrencyOrOptions: number | ConcurrencyPoolOptions<R>,
	worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
	if (items.length === 0) return [];

	const opts: ConcurrencyPoolOptions<R> =
		typeof concurrencyOrOptions === 'number'
			? { concurrency: concurrencyOrOptions }
			: concurrencyOrOptions;

	const initialConcurrency = Math.max(1, Math.floor(opts.concurrency || 1));
	let maxAllowedLanes = initialConcurrency;
	const backoffMs = opts.backoffMs && opts.backoffMs > 0 ? opts.backoffMs : 0;

	const results: R[] = new Array(items.length);
	let nextIndex = 0;

	const runLane = async (laneId: number) => {
		while (nextIndex < items.length) {
			// If adaptive throttling stepped down concurrency below this lane's ID,
			// retire this lane (lane 0 always stays active so progress is guaranteed).
			if (laneId > 0 && laneId >= maxAllowedLanes) {
				return;
			}

			const currentIdx = nextIndex++;
			if (currentIdx >= items.length) return;

			const res = await worker(items[currentIdx], currentIdx);
			results[currentIdx] = res;

			if (opts.isRateLimited && opts.isRateLimited(res)) {
				maxAllowedLanes = Math.max(1, Math.floor(maxAllowedLanes / 2));
				if (backoffMs > 0) {
					await new Promise((resolve) => setTimeout(resolve, backoffMs));
				}
			}
		}
	};

	const poolSize = Math.min(initialConcurrency, items.length);
	await Promise.all(Array.from({ length: poolSize }, (_, laneId) => runLane(laneId)));

	return results;
}
