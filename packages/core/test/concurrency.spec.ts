import { describe, it, expect } from 'vitest';
import { mapWithConcurrency } from '../src/utils/concurrency';

describe('Order-Preserving Concurrency Pool (concurrency.ts)', () => {
	it('returns empty array when given empty input', async () => {
		const res = await mapWithConcurrency([], 4, async (x) => x);
		expect(res).toEqual([]);
	});

	it('preserves deterministic input order even when tasks resolve out of order', async () => {
		const delays = [40, 10, 30, 5, 20];
		const out = await mapWithConcurrency(delays, 3, async (ms, idx) => {
			await new Promise((r) => setTimeout(r, ms));
			return `item-${idx}-${ms}`;
		});

		expect(out).toEqual([
			'item-0-40',
			'item-1-10',
			'item-2-30',
			'item-3-5',
			'item-4-20',
		]);
	});

	it('never exceeds the configured concurrency limit', async () => {
		let inFlight = 0;
		let maxObserved = 0;
		const items = Array.from({ length: 16 }, (_, i) => i);

		await mapWithConcurrency(items, 4, async (item) => {
			inFlight++;
			if (inFlight > maxObserved) maxObserved = inFlight;
			await new Promise((r) => setTimeout(r, 8));
			inFlight--;
			return item * 2;
		});

		expect(maxObserved).toBeLessThanOrEqual(4);
		expect(maxObserved).toBeGreaterThanOrEqual(2);
	});

	it('dynamically steps down concurrency when rate-limiting (429) is detected', async () => {
		let inFlight = 0;
		const inFlightAfterRateLimit: number[] = [];
		let rateLimitTriggered = false;
		const items = Array.from({ length: 12 }, (_, i) => i);

		const results = await mapWithConcurrency(
			items,
			{
				concurrency: 4,
				isRateLimited: (res) => res.status === 429,
				backoffMs: 5,
			},
			async (idx) => {
				inFlight++;
				if (rateLimitTriggered) {
					inFlightAfterRateLimit.push(inFlight);
				}
				await new Promise((r) => setTimeout(r, 6));
				inFlight--;
				if (idx === 1) {
					rateLimitTriggered = true;
					return { idx, status: 429 };
				}
				return { idx, status: 200 };
			},
		);

		expect(results).toHaveLength(12);
		expect(results.map((r) => r.idx)).toEqual(items);
		// Once 429 occurs on idx 1, effective concurrency steps down from 4 -> 2
		expect(Math.max(...inFlightAfterRateLimit)).toBeLessThanOrEqual(3);
	});
});
