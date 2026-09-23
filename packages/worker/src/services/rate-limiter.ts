interface WindowState {
	count: number;
	windowStart: number;
}

/**
 * Fixed-window rate limiter backed by KV.
 *
 * The window start is stored alongside the counter and the TTL is derived from
 * it, so the window expires at a fixed time instead of being pushed forward by
 * every increment — refreshing the TTL on each write turned the documented
 * one-hour window into one that slid forward with traffic and locked callers out
 * for longer than intended.
 *
 * Known limitation, accepted deliberately: the read-then-write is not atomic, so
 * concurrent requests can read the same count and all pass. This is a throttle
 * against bulk abuse, not a hard security barrier. On any KV error it fails open,
 * because losing storage should not take subscriptions offline.
 */
export async function checkRateLimit(
	kv: KVNamespace | undefined,
	key: string,
	maxAttempts: number,
	windowSeconds: number
): Promise<{ allowed: boolean; remaining: number }> {
	if (!kv) return { allowed: true, remaining: maxAttempts };
	try {
		const now = Date.now();
		const raw = await kv.get(key);

		let state: WindowState = { count: 0, windowStart: now };
		if (raw) {
			try {
				const parsed = JSON.parse(raw) as WindowState;
				if (typeof parsed?.count === 'number' && typeof parsed?.windowStart === 'number') {
					state = parsed;
				}
			} catch {
				// Legacy plain-counter value: start a fresh window rather than guess.
			}
		}

		const elapsedSeconds = (now - state.windowStart) / 1000;
		if (elapsedSeconds >= windowSeconds) {
			state = { count: 0, windowStart: now };
		}

		if (state.count >= maxAttempts) {
			return { allowed: false, remaining: 0 };
		}

		const remainingWindow = Math.ceil(windowSeconds - (now - state.windowStart) / 1000);
		await kv.put(key, JSON.stringify({ count: state.count + 1, windowStart: state.windowStart }), {
			// KV enforces a 60s floor on expirationTtl.
			expirationTtl: Math.max(60, remainingWindow),
		});

		return { allowed: true, remaining: maxAttempts - (state.count + 1) };
	} catch (err) {
		console.error('Rate limiter KV error:', err);
		return { allowed: true, remaining: 1 };
	}
}
