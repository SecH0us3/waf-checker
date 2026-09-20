/**
 * Fixed-window rate limiter using KV.
 * Increments an attempt counter within a fixed expiration window.
 * If KV operations fail, logs the error and fails open to avoid blocking legitimate requests.
 */
export async function checkRateLimit(
	kv: KVNamespace | undefined,
	key: string,
	maxAttempts: number,
	windowSeconds: number
): Promise<{ allowed: boolean; remaining: number }> {
	if (!kv) return { allowed: true, remaining: maxAttempts };
	try {
		const currentVal = await kv.get(key);
		const count = currentVal ? parseInt(currentVal, 10) : 0;
		if (count >= maxAttempts) {
			return { allowed: false, remaining: 0 };
		}
		await kv.put(key, String(count + 1), { expirationTtl: windowSeconds });
		return { allowed: true, remaining: maxAttempts - (count + 1) };
	} catch (err) {
		console.error('Rate limiter KV error:', err);
		return { allowed: true, remaining: 1 };
	}
}
