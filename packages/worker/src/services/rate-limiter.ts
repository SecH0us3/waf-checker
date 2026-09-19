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
	} catch {
		return { allowed: true, remaining: 1 };
	}
}
