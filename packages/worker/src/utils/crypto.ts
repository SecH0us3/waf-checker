function getSubtleCrypto(): SubtleCrypto {
	return crypto.subtle;
}

async function deriveKey(secretKey: string): Promise<CryptoKey> {
	const enc = new TextEncoder();
	const keyMaterial = await getSubtleCrypto().digest('SHA-256', enc.encode(secretKey));
	return getSubtleCrypto().importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function encryptPayload(data: unknown, secretKey: string): Promise<string> {
	const key = await deriveKey(secretKey);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const encodedData = new TextEncoder().encode(JSON.stringify(data));

	const ciphertext = await getSubtleCrypto().encrypt({ name: 'AES-GCM', iv }, key, encodedData);

	const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
	combined.set(iv, 0);
	combined.set(new Uint8Array(ciphertext), iv.byteLength);

	let binary = '';
	for (let i = 0; i < combined.length; i++) {
		binary += String.fromCharCode(combined[i]);
	}
	return btoa(binary);
}

export async function decryptPayload<T>(encryptedBase64: string, secretKey: string): Promise<T> {
	const key = await deriveKey(secretKey);
	const binary = atob(encryptedBase64);
	const combined = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		combined[i] = binary.charCodeAt(i);
	}

	if (combined.byteLength < 12) {
		throw new Error('Invalid ciphertext payload');
	}

	const iv = combined.slice(0, 12);
	const ciphertext = combined.slice(12);

	const decryptedBuffer = await getSubtleCrypto().decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
	const jsonStr = new TextDecoder().decode(decryptedBuffer);
	return JSON.parse(jsonStr) as T;
}

export async function computeBlindIndex(input: string, secretKey: string): Promise<string> {
	const normalized = input.trim().toLowerCase();
	const enc = new TextEncoder();
	const key = await getSubtleCrypto().importKey('raw', enc.encode(secretKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signature = await getSubtleCrypto().sign('HMAC', key, enc.encode(normalized));
	const hashArray = Array.from(new Uint8Array(signature));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function generateSecureToken(byteLength: number = 24): string {
	const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}
