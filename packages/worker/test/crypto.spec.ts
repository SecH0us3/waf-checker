import { describe, it, expect } from 'vitest';
import { encryptPayload, decryptPayload, computeBlindIndex, generateSecureToken } from '../src/utils/crypto';

describe('Crypto Service (AES-256-GCM & Blind Index)', () => {
	const secret = 'super-secret-key-for-testing-at-least-32-chars-long';

	it('encrypts and decrypts payload preserving data structure', async () => {
		const payload = { email: 'admin@example.com', target: 'https://example.com', count: 42 };
		const encrypted = await encryptPayload(payload, secret);
		expect(typeof encrypted).toBe('string');
		expect(encrypted).not.toContain('admin@example.com');

		const decrypted = await decryptPayload<typeof payload>(encrypted, secret);
		expect(decrypted).toEqual(payload);
	});

	it('produces different ciphertexts for the same plaintext due to random IV', async () => {
		const payload = { email: 'admin@example.com' };
		const enc1 = await encryptPayload(payload, secret);
		const enc2 = await encryptPayload(payload, secret);
		expect(enc1).not.toEqual(enc2);
	});

	it('fails decryption with wrong secret key', async () => {
		const encrypted = await encryptPayload({ test: 'data' }, secret);
		await expect(decryptPayload(encrypted, 'wrong-secret-key-123456789012345')).rejects.toThrow();
	});

	it('computes deterministic blind index for same normalized email', async () => {
		const idx1 = await computeBlindIndex('User@Example.COM', secret);
		const idx2 = await computeBlindIndex('user@example.com ', secret);
		expect(idx1).toEqual(idx2);
		expect(idx1.length).toBe(64); // SHA-256 hex
	});

	it('generates secure random hex token', () => {
		const token = generateSecureToken(16);
		expect(token.length).toBe(32);
	});
});
