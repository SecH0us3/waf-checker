import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
	handleScheduleSubscribe,
	handleScheduleVerify,
	handleScheduleUnsubscribe,
	handleScheduledCron,
} from '../src/handlers/schedule';
import { WorkerEnv, SubscriptionRecord } from '../types/monitor';
import { decryptPayload } from '../src/utils/crypto';

let originalFetch: typeof globalThis.fetch;

/** Stands in for the Turnstile siteverify endpoint so handlers can run the real
 *  captcha path instead of the (now refused) unconfigured one. */
function stubTurnstile() {
	originalFetch = globalThis.fetch;
	globalThis.fetch = vi.fn(async (input: any) => {
		const url = typeof input === 'string' ? input : input?.url || '';
		if (url.includes('challenges.cloudflare.com')) {
			return new Response(JSON.stringify({ success: true }), {
				status: 200,
				headers: { 'content-type': 'application/json' },
			});
		}
		return new Response('', { status: 404 });
	}) as any;
}

function restoreFetch() {
	if (originalFetch) globalThis.fetch = originalFetch;
}

// In-memory KV mock
function createMockKV() {
	const store = new Map<string, string>();
	return {
		store,
		async get(key: string) {
			return store.get(key) ?? null;
		},
		async put(key: string, value: string) {
			store.set(key, value);
		},
		async delete(key: string) {
			store.delete(key);
		},
		async list(options?: { prefix?: string }) {
			const prefix = options?.prefix || '';
			const keys = Array.from(store.keys())
				.filter((k) => k.startsWith(prefix))
				.map((name) => ({ name }));
			return { keys, list_complete: true, cursor: '' };
		},
	} as unknown as KVNamespace & { store: Map<string, string> };
}

describe('Schedule Handlers & Cron Execution', () => {
	let mockKV: ReturnType<typeof createMockKV>;
	let mockSendEmail: ReturnType<typeof vi.fn>;
	let env: WorkerEnv;
	const secret = 'test-secret-key-32-characters-minimum';

	beforeEach(() => {
		mockKV = createMockKV();
		mockSendEmail = vi.fn().mockResolvedValue(undefined);
		env = {
			ASSETS: { fetch: vi.fn() },
			MONITOR_KV: mockKV,
			SEND_EMAIL: { send: mockSendEmail },
			EMAIL_ENCRYPTION_KEY: secret,
			TURNSTILE_SECRET_KEY: 'turnstile-test-secret',
		};
		stubTurnstile();
	});

	afterEach(() => {
		restoreFetch();
	});

	it('rejects subscription for self-host secmy.app (SSRF / self-scan protection)', async () => {
		const req = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'admin@secmy.app', targetUrl: 'https://secmy.app' }),
		});
		const res = await handleScheduleSubscribe(req, env);
		expect(res.status).toBe(422);
		const json = (await res.json()) as any;
		expect(json.code).toBe('SELF_SCAN_REFUSED');
	});

	it('rejects invalid or localhost target URL (SSRF protection)', async () => {
		const req = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'admin@example.com', targetUrl: 'http://127.0.0.1:8080' }),
		});
		const res = await handleScheduleSubscribe(req, env);
		expect(res.status).toBe(400);
	});

	it('creates fast-track pending subscription and dispatches verification email', async () => {
		const req = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const res = await handleScheduleSubscribe(req, env);
		expect(res.status).toBe(200);
		const json = (await res.json()) as any;
		expect(json.success).toBe(true);
		expect(json.mode).toBe('fast-track');

		// Verification email should have been sent
		expect(mockSendEmail).toHaveBeenCalledWith(
			expect.objectContaining({
				to: 'security@example.com',
				from: 'waf@secmy.app',
			})
		);

		// KV should contain encrypted pending record
		const pendingKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('pending:'));
		expect(pendingKeys.length).toBe(1);
		expect(json.devVerifyUrl).toBeUndefined();
	});

	it('does not leak devVerifyUrl in production even if SEND_EMAIL is missing', async () => {
		const envNoEmail: WorkerEnv = { ...env, SEND_EMAIL: undefined };
		const req = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const res = await handleScheduleSubscribe(req, envNoEmail);
		const json = (await res.json()) as any;
		expect(json.devVerifyUrl).toBeUndefined();
	});

	it('returns devVerifyUrl only for DEV_MODE, never for a loopback Host header', async () => {
		// The request hostname comes from the client-supplied Host header on
		// Workers, so a loopback-looking host must not unlock the dev-only link.
		const localReq = new Request('http://localhost:8787/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const localRes = await handleScheduleSubscribe(localReq, env);
		const localJson = (await localRes.json()) as any;
		expect(localJson.devVerifyUrl).toBeUndefined();

		const devModeEnv: WorkerEnv = { ...env, DEV_MODE: 'true' };
		const prodReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const devModeRes = await handleScheduleSubscribe(prodReq, devModeEnv);
		const devModeJson = (await devModeRes.json()) as any;
		expect(devModeJson.devVerifyUrl).toBeDefined();
	});

	it('handles email dispatch failure by cleaning up pending record and returning 500', async () => {
		mockSendEmail.mockRejectedValueOnce(new Error('SMTP connection timed out'));
		const req = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const res = await handleScheduleSubscribe(req, env);
		expect(res.status).toBe(500);
		const json = (await res.json()) as any;
		expect(json.error).toContain('Failed to dispatch verification email');

		// KV should NOT keep pending or pendingIdx record
		const pendingKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('pending:') || k.startsWith('pendingIdx:'));
		expect(pendingKeys.length).toBe(0);
	});

	it('verifies fast-track subscription and activates it', async () => {
		// Subscribe first
		const subReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		await handleScheduleSubscribe(subReq, env);

		const pendingKey = Array.from(mockKV.store.keys()).find((k) => k.startsWith('pending:'))!;
		const token = pendingKey.replace('pending:', '');

		// Call verify
		const verifyReq = new Request(`https://secmy.app/api/schedule/verify?token=${token}`);
		const verifyRes = await handleScheduleVerify(verifyReq, env);
		expect(verifyRes.status).toBe(200);

		// Pending key removed, active key created
		expect(mockKV.store.has(pendingKey)).toBe(false);
		const activeKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('active:'));
		expect(activeKeys.length).toBe(1);

		// Check encrypted data
		const encryptedVal = mockKV.store.get(activeKeys[0])!;
		const decrypted = await decryptPayload<SubscriptionRecord>(encryptedVal, secret);
		expect(decrypted.email).toBe('security@example.com');
		expect(decrypted.targetUrl).toBe('https://example.com');
		expect(decrypted.status).toBe('ACTIVE');
	});

	it('unsubscribes active subscription', async () => {
		// Subscribe and activate
		const subReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		await handleScheduleSubscribe(subReq, env);
		const pendingKey = Array.from(mockKV.store.keys()).find((k) => k.startsWith('pending:'))!;
		const token = pendingKey.replace('pending:', '');
		await handleScheduleVerify(new Request(`https://secmy.app/api/schedule/verify?token=${token}`), env);

		const activeKey = Array.from(mockKV.store.keys()).find((k) => k.startsWith('active:'))!;
		const manageToken = activeKey.replace('active:', '');

		// Unsubscribe
		const unsubReq = new Request(`https://secmy.app/api/schedule/unsubscribe?token=${manageToken}`, {
			method: 'POST',
		});
		const unsubRes = await handleScheduleUnsubscribe(unsubReq, env);
		expect(unsubRes.status).toBe(200);
		expect(mockKV.store.has(activeKey)).toBe(false);

		// Blind index should also be cleaned up
		const blindKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('blind:'));
		expect(blindKeys.length).toBe(0);
	});

	it('silently ignores a duplicate subscription without confirming it exists', async () => {
		// Subscribe and activate
		const subReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		await handleScheduleSubscribe(subReq, env);
		const pendingKey = Array.from(mockKV.store.keys()).find((k) => k.startsWith('pending:'))!;
		const token = pendingKey.replace('pending:', '');
		await handleScheduleVerify(new Request(`https://secmy.app/api/schedule/verify?token=${token}`), env);

		// Attempt subscribe again with same email and target
		const dupReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const dupRes = await handleScheduleSubscribe(dupReq, env);
		expect(dupRes.status).toBe(200);
		const json = (await dupRes.json()) as any;
		// The duplicate must not be acknowledged as one: that would answer
		// "is this address monitoring this domain?" to an anonymous caller.
		expect(json.alreadySubscribed).toBeUndefined();
		expect(json.message).toBe('Verification email dispatched. Please confirm to activate monitoring.');
		// ...and no second pending record may be created for it.
		const pendingKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('pending:'));
		expect(pendingKeys).toHaveLength(0);
	});

	it('subscribe x2 -> verify x2 leaves exactly 1 active record in KV without orphans', async () => {
		// Subscribe 1st time
		const sub1 = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		await handleScheduleSubscribe(sub1, env);
		const token1 = Array.from(mockKV.store.keys()).find((k) => k.startsWith('pending:'))!.replace('pending:', '');

		// Subscribe 2nd time before verifying 1st
		const sub2 = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		await handleScheduleSubscribe(sub2, env);
		const pendingKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('pending:'));
		expect(pendingKeys.length).toBe(1); // Old pending was deleted
		const token2 = pendingKeys[0].replace('pending:', '');
		expect(token2).not.toBe(token1);

		// First verify link should now be invalid/expired
		const verify1Res = await handleScheduleVerify(new Request(`https://secmy.app/api/schedule/verify?token=${token1}`), env);
		expect(verify1Res.status).toBe(404);

		// Second verify link succeeds
		const verify2Res = await handleScheduleVerify(new Request(`https://secmy.app/api/schedule/verify?token=${token2}`), env);
		expect(verify2Res.status).toBe(200);

		// Exactly 1 active record in KV
		const activeKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('active:'));
		expect(activeKeys.length).toBe(1);

		// pendingIdx should be cleaned up
		const pendingIdxKeys = Array.from(mockKV.store.keys()).filter((k) => k.startsWith('pendingIdx:'));
		expect(pendingIdxKeys.length).toBe(0);
	});

	it('cron detects degradation diff and sends alert email', async () => {
		// Seed an active subscription with a baseline
		const manageToken = 'manage-123';
		const record: SubscriptionRecord = {
			email: 'admin@example.com',
			targetUrl: 'https://example.com',
			status: 'ACTIVE',
			manageToken,
			baselineFingerprint: {
				wafDetected: 'Cloudflare',
				blockedCount: 50,
				bypassedCount: 0,
				totalCount: 50,
				scanHash: 'Cloudflare:50:0:50',
				scannedAt: Date.now() - 25 * 3600 * 1000, // 25 hours ago
			},
			createdAt: Date.now() - 30 * 3600 * 1000,
			lastScannedAt: Date.now() - 25 * 3600 * 1000,
		};

		const encrypted = await (await import('../src/utils/crypto')).encryptPayload(record, secret);
		await mockKV.put(`active:${manageToken}`, encrypted);

		// Run scheduled cron with a probe simulator that finds a bypass
		const mockScanFn = vi.fn().mockResolvedValue({
			wafDetected: 'Cloudflare',
			summary: { blocked: 40, passed: 10, total: 50 },
		});

		await handleScheduledCron(env, mockScanFn);

		// Should have sent alert email
		expect(mockSendEmail).toHaveBeenCalledWith(
			expect.objectContaining({
				to: 'admin@example.com',
				subject: expect.stringContaining('ALERT'),
			})
		);
	});

	it('cron skips subscriber on scan error without updating baseline or sending email', async () => {
		const manageToken = 'manage-error-test';
		const originalLastScanned = Date.now() - 25 * 3600 * 1000;
		const record: SubscriptionRecord = {
			email: 'admin@example.com',
			targetUrl: 'https://example.com',
			status: 'ACTIVE',
			manageToken,
			baselineFingerprint: {
				wafDetected: 'Cloudflare',
				blockedCount: 50,
				bypassedCount: 0,
				totalCount: 50,
				scanHash: 'Cloudflare:50:0:50',
				scannedAt: originalLastScanned,
			},
			createdAt: Date.now() - 30 * 3600 * 1000,
			lastScannedAt: originalLastScanned,
		};

		const encrypted = await (await import('../src/utils/crypto')).encryptPayload(record, secret);
		await mockKV.put(`active:${manageToken}`, encrypted);

		const failingScanFn = vi.fn().mockRejectedValue(new Error('Network timeout'));

		await handleScheduledCron(env, failingScanFn);

		// Should NOT send email
		expect(mockSendEmail).not.toHaveBeenCalled();

		// Record in KV should remain unmodified (lastScannedAt unchanged)
		const currentEncrypted = await mockKV.get(`active:${manageToken}`);
		const currentRecord = await decryptPayload<SubscriptionRecord>(currentEncrypted!, secret);
		expect(currentRecord.lastScannedAt).toBe(originalLastScanned);
		expect(currentRecord.baselineFingerprint?.scanHash).toBe('Cloudflare:50:0:50');
	});
});

describe('Security invariants (design-review acceptance criteria)', () => {
	let mockKV: any;
	let env: WorkerEnv;
	const secret = 'test-secret-key-32-characters-minimum';

	function createKV() {
		const store = new Map<string, string>();
		return {
			store,
			async get(key: string) {
				return store.get(key) ?? null;
			},
			async put(key: string, value: string) {
				store.set(key, value);
			},
			async delete(key: string) {
				store.delete(key);
			},
			async list(options?: { prefix?: string }) {
				const prefix = options?.prefix || '';
				return {
					keys: Array.from(store.keys())
						.filter((k) => k.startsWith(prefix))
						.map((name) => ({ name })),
					list_complete: true,
					cursor: '',
				};
			},
		} as any;
	}

	beforeEach(() => {
		mockKV = createKV();
		env = {
			ASSETS: { fetch: vi.fn() },
			MONITOR_KV: mockKV,
			SEND_EMAIL: { send: vi.fn().mockResolvedValue(undefined) },
			EMAIL_ENCRYPTION_KEY: secret,
			TURNSTILE_SECRET_KEY: 'turnstile-test-secret',
		};
		stubTurnstile();
	});

	afterEach(() => {
		restoreFetch();
	});

	function subscribeRequest(email: string, targetUrl: string) {
		return new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ turnstileToken: 'captcha-ok', email, targetUrl }),
		});
	}

	// I6: the deployment must refuse to operate rather than silently fall back
	// to the secret published in this repository.
	it('I6: refuses to serve when EMAIL_ENCRYPTION_KEY is absent in production', async () => {
		const prodEnv: WorkerEnv = { ...env, EMAIL_ENCRYPTION_KEY: undefined };
		const res = await handleScheduleSubscribe(
			subscribeRequest('user@example.com', 'https://example.com'),
			prodEnv
		);
		expect(res.status).toBe(503);
		// Nothing subscriber-related may be persisted under the fallback secret.
		const persisted = Array.from(mockKV.store.keys() as Iterable<string>).filter(
			(k) => k.startsWith('pending:') || k.startsWith('active:') || k.startsWith('blind:')
		);
		expect(persisted).toHaveLength(0);
	});

	it('I6: still uses the development fallback for an explicit dev deployment', async () => {
		const devEnv: WorkerEnv = { ...env, EMAIL_ENCRYPTION_KEY: undefined, DEV_MODE: 'true' };
		const res = await handleScheduleSubscribe(
			subscribeRequest('user@example.com', 'https://example.com'),
			devEnv
		);
		expect(res.status).toBe(200);
	});

	// I7: the response must not answer "does this address monitor this domain?".
	it('I7: a duplicate subscription is indistinguishable from a first-time one', async () => {
		const first = await handleScheduleSubscribe(
			subscribeRequest('owner@example.com', 'https://example.com'),
			env
		);
		const firstJson = (await first.json()) as any;

		// Activate it so the second attempt hits the "already active" path.
		const verifyToken = Array.from(mockKV.store.keys() as Iterable<string>)
			.find((k) => k.startsWith('pending:'))!
			.slice('pending:'.length);
		await handleScheduleVerify(
			new Request(`https://secmy.app/api/schedule/verify?token=${verifyToken}`),
			env,
			async () => ({ wafDetected: 'Cloudflare', summary: { blocked: 10, passed: 0, total: 10 } })
		);

		const second = await handleScheduleSubscribe(
			subscribeRequest('owner@example.com', 'https://example.com'),
			env
		);
		const secondJson = (await second.json()) as any;

		expect(second.status).toBe(first.status);
		expect(secondJson.message).toBe(firstJson.message);
		expect(secondJson.success).toBe(firstJson.success);
		expect('alreadySubscribed' in secondJson).toBe(false);
	});

	// I8: the mailbox itself is rate limited, not just the source address.
	it('I8: throttles repeated mail to one address across rotating source IPs', async () => {
		const statuses: number[] = [];
		for (let attempt = 0; attempt < 5; attempt++) {
			const req = new Request('https://secmy.app/api/schedule/subscribe', {
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					'cf-connecting-ip': `203.0.113.${attempt}`,
				},
				body: JSON.stringify({ turnstileToken: 'captcha-ok', email: 'victim@example.org', targetUrl: 'https://example.com' }),
			});
			statuses.push((await handleScheduleSubscribe(req, env)).status);
		}
		expect(statuses).toContain(429);
	});

	// I2: authorization and target validity are re-established at scan time.
	it('I2: cron refuses to scan a stored target that is no longer allowed', async () => {
		const scanFn = vi.fn().mockResolvedValue({
			wafDetected: 'Cloudflare',
			summary: { blocked: 1, passed: 0, total: 1 },
		});
		const record: SubscriptionRecord = {
			email: 'owner@example.com',
			targetUrl: 'http://169.254.169.254/latest/meta-data/',
			status: 'ACTIVE',
			manageToken: 'tok-internal',
			createdAt: Date.now(),
		};
		const { encryptPayload } = await import('../src/utils/crypto');
		mockKV.store.set('active:tok-internal', await encryptPayload(record, secret));

		await handleScheduledCron(env, scanFn);
		expect(scanFn).not.toHaveBeenCalled();
	});

	it('I2: cron re-proves external ownership once the proof goes stale', async () => {
		const scanFn = vi.fn().mockResolvedValue({
			wafDetected: 'Cloudflare',
			summary: { blocked: 1, passed: 0, total: 1 },
		});
		const record: SubscriptionRecord = {
			email: 'owner@gmail.com',
			targetUrl: 'https://notmine.example',
			status: 'ACTIVE',
			manageToken: 'tok-stale',
			createdAt: Date.now(),
			mode: 'external',
			ownershipToken: 'secmy-abc',
			lastOwnershipVerifiedAt: Date.now() - 400 * 24 * 3600 * 1000,
		};
		const { encryptPayload } = await import('../src/utils/crypto');
		mockKV.store.set('active:tok-stale', await encryptPayload(record, secret));

		// The challenge file is gone, so the stale proof cannot be renewed.
		const originalFetch = globalThis.fetch;
		globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 404 })) as any;
		try {
			await handleScheduledCron(env, scanFn);
		} finally {
			globalThis.fetch = originalFetch;
		}
		expect(scanFn).not.toHaveBeenCalled();
	});
});

describe('Cron scheduling fairness and unsubscribe safety', () => {
	const secret = 'test-secret-key-32-characters-minimum';
	let mockKV: any;
	let env: WorkerEnv;

	beforeEach(() => {
		const store = new Map<string, string>();
		mockKV = {
			store,
			async get(key: string) {
				return store.get(key) ?? null;
			},
			async put(key: string, value: string) {
				store.set(key, value);
			},
			async delete(key: string) {
				store.delete(key);
			},
			async list(options?: { prefix?: string; cursor?: string }) {
				const prefix = options?.prefix || '';
				return {
					keys: Array.from(store.keys())
						.filter((k) => k.startsWith(prefix))
						.map((name) => ({ name })),
					list_complete: true,
					cursor: '',
				};
			},
		};
		env = {
			ASSETS: { fetch: vi.fn() },
			MONITOR_KV: mockKV,
			SEND_EMAIL: { send: vi.fn().mockResolvedValue(undefined) },
			EMAIL_ENCRYPTION_KEY: secret,
		};
	});

	// The per-run cap must be a throughput limit, not a permanent cutoff: taking
	// the first N keys off the listing starves everything past the cap forever.
	it('audits the stalest subscriptions first so no subscription is starved', async () => {
		const { encryptPayload } = await import('../src/utils/crypto');
		const dayMs = 24 * 3600 * 1000;
		// 30 subscriptions; the ones listed last were scanned longest ago.
		for (let i = 0; i < 30; i++) {
			const record: SubscriptionRecord = {
				email: `owner${i}@example.com`,
				targetUrl: `https://example${i}.com`,
				status: 'ACTIVE',
				manageToken: `tok-${String(i).padStart(2, '0')}`,
				createdAt: Date.now(),
				lastScannedAt: Date.now() - (i + 1) * dayMs,
			};
			mockKV.store.set(`active:tok-${String(i).padStart(2, '0')}`, await encryptPayload(record, secret));
		}

		const scanned: string[] = [];
		await handleScheduledCron(env, async (targetUrl) => {
			scanned.push(targetUrl);
			return { wafDetected: 'Cloudflare', summary: { blocked: 5, passed: 0, total: 5 } };
		});

		expect(scanned).toHaveLength(25);
		// example29 is the stalest and must be in the first run, even though its key
		// sorts last in the listing.
		expect(scanned).toContain('https://example29.com');
		expect(scanned).not.toContain('https://example0.com');
	});

	it('does not delete a subscription on a bare GET', async () => {
		const { encryptPayload } = await import('../src/utils/crypto');
		const record: SubscriptionRecord = {
			email: 'owner@example.com',
			targetUrl: 'https://example.com',
			status: 'ACTIVE',
			manageToken: 'tok-get',
			createdAt: Date.now(),
		};
		mockKV.store.set('active:tok-get', await encryptPayload(record, secret));

		const res = await handleScheduleUnsubscribe(
			new Request('https://secmy.app/api/schedule/unsubscribe?token=tok-get'),
			env
		);
		expect(res.status).toBe(200);
		// A link scanner or prefetch must not have cancelled anything.
		expect(mockKV.store.has('active:tok-get')).toBe(true);

		const posted = await handleScheduleUnsubscribe(
			new Request('https://secmy.app/api/schedule/unsubscribe?token=tok-get', { method: 'POST' }),
			env
		);
		expect(posted.status).toBe(200);
		expect(mockKV.store.has('active:tok-get')).toBe(false);
	});
});
