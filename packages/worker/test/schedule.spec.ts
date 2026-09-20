import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
	handleScheduleSubscribe,
	handleScheduleVerify,
	handleScheduleUnsubscribe,
	handleScheduledCron,
} from '../src/handlers/schedule';
import { WorkerEnv, SubscriptionRecord } from '../types/monitor';
import { decryptPayload } from '../src/utils/crypto';

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
		};
	});

	it('rejects subscription for self-host secmy.app (SSRF / self-scan protection)', async () => {
		const req = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ email: 'admin@secmy.app', targetUrl: 'https://secmy.app' }),
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
			body: JSON.stringify({ email: 'admin@example.com', targetUrl: 'http://127.0.0.1:8080' }),
		});
		const res = await handleScheduleSubscribe(req, env);
		expect(res.status).toBe(400);
	});

	it('creates fast-track pending subscription and dispatches verification email', async () => {
		const req = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
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
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const res = await handleScheduleSubscribe(req, envNoEmail);
		const json = (await res.json()) as any;
		expect(json.devVerifyUrl).toBeUndefined();
	});

	it('returns devVerifyUrl when called on localhost or with DEV_MODE', async () => {
		const localReq = new Request('http://localhost:8787/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const localRes = await handleScheduleSubscribe(localReq, env);
		const localJson = (await localRes.json()) as any;
		expect(localJson.devVerifyUrl).toBeDefined();

		const devModeEnv: WorkerEnv = { ...env, DEV_MODE: 'true' };
		const prodReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const devModeRes = await handleScheduleSubscribe(prodReq, devModeEnv);
		const devModeJson = (await devModeRes.json()) as any;
		expect(devModeJson.devVerifyUrl).toBeDefined();
	});

	it('verifies fast-track subscription and activates it', async () => {
		// Subscribe first
		const subReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
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
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
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

	it('returns alreadySubscribed when attempting duplicate subscription for active site', async () => {
		// Subscribe and activate
		const subReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		await handleScheduleSubscribe(subReq, env);
		const pendingKey = Array.from(mockKV.store.keys()).find((k) => k.startsWith('pending:'))!;
		const token = pendingKey.replace('pending:', '');
		await handleScheduleVerify(new Request(`https://secmy.app/api/schedule/verify?token=${token}`), env);

		// Attempt subscribe again with same email and target
		const dupReq = new Request('https://secmy.app/api/schedule/subscribe', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ email: 'security@example.com', targetUrl: 'https://example.com' }),
		});
		const dupRes = await handleScheduleSubscribe(dupReq, env);
		expect(dupRes.status).toBe(200);
		const json = (await dupRes.json()) as any;
		expect(json.alreadySubscribed).toBe(true);
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
