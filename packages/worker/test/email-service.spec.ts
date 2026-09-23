import { describe, it, expect, vi } from 'vitest';
import { sendNotificationEmail, buildVerificationEmail, buildAlertEmail } from '../src/services/email';
import { WorkerEnv } from '../types/monitor';

describe('Email Service (send_email & templates)', () => {
	it('uses env.SEND_EMAIL in production with waf@secmy.app sender and RFC headers', async () => {
		const mockSend = vi.fn().mockResolvedValue(undefined);
		const env: WorkerEnv = {
			ASSETS: { fetch: vi.fn() },
			SEND_EMAIL: { send: mockSend },
		};

		const res = await sendNotificationEmail(env, {
			to: 'user@example.com',
			subject: 'Test Subject',
			html: '<p>Hello</p>',
			text: 'Hello',
			headers: { 'List-Unsubscribe': '<https://secmy.app/api/schedule/unsubscribe?token=abc>' },
		});

		expect(res.sent).toBe(true);
		expect(res.simulated).toBe(false);
		expect(mockSend).toHaveBeenCalledWith(
			expect.objectContaining({
				from: 'waf@secmy.app',
				to: 'user@example.com',
				subject: 'Test Subject',
				headers: expect.objectContaining({
					'List-Unsubscribe': '<https://secmy.app/api/schedule/unsubscribe?token=abc>',
				}),
			})
		);
	});

	it('simulates the send only for a development deployment', async () => {
		const devEnv: WorkerEnv = { ASSETS: { fetch: vi.fn() }, DEV_MODE: 'true' };
		const res = await sendNotificationEmail(devEnv, {
			to: 'user@example.com',
			subject: 'Fallback Test',
			text: 'Simulation test',
		});
		expect(res.sent).toBe(true);
		expect(res.simulated).toBe(true);
	});

	it('reports failure rather than success when the binding is missing in production', async () => {
		// Reporting a delivered notification here would let a subscription persist
		// with no mail sent, and would drop every cron alert without a trace.
		const prodEnv: WorkerEnv = { ASSETS: { fetch: vi.fn() } };
		const res = await sendNotificationEmail(prodEnv, {
			to: 'user@example.com',
			subject: 'Fallback Test',
			text: 'Simulation test',
		});
		expect(res.sent).toBe(false);
		expect(res.simulated).toBe(false);
	});

	it('builds clear verification email for fast-track and external modes', () => {
		const ft = buildVerificationEmail({
			targetUrl: 'https://example.com',
			verifyUrl: 'https://secmy.app/verify?token=123',
			mode: 'fast-track',
		});
		expect(ft.subject).toContain('example.com');
		expect(ft.html).toContain('https://secmy.app/verify?token=123');

		const ext = buildVerificationEmail({
			targetUrl: 'https://example.com',
			verifyUrl: 'https://secmy.app/verify?token=123',
			mode: 'external',
			ownershipToken: 'tok-abc',
		});
		expect(ext.html).toContain('.well-known/secmy-check.txt');
		expect(ext.html).toContain('tok-abc');
	});

	it('builds clear alert email with diff details and one-click unsubscribe', () => {
		const alert = buildAlertEmail({
			targetUrl: 'https://example.com',
			isAlert: true,
			diffDetails: ['XSS bypass detected'],
			detectedWAF: 'Cloudflare',
			unsubscribeUrl: 'https://secmy.app/api/schedule/unsubscribe?token=tok-1',
			manageUrl: 'https://secmy.app',
		});
		expect(alert.subject).toContain('ALERT');
		expect(alert.html).toContain('XSS bypass detected');
		expect(alert.html).toContain('https://secmy.app/api/schedule/unsubscribe?token=tok-1');
	});
});
