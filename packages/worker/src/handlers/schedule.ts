import { isValidTargetUrl } from '@waf-checker/core';
import { isSelfScan } from '../api';
import {
	WorkerEnv,
	PendingVerificationRecord,
	SubscriptionRecord,
	EmailOptions,
	BaselineFingerprint,
} from '../types/monitor';
import {
	encryptPayload,
	decryptPayload,
	computeBlindIndex,
	generateSecureToken,
} from '../utils/crypto';
import {
	determineOwnershipMode,
	verifyHttpOwnership,
	extractHost,
	normalizeEmail,
} from '../services/ownership';
import {
	sendNotificationEmail,
	buildVerificationEmail,
	buildAlertEmail,
} from '../services/email';
import { computeFingerprint, diffFingerprints } from '../services/monitor';
import { runMonitorScan, MonitorScanResult } from '../services/scan';
import { checkRateLimit } from '../services/rate-limiter';
import { escapeHtml } from '../utils/html';

const DEFAULT_SECRET = 'default-dev-secret-key-32-chars-long';
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Re-prove external-mode domain ownership at least this often (30 days). */
const OWNERSHIP_REVERIFY_INTERVAL_MS = 30 * 24 * 3600 * 1000;
/** Upper bound on subscriptions audited in a single cron invocation. */
const MAX_SUBSCRIPTIONS_PER_RUN = 25;

/**
 * A request is "development" only when it demonstrably originates from this
 * machine, or when the operator opted in explicitly. Notably it is NOT inferred
 * from a missing binding: a production deployment whose email binding broke
 * must not silently become a dev deployment that hands out verification links.
 */
function isDevEnvironment(env: WorkerEnv, request?: Request): boolean {
	if (env.DEV_MODE === 'true') return true;
	if (!request) return false;
	try {
		const reqHost = new URL(request.url).hostname.toLowerCase();
		return reqHost === 'localhost' || reqHost === '127.0.0.1' || reqHost === '[::1]' || reqHost === '::1';
	} catch {
		return false;
	}
}

/**
 * Returns the record encryption key, or null when the deployment is not in a
 * state where the confidentiality promise holds.
 *
 * Falling back to a hardcoded secret in production would mean every encrypted
 * record and every blind index is derived from a value published in this
 * repository — the stored data would be readable and enumerable by anyone who
 * obtained a KV dump. Refusing to operate is the only honest option; the
 * built-in fallback exists solely so local development and tests need no setup.
 */
function resolveSecret(env: WorkerEnv, request?: Request): string | null {
	if (env.EMAIL_ENCRYPTION_KEY) return env.EMAIL_ENCRYPTION_KEY;
	if (isDevEnvironment(env, request)) return DEFAULT_SECRET;
	return null;
}

function misconfiguredResponse(detail: string): Response {
	console.error(`Refusing to serve scheduled-monitoring request: ${detail}`);
	return new Response(
		JSON.stringify({ error: 'Scheduled monitoring is not available on this deployment.' }),
		{ status: 503, headers: { 'content-type': 'application/json' } }
	);
}

async function verifyTurnstile(token: string, secretKey: string, remoteIp?: string): Promise<boolean> {
	try {
		const formData = new FormData();
		formData.append('secret', secretKey);
		formData.append('response', token);
		if (remoteIp) formData.append('remoteip', remoteIp);

		const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
			method: 'POST',
			body: formData,
		});
		const outcome: any = await res.json();
		return Boolean(outcome.success);
	} catch {
		return false;
	}
}

export async function handleScheduleSubscribe(request: Request, env: WorkerEnv): Promise<Response> {
	if (request.method !== 'POST') {
		return new Response(JSON.stringify({ error: 'Method not allowed. Use POST.' }), {
			status: 405,
			headers: { 'content-type': 'application/json' },
		});
	}

	let body: any;
	try {
		body = await request.json();
	} catch {
		return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}

	const email = typeof body.email === 'string' ? normalizeEmail(body.email) : '';
	const targetUrl = typeof body.targetUrl === 'string' ? body.targetUrl.trim() : '';
	const turnstileToken = typeof body.turnstileToken === 'string' ? body.turnstileToken.trim() : '';

	if (!email || !EMAIL_REGEX.test(email)) {
		return new Response(JSON.stringify({ error: 'Invalid email address' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}

	if (!targetUrl || !isValidTargetUrl(targetUrl)) {
		return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}

	if (isSelfScan(targetUrl)) {
		return new Response(JSON.stringify({ error: 'self-scan refused', code: 'SELF_SCAN_REFUSED' }), {
			status: 422,
			headers: { 'content-type': 'application/json' },
		});
	}

	// Verify Turnstile captcha. Outside development the captcha is mandatory:
	// an unconfigured secret used to disable the check entirely, which turned a
	// missing binding into an open, automatable mail-sending endpoint.
	const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
	if (!env.TURNSTILE_SECRET_KEY && !isDevEnvironment(env, request)) {
		return misconfiguredResponse('TURNSTILE_SECRET_KEY is not configured');
	}
	if (env.TURNSTILE_SECRET_KEY) {
		if (!turnstileToken) {
			return new Response(JSON.stringify({ error: 'Captcha verification required' }), {
				status: 403,
				headers: { 'content-type': 'application/json' },
			});
		}
		const validCaptcha = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY, clientIp);
		if (!validCaptcha) {
			return new Response(JSON.stringify({ error: 'Captcha validation failed' }), {
				status: 403,
				headers: { 'content-type': 'application/json' },
			});
		}
	}

	// Rate limiting: max 5 subscription attempts per IP per hour
	const rl = await checkRateLimit(env.MONITOR_KV, `rl:sub:${clientIp}`, 5, 3600);
	if (!rl.allowed) {
		return new Response(
			JSON.stringify({ error: 'Too many subscription requests. Please try again later.' }),
			{ status: 429, headers: { 'content-type': 'application/json' } }
		);
	}

	const secretKey = resolveSecret(env, request);
	if (!secretKey) {
		return misconfiguredResponse('EMAIL_ENCRYPTION_KEY is not configured');
	}
	const host = extractHost(targetUrl);
	const blindIndex = (env.MONITOR_KV && host)
		? await computeBlindIndex(`${email}:${host}`, secretKey)
		: null;

	// Per-recipient throttle. The IP-keyed limit above does not protect the
	// mailbox: rotating source addresses would otherwise let one address be
	// mailed repeatedly on an attacker's schedule.
	if (blindIndex) {
		const recipientRl = await checkRateLimit(env.MONITOR_KV, `rl:mail:${blindIndex}`, 3, 3600);
		if (!recipientRl.allowed) {
			return new Response(
				JSON.stringify({ error: 'Too many subscription requests. Please try again later.' }),
				{ status: 429, headers: { 'content-type': 'application/json' } }
			);
		}
	}

	// Already actively subscribed: stop here, but answer exactly as a first-time
	// subscription would. A distinguishable response is an unauthenticated
	// oracle for "is this address monitoring this domain?".
	let alreadyActive = false;
	if (env.MONITOR_KV && blindIndex) {
		const existingManageToken = await env.MONITOR_KV.get(`blind:${blindIndex}`);
		if (existingManageToken) {
			alreadyActive = Boolean(await env.MONITOR_KV.get(`active:${existingManageToken}`));
		}

		if (!alreadyActive) {
			// Invalidate previous pending token if one was already issued for this (email, host)
			const previousPendingToken = await env.MONITOR_KV.get(`pendingIdx:${blindIndex}`);
			if (previousPendingToken) {
				await env.MONITOR_KV.delete(`pending:${previousPendingToken}`);
			}
		}
	}

	if (alreadyActive) {
		// Mirror the first-time response field-for-field, including a freshly
		// generated (and unused) ownership token for external mode, so the two
		// cases are indistinguishable to the caller.
		const decoyMode = determineOwnershipMode(email, targetUrl);
		return new Response(
			JSON.stringify({
				success: true,
				message: 'Verification email dispatched. Please confirm to activate monitoring.',
				mode: decoyMode,
				ownershipToken: decoyMode === 'external' ? `secmy-${generateSecureToken(16)}` : undefined,
				ownershipChallengeFile:
					decoyMode === 'external' ? `${targetUrl}/.well-known/secmy-check.txt` : undefined,
			}),
			{ status: 200, headers: { 'content-type': 'application/json' } }
		);
	}

	const mode = determineOwnershipMode(email, targetUrl);
	const verifyToken = generateSecureToken(24);
	const ownershipToken = mode === 'external' ? `secmy-${generateSecureToken(16)}` : undefined;

	const pendingRecord: PendingVerificationRecord = {
		email,
		targetUrl,
		mode,
		ownershipToken,
		createdAt: Date.now(),
	};

	const encrypted = await encryptPayload(pendingRecord, secretKey);

	if (env.MONITOR_KV) {
		// Pending verification expires in 24 hours (86400s)
		await env.MONITOR_KV.put(`pending:${verifyToken}`, encrypted, { expirationTtl: 86400 });
		if (blindIndex) {
			await env.MONITOR_KV.put(`pendingIdx:${blindIndex}`, verifyToken, { expirationTtl: 86400 });
		}
	}

	const origin = new URL(request.url).origin;
	const verifyUrl = `${origin}/api/schedule/verify?token=${verifyToken}`;

	const emailContent = buildVerificationEmail({
		targetUrl,
		verifyUrl,
		mode,
		ownershipToken,
	});

	const emailResult = await sendNotificationEmail(env, {
		to: email,
		subject: emailContent.subject,
		html: emailContent.html,
		text: emailContent.text,
	});

	if (!emailResult.sent) {
		if (env.MONITOR_KV) {
			await env.MONITOR_KV.delete(`pending:${verifyToken}`);
			if (blindIndex) {
				await env.MONITOR_KV.delete(`pendingIdx:${blindIndex}`);
			}
		}
		return new Response(
			JSON.stringify({
				error: 'Failed to dispatch verification email. Please try again later.',
			}),
			{ status: 500, headers: { 'content-type': 'application/json' } }
		);
	}

	const reqHost = new URL(request.url).hostname.toLowerCase();
	const isLocalDev =
		reqHost === 'localhost' ||
		reqHost === '127.0.0.1' ||
		reqHost === '[::1]' ||
		reqHost === '::1' ||
		env.DEV_MODE === 'true';

	return new Response(
		JSON.stringify({
			success: true,
			message: 'Verification email dispatched. Please confirm to activate monitoring.',
			mode,
			ownershipToken: mode === 'external' ? ownershipToken : undefined,
			ownershipChallengeFile:
				mode === 'external' ? `${targetUrl}/.well-known/secmy-check.txt` : undefined,
			devVerifyUrl: isLocalDev ? verifyUrl : undefined,
		}),
		{ status: 200, headers: { 'content-type': 'application/json' } }
	);
}

export async function handleScheduleVerify(
	request: Request,
	env: WorkerEnv,
	scanFn?: (targetUrl: string) => Promise<MonitorScanResult>
): Promise<Response> {
	const url = new URL(request.url);
	const token = url.searchParams.get('token');

	if (!token) {
		return new Response(JSON.stringify({ error: 'Missing token parameter' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}

	if (!env.MONITOR_KV) {
		return new Response(JSON.stringify({ error: 'Storage KV not configured' }), {
			status: 500,
			headers: { 'content-type': 'application/json' },
		});
	}

	const encrypted = await env.MONITOR_KV.get(`pending:${token}`);
	if (!encrypted) {
		return new Response(JSON.stringify({ error: 'Invalid or expired verification token' }), {
			status: 404,
			headers: { 'content-type': 'application/json' },
		});
	}

	const secretKey = resolveSecret(env, request);
	if (!secretKey) {
		return misconfiguredResponse('EMAIL_ENCRYPTION_KEY is not configured');
	}
	let pending: PendingVerificationRecord;
	try {
		pending = await decryptPayload<PendingVerificationRecord>(encrypted, secretKey);
	} catch {
		return new Response(JSON.stringify({ error: 'Decryption failed for verification record' }), {
			status: 500,
			headers: { 'content-type': 'application/json' },
		});
	}

	// If external mode, verify HTTP challenge file
	if (pending.mode === 'external') {
		const verified = await verifyHttpOwnership(pending.targetUrl, pending.ownershipToken || '');
		if (!verified) {
			return new Response(
				JSON.stringify({
					error: 'Domain ownership verification failed.',
					instruction: `Please create file ${pending.targetUrl}/.well-known/secmy-check.txt with token: ${pending.ownershipToken}`,
				}),
				{ status: 400, headers: { 'content-type': 'application/json' } }
			);
		}
	}

	// Compute initial baseline via deterministic scan.
	// If the scan fails, activate without a baseline: the first cron run then
	// establishes it instead of diffing against a fabricated zero-fingerprint,
	// which would always produce a false "WAF status changed" alert.
	let baseline: BaselineFingerprint | undefined;
	try {
		const scanResult = scanFn
			? await scanFn(pending.targetUrl)
			: await runMonitorScan(pending.targetUrl);
		baseline = computeFingerprint(scanResult);
	} catch (err) {
		console.error('Initial baseline monitor scan failed:', err);
	}

	const manageToken = generateSecureToken(24);
	const activeRecord: SubscriptionRecord = {
		email: pending.email,
		targetUrl: pending.targetUrl,
		status: 'ACTIVE',
		manageToken,
		mode: pending.mode,
		ownershipToken: pending.ownershipToken,
		lastOwnershipVerifiedAt: Date.now(),
		baselineFingerprint: baseline,
		createdAt: Date.now(),
		lastScannedAt: Date.now(),
	};

	const encryptedActive = await encryptPayload(activeRecord, secretKey);
	const host = extractHost(pending.targetUrl);
	const blindIndex = host
		? await computeBlindIndex(`${pending.email}:${host}`, secretKey)
		: null;

	if (blindIndex) {
		const existingManageToken = await env.MONITOR_KV.get(`blind:${blindIndex}`);
		if (existingManageToken && existingManageToken !== manageToken) {
			await env.MONITOR_KV.delete(`active:${existingManageToken}`);
		}
		await env.MONITOR_KV.put(`blind:${blindIndex}`, manageToken);
		await env.MONITOR_KV.delete(`pendingIdx:${blindIndex}`);
	}

	await env.MONITOR_KV.put(`active:${manageToken}`, encryptedActive);
	await env.MONITOR_KV.delete(`pending:${token}`);

	const origin = new URL(request.url).origin;
	const unsubscribeUrl = `${origin}/api/schedule/unsubscribe?token=${manageToken}`;

	const welcomeEmail = buildAlertEmail({
		targetUrl: pending.targetUrl,
		isAlert: false,
		diffDetails: ['Security monitoring activated successfully. Daily audits initiated.'],
		detectedWAF: baseline?.wafDetected || 'Pending first scan',
		unsubscribeUrl,
		manageUrl: origin,
	});

	await sendNotificationEmail(env, {
		to: pending.email,
		subject: welcomeEmail.subject,
		html: welcomeEmail.html,
		text: welcomeEmail.text,
		headers: {
			'List-Unsubscribe': `<${unsubscribeUrl}>`,
			'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
		},
	});

	const acceptsHtml = request.headers.get('accept')?.includes('text/html');
	if (acceptsHtml) {
		return new Response(
			`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:50px;">
				<h2 style="color:#00875a;">Security Monitoring Activated!</h2>
				<p>Target endpoint <strong>${escapeHtml(pending.targetUrl)}</strong> has been added to daily security audits.</p>
				<p><a href="${escapeHtml(origin)}">Return to secmy.app</a></p>
			</body></html>`,
			{ status: 200, headers: { 'content-type': 'text/html; charset=UTF-8' } }
		);
	}

	return new Response(
		JSON.stringify({
			success: true,
			message: 'Monitoring activated successfully',
			targetUrl: pending.targetUrl,
			manageToken,
		}),
		{ status: 200, headers: { 'content-type': 'application/json' } }
	);
}

export async function handleScheduleUnsubscribe(request: Request, env: WorkerEnv): Promise<Response> {
	const url = new URL(request.url);
	let token = url.searchParams.get('token');

	if (!token && request.method === 'POST') {
		try {
			const body: any = await request.clone().json();
			if (typeof body?.token === 'string') token = body.token;
		} catch {}
	}

	if (!token) {
		return new Response(JSON.stringify({ error: 'Missing token parameter' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}

	if (env.MONITOR_KV) {
		const existing = await env.MONITOR_KV.get(`active:${token}`);
		if (existing) {
			try {
				const secretKey = resolveSecret(env, request);
				if (!secretKey) throw new Error('encryption key unavailable');
				const record = await decryptPayload<SubscriptionRecord>(existing, secretKey);
				const host = extractHost(record.targetUrl);
				if (host) {
					const blindIndex = await computeBlindIndex(`${record.email}:${host}`, secretKey);
					await env.MONITOR_KV.delete(`blind:${blindIndex}`);
					await env.MONITOR_KV.delete(`pendingIdx:${blindIndex}`);
				}
			} catch {}
			await env.MONITOR_KV.delete(`active:${token}`);
		}
	}

	const acceptsHtml = request.headers.get('accept')?.includes('text/html');
	if (acceptsHtml) {
		return new Response(
			`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:50px;">
				<h2>Successfully Unsubscribed</h2>
				<p>Security monitoring alerts will no longer be sent to this email address.</p>
			</body></html>`,
			{ status: 200, headers: { 'content-type': 'text/html; charset=UTF-8' } }
		);
	}

	return new Response(JSON.stringify({ success: true, message: 'Successfully unsubscribed' }), {
		status: 200,
		headers: { 'content-type': 'application/json' },
	});
}

export async function handleScheduledCron(
	env: WorkerEnv,
	scanFn?: (targetUrl: string) => Promise<{ wafDetected?: string; summary?: { blocked: number; passed: number; total: number } }>
): Promise<void> {
	if (!env.MONITOR_KV) return;
	const secret = resolveSecret(env);
	if (!secret) {
		console.error('Skipping scheduled run: EMAIL_ENCRYPTION_KEY is not configured');
		return;
	}

	const listRes = await env.MONITOR_KV.list({ prefix: 'active:' });
	let audited = 0;
	for (const key of listRes.keys) {
		if (audited >= MAX_SUBSCRIPTIONS_PER_RUN) {
			console.warn(
				`Scheduled run hit the per-run cap of ${MAX_SUBSCRIPTIONS_PER_RUN}; remaining subscriptions run next cycle`
			);
			break;
		}
		try {
			const encrypted = await env.MONITOR_KV.get(key.name);
			if (!encrypted) continue;

			const record = await decryptPayload<SubscriptionRecord>(encrypted, secret);
			if (record.status !== 'ACTIVE') continue;

			// Enforce at most 1 scan per 23h
			if (record.lastScannedAt && Date.now() - record.lastScannedAt < 23 * 3600 * 1000) {
				continue;
			}

			// Re-validate the stored target before using it. It was checked once at
			// subscribe time; this is a different, unattended context reading a value
			// back out of storage, and the deny-list may also have grown since.
			if (!isValidTargetUrl(record.targetUrl) || isSelfScan(record.targetUrl)) {
				console.error(`Skipping subscription ${key.name}: stored target is no longer an allowed scan target`);
				continue;
			}

			// Re-prove ownership periodically. Domains change hands, and a one-time
			// proof must not authorize scanning indefinitely.
			if (record.mode === 'external') {
				const lastProof = record.lastOwnershipVerifiedAt ?? 0;
				if (Date.now() - lastProof > OWNERSHIP_REVERIFY_INTERVAL_MS) {
					const stillOwned = await verifyHttpOwnership(record.targetUrl, record.ownershipToken || '');
					if (!stillOwned) {
						console.error(`Skipping subscription ${key.name}: ownership proof no longer present`);
						continue;
					}
					record.lastOwnershipVerifiedAt = Date.now();
				}
			}

			audited++;

			let scanResult: { wafDetected?: string; summary?: { blocked: number; passed: number; total: number } };
			try {
				if (scanFn) {
					scanResult = await scanFn(record.targetUrl);
				} else {
					scanResult = await runMonitorScan(record.targetUrl);
				}
			} catch (scanErr) {
				console.error(`Scheduled scan failed for ${record.targetUrl}, skipping:`, scanErr);
				continue;
			}

			const newFp = computeFingerprint(scanResult);
			if (record.baselineFingerprint) {
				const diff = diffFingerprints(record.baselineFingerprint, newFp);
				if (diff.isAlert) {
					const unsubscribeUrl = `https://secmy.app/api/schedule/unsubscribe?token=${record.manageToken}`;
					const email = buildAlertEmail({
						targetUrl: record.targetUrl,
						isAlert: true,
						diffDetails: diff.details,
						detectedWAF: newFp.wafDetected,
						unsubscribeUrl,
						manageUrl: 'https://secmy.app',
					});
					await sendNotificationEmail(env, {
						to: record.email,
						subject: email.subject,
						html: email.html,
						text: email.text,
						headers: {
							'List-Unsubscribe': `<${unsubscribeUrl}>`,
							'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
						},
					});
				}
			}

			record.baselineFingerprint = newFp;
			record.lastScannedAt = Date.now();
			const updatedEncrypted = await encryptPayload(record, secret);
			await env.MONITOR_KV.put(key.name, updatedEncrypted);
		} catch (err) {
			console.error(`Error in scheduled scan for key ${key.name}:`, err);
		}
	}
}
