import { EmailOptions, OwnershipMode, WorkerEnv } from '../types/monitor';
import { escapeHtml } from '../utils/html';
import { isDevEnvironment } from '../utils/env';
import { challengeUrlFor } from './ownership';

export const SENDER_EMAIL = 'waf@secmy.app';
export const SENDER_NAME = 'secmy.app WAF Monitor';

export async function sendNotificationEmail(
	env: WorkerEnv,
	options: EmailOptions
): Promise<{ sent: boolean; simulated: boolean }> {
	const headers = {
		'X-Mailer': 'secmy-waf-monitor',
		...(options.headers || {}),
	};

	if (env.SEND_EMAIL && typeof env.SEND_EMAIL.send === 'function') {
		try {
			await env.SEND_EMAIL.send({
				from: SENDER_EMAIL,
				to: options.to,
				subject: options.subject,
				text: options.text,
				html: options.html,
				headers,
			});
			return { sent: true, simulated: false };
		} catch (err: any) {
			console.error('Failed to send email notification:', err?.code || err);
			return { sent: false, simulated: false };
		}
	}

	// No binding. Simulating a send is only honest in development: reporting
	// success in production would let the caller persist a pending subscription
	// and let cron drop every alert, with nothing anywhere saying mail never left.
	if (isDevEnvironment(env)) {
		console.log(`[SIMULATED EMAIL] To: ${options.to} | Subject: ${options.subject}`);
		return { sent: true, simulated: true };
	}

	console.error('SEND_EMAIL binding is not configured; refusing to report a delivered notification');
	return { sent: false, simulated: false };
}

export function buildVerificationEmail(data: {
	targetUrl: string;
	verifyUrl: string;
	mode: OwnershipMode;
	ownershipToken?: string;
	/** Where the challenge file must be published, as the verifier will read it. */
	challengeUrl?: string;
}): { subject: string; html: string; text: string } {
	const subject = `[secmy.app] Confirm Security Monitoring for ${data.targetUrl}`;

	let instructionsHtml = '';
	let instructionsText = '';

	if (data.mode === 'external' && data.ownershipToken) {
		// Derived here when the caller did not supply it, so the instruction can
		// never drift from the location the verifier actually reads.
		const challengeUrl = data.challengeUrl || challengeUrlFor(data.targetUrl);
		instructionsHtml = `
		<div style="background: #fdf6e2; border-left: 4px solid #b58900; padding: 12px; margin: 16px 0;">
			<p><strong>Domain ownership verification required:</strong></p>
			<p>Because your email domain does not match the target website, please create a text file at:</p>
			<code>${escapeHtml(challengeUrl)}</code>
			<p>with the following content:</p>
			<pre style="background: #eee; padding: 8px;">${escapeHtml(data.ownershipToken)}</pre>
			<p>After creating the file, click the confirmation button below.</p>
		</div>`;
		instructionsText = `Domain ownership verification required: create file ${challengeUrl} with content: ${data.ownershipToken}\n\n`;
	}

	const html = `
	<!DOCTYPE html>
	<html>
	<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #222; line-height: 1.5; padding: 20px;">
		<h2 style="color: #0052cc;">secmy.app — WAF Monitoring</h2>
		<p>Daily security monitoring was requested for <strong>${escapeHtml(data.targetUrl)}</strong>.</p>
		${instructionsHtml}
		<p>
			<a href="${escapeHtml(data.verifyUrl)}" style="background-color: #0052cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Confirm Monitoring</a>
		</p>
		<p style="color: #666; font-size: 13px;">This link is valid for 24 hours. If you did not request this, please ignore this email — no scans will be scheduled.</p>
	</body>
	</html>`;

	const text = `secmy.app — WAF Monitoring\n\nDaily security monitoring was requested for ${data.targetUrl}.\n\n${instructionsText}To confirm, please visit:\n${data.verifyUrl}\n\nThis link is valid for 24 hours. If you did not request this, please ignore this email.`;

	return { subject, html, text };
}

export function buildAlertEmail(data: {
	targetUrl: string;
	isAlert: boolean;
	diffDetails: string[];
	detectedWAF: string;
	unsubscribeUrl: string;
	manageUrl: string;
}): { subject: string; html: string; text: string } {
	const prefix = data.isAlert ? '⚠️ [ALERT]' : '🟢 [STATUS]';
	const subject = `${prefix} WAF Security Report for ${data.targetUrl}`;

	const detailsList = data.diffDetails.map((d) => `<li>${escapeHtml(d)}</li>`).join('');

	const html = `
	<!DOCTYPE html>
	<html>
	<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #222; line-height: 1.5; padding: 20px;">
		<h2 style="color: ${data.isAlert ? '#d9381e' : '#00875a'};">secmy.app — Daily WAF Monitoring</h2>
		<p><strong>Target:</strong> ${escapeHtml(data.targetUrl)}</p>
		<p><strong>Detected WAF:</strong> ${escapeHtml(data.detectedWAF || 'None detected')}</p>
		<div style="background: #f4f5f7; padding: 14px; border-radius: 4px; margin: 16px 0;">
			<h4 style="margin-top: 0;">Security Posture Changes:</h4>
			<ul>${detailsList || '<li>No critical changes detected</li>'}</ul>
		</div>
		<p style="margin-top: 24px; font-size: 12px; color: #777; border-top: 1px solid #ddd; padding-top: 12px;">
			You received this email because you are subscribed to monitoring for ${escapeHtml(data.targetUrl)}.<br/>
			<a href="${escapeHtml(data.unsubscribeUrl)}" style="color: #777;">1-Click Unsubscribe</a>
		</p>
	</body>
	</html>`;

	const text = `${prefix} WAF Security Report for ${data.targetUrl}\n\nDetected WAF: ${data.detectedWAF || 'None detected'}\n\nChanges:\n${data.diffDetails.join('\n')}\n\nUnsubscribe: ${data.unsubscribeUrl}`;

	return { subject, html, text };
}
