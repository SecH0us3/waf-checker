import { EmailOptions, OwnershipMode, WorkerEnv } from '../types/monitor';

export const SENDER_EMAIL = 'waf@secmy.app';
export const SENDER_NAME = 'secmy.app WAF Monitor';

export async function sendNotificationEmail(
	env: WorkerEnv,
	options: EmailOptions
): Promise<{ sent: boolean; simulated: boolean }> {
	const from = `${SENDER_NAME} <${SENDER_EMAIL}>`;
	const headers = {
		'X-Mailer': 'secmy-waf-monitor',
		...(options.headers || {}),
	};

	if (env.SEND_EMAIL && typeof env.SEND_EMAIL.send === 'function') {
		await env.SEND_EMAIL.send({
			from: SENDER_EMAIL,
			to: options.to,
			subject: options.subject,
			text: options.text,
			html: options.html,
			headers,
		});
		return { sent: true, simulated: false };
	}

	console.log(`[SIMULATED EMAIL] To: ${options.to} | Subject: ${options.subject}`);
	return { sent: true, simulated: true };
}

export function buildVerificationEmail(data: {
	targetUrl: string;
	verifyUrl: string;
	mode: OwnershipMode;
	ownershipToken?: string;
}): { subject: string; html: string; text: string } {
	const subject = `[secmy.app] Подтвердите мониторинг безопасности для ${data.targetUrl}`;

	let instructionsHtml = '';
	let instructionsText = '';

	if (data.mode === 'external' && data.ownershipToken) {
		instructionsHtml = `
		<div style="background: #fdf6e2; border-left: 4px solid #b58900; padding: 12px; margin: 16px 0;">
			<p><strong>Требуется подтверждение владения доменом:</strong></p>
			<p>Так как домен вашей почты отличается от сканируемого сайта, создайте текстовый файл:</p>
			<code>${data.targetUrl}/.well-known/secmy-check.txt</code>
			<p>с содержимым:</p>
			<pre style="background: #eee; padding: 8px;">${data.ownershipToken}</pre>
			<p>После создания файла нажмите кнопку подтверждения ниже.</p>
		</div>`;
		instructionsText = `Требуется подтверждение владения: создайте файл ${data.targetUrl}/.well-known/secmy-check.txt с содержимым: ${data.ownershipToken}\n\n`;
	}

	const html = `
	<!DOCTYPE html>
	<html>
	<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #222; line-height: 1.5; padding: 20px;">
		<h2 style="color: #0052cc;">secmy.app — Мониторинг WAF</h2>
		<p>Был запрошен ежедневный мониторинг защиты для <strong>${data.targetUrl}</strong>.</p>
		${instructionsHtml}
		<p>
			<a href="${data.verifyUrl}" style="background-color: #0052cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Подтвердить мониторинг</a>
		</p>
		<p style="color: #666; font-size: 13px;">Ссылка действительна в течение 24 часов. Если вы не отправляли этот запрос, проигнорируйте письмо — никаких сканирований запущено не будет.</p>
	</body>
	</html>`;

	const text = `secmy.app — Мониторинг WAF\n\nБыл запрошен ежедневный мониторинг для ${data.targetUrl}.\n\n${instructionsText}Для подтверждения перейдите по ссылке:\n${data.verifyUrl}\n\nСсылка действительна 24 часа. Если вы не запрашивали проверку, проигнорируйте письмо.`;

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
	const prefix = data.isAlert ? '⚠️ [ВНИМАНИЕ]' : '🟢 [СТАТУС]';
	const subject = `${prefix} Отчет безопасности WAF для ${data.targetUrl}`;

	const detailsList = data.diffDetails.map((d) => `<li>${d}</li>`).join('');

	const html = `
	<!DOCTYPE html>
	<html>
	<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #222; line-height: 1.5; padding: 20px;">
		<h2 style="color: ${data.isAlert ? '#d9381e' : '#00875a'};">secmy.app — Ежедневный мониторинг WAF</h2>
		<p><strong>Ресурс:</strong> ${data.targetUrl}</p>
		<p><strong>Обнаруженный WAF:</strong> ${data.detectedWAF || 'Не обнаружен'}</p>
		<div style="background: #f4f5f7; padding: 14px; border-radius: 4px; margin: 16px 0;">
			<h4 style="margin-top: 0;">Изменения безопасности:</h4>
			<ul>${detailsList || '<li>Без критических изменений</li>'}</ul>
		</div>
		<p style="margin-top: 24px; font-size: 12px; color: #777; border-top: 1px solid #ddd; padding-top: 12px;">
			Вы получили это письмо, так как подписаны на мониторинг ${data.targetUrl}.<br/>
			<a href="${data.unsubscribeUrl}" style="color: #777;">Отписаться от уведомлений в 1 клик</a>
		</p>
	</body>
	</html>`;

	const text = `${prefix} Отчет безопасности WAF для ${data.targetUrl}\n\nОбнаруженный WAF: ${data.detectedWAF || 'Не обнаружен'}\n\nИзменения:\n${data.diffDetails.join('\n')}\n\nОтписаться: ${data.unsubscribeUrl}`;

	return { subject, html, text };
}
