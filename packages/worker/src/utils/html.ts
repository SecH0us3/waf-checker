/**
 * Escapes a value for interpolation into an HTML text or attribute context.
 *
 * Server-rendered HTML here (verification emails, alert emails, the activation
 * page) embeds values that are attacker-influenced even after they pass URL
 * validation: `isValidTargetUrl` constrains the *host*, not the path or query,
 * so `https://ok.example/"><img src=x onerror=...>` is a legitimate target URL.
 * `wafDetected` is worse — it originates from the scanned host's own response
 * headers and is read back out of KV a day later.
 */
export function escapeHtml(value: unknown): string {
	return String(value ?? '')
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}
