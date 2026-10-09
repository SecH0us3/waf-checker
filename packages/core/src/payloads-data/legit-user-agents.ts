// Legitimate / trusted User-Agent strings used by the "User-Agent bypass" test.
//
// Many WAFs (or origin apps behind them) allow-list well-known crawlers,
// link-unfurlers and uptime monitors by their User-Agent. If an attack payload
// is blocked with a normal UA but sails through once the request claims to be
// Googlebot, Slackbot, etc., that allow-list is a real bypass. This module
// provides the curated identities we replay blocked requests with.

export interface LegitUserAgent {
	/** Short, human-friendly label shown in reports (e.g. "Googlebot"). */
	name: string;
	/** The exact User-Agent header value to send. */
	userAgent: string;
}

export const LEGIT_USER_AGENTS: LegitUserAgent[] = [
	// Search engine crawlers
	{ name: 'Googlebot', userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
	{
		name: 'Google-InspectionTool',
		userAgent: 'Mozilla/5.0 (compatible; Google-InspectionTool/1.0; +https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers)',
	},
	{ name: 'Bingbot', userAgent: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' },
	{ name: 'YandexBot', userAgent: 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)' },
	{ name: 'DuckDuckBot', userAgent: 'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)' },
	{ name: 'Applebot', userAgent: 'Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)' },

	// Messaging / social link-unfurlers
	{ name: 'Slackbot', userAgent: 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)' },
	{ name: 'Slack-ImgProxy', userAgent: 'Slack-ImgProxy (+https://api.slack.com/robots)' },
	{ name: 'facebookexternalhit', userAgent: 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)' },
	{ name: 'Twitterbot', userAgent: 'Twitterbot/1.0' },
	{ name: 'Discordbot', userAgent: 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)' },
	{ name: 'LinkedInBot', userAgent: 'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)' },
	{ name: 'TelegramBot', userAgent: 'TelegramBot (like TwitterBot)' },
	{ name: 'WhatsApp', userAgent: 'WhatsApp/2.23.20.0 A' },

	// Uptime / monitoring services
	{ name: 'UptimeRobot', userAgent: 'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)' },
	{ name: 'Pingdom', userAgent: 'Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)' },
];

/**
 * Resolve the `spoofUserAgents` option into a concrete list of identities.
 * - `false`/`undefined` → disabled (empty list).
 * - `true` → the full curated {@link LEGIT_USER_AGENTS} list.
 * - an array → used as-is (custom identities).
 */
export function resolveLegitUserAgents(spoof?: boolean | LegitUserAgent[]): LegitUserAgent[] {
	if (!spoof) return [];
	if (Array.isArray(spoof)) return spoof;
	return LEGIT_USER_AGENTS;
}

/**
 * Identities probed first on Cloudflare Workers, where the 50-subrequest budget
 * per invocation makes replaying every blocked payload against all identities
 * too expensive. Chosen to span categories on purpose: origins allow-list very
 * different bots, and a publishing/content site typically trusts social
 * link-unfurlers (Slackbot, facebookexternalhit) far more than search crawlers.
 *
 * A naive positional `slice()` of {@link LEGIT_USER_AGENTS} only ever reached
 * the first few search-engine crawlers (Googlebot, Google-InspectionTool,
 * Bingbot) and silently missed every social/unfurler allow-list bypass, so the
 * worker stopped reporting bypasses it used to find.
 */
export const WORKER_PROBE_PRIORITY: readonly string[] = ['Googlebot', 'Slackbot', 'facebookexternalhit'];

/**
 * Pick the subset of identities to probe on Cloudflare Workers, keeping the
 * subrequest budget bounded while preserving cross-category coverage.
 *
 * Entries named in {@link WORKER_PROBE_PRIORITY} come first (in that order);
 * any remaining slots are filled from the rest of the list in its own order, so
 * a custom list without the named identities still degrades gracefully to its
 * leading entries.
 */
export function selectWorkerProbeAgents(agents: LegitUserAgent[], limit: number = 3): LegitUserAgent[] {
	const prioritized = WORKER_PROBE_PRIORITY.map((name) => agents.find((a) => a.name === name)).filter(
		(a): a is LegitUserAgent => a !== undefined,
	);
	const rest = agents.filter((a) => !WORKER_PROBE_PRIORITY.includes(a.name));
	return [...prioritized, ...rest].slice(0, limit);
}
