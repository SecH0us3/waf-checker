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

	// AI assistants / LLM crawlers & retrieval agents. Increasingly allow-listed
	// (robots.txt, WAF managed rules, bot-management "verified bot" lists), so a
	// WAF that trusts these UAs is a real bypass surface. Strings taken from each
	// vendor's crawler docs where published, else widely-reported request logs —
	// version/token is what matters, since vendors bump versions and advise
	// matching on the token. NOTE: agentic coding tools (Claude Code, OpenAI
	// Codex, Google Antigravity) and robots-only product tokens (Google-Extended)
	// are intentionally excluded — they publish no stable crawler User-Agent.
	{ name: 'GPTBot', userAgent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.3; +https://openai.com/gptbot' },
	{ name: 'ChatGPT-User', userAgent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot' },
	{
		name: 'OAI-SearchBot',
		userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.4; +https://openai.com/searchbot',
	},
	{ name: 'ClaudeBot', userAgent: 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)' },
	{ name: 'Claude-User', userAgent: 'Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)' },
	{ name: 'PerplexityBot', userAgent: 'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)' },
	{ name: 'Perplexity-User', userAgent: 'Mozilla/5.0 (compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)' },
	{ name: 'Amazonbot', userAgent: 'Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)' },
	{ name: 'Meta-ExternalAgent', userAgent: 'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)' },
	{
		name: 'Bytespider',
		userAgent: 'Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)',
	},
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
