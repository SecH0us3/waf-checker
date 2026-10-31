import { PAYLOADS, getEnhancedPayloads } from './payloads';
import { WAFDetector, WAFDetectionResult } from './waf-detection';
import { PayloadEncoder } from './encoding';
import {
	generateWAFSpecificPayloads,
	generateHTTPManipulationPayloads,
	ADVANCED_PAYLOADS,
	generateEncodedPayloads,
} from './advanced-payloads';
import { HTTPManipulationOptions, HTTPManipulator } from './http-manipulation';
import { isValidTargetUrl, isInScopeRedirect, applyOriginIpOverride } from './utils/security';
import { substitutePayload, processCustomHeaders, randomUppercase, seededRandom, redactHeaders, redactUrl } from './utils/payload-utils';
import { AuditResultItem, CheckResultEnvelope, UserAgentBypassInfo, IpHeaderBypassInfo } from './reports/types';
import { LegitUserAgent, resolveLegitUserAgents } from './payloads-data/legit-user-agents';
import { TrustedIpHeader, resolveTrustedIpHeaders } from './payloads-data/trusted-ip-headers';
import {
	BaselineProfile,
	computeBodySignature,
	areBodiesStructurallySimilar,
	isSoftBlockBody,
} from './baseline';
import { mapWithConcurrency } from './utils/concurrency';

/**
 * Replays a request that the WAF blocked (403) under a set of legitimate,
 * commonly allow-listed User-Agents (Googlebot, Slackbot, ...). If any of them
 * turns the block into a non-blocked response, the WAF is trusting the
 * User-Agent header — a real bypass worth surfacing.
 *
 * `reissue` re-issues the exact same request but with the given User-Agent
 * header injected/overridden; the caller owns the request shape so this works
 * uniformly for param, file and header checks.
 *
 * Every identity in the list is eligible (the worker and the CLI probe the
 * same list; the Worker's page size is sized for it, see maxWorkerPageSize).
 * The first identity goes alone, so a site that trusts it costs one probe. The
 * rest go through a pool of UA_PROBE_CONCURRENCY requests in flight, and no new
 * probe starts once one has got through. `hits` holds every identity that got
 * through (probes already in flight may add more than one); `tested` counts the
 * requests actually sent.
 */
async function probeUserAgentBypass(
	reissue: (userAgent: string) => Promise<any>,
	legitUserAgents: LegitUserAgent[],
	detection: WAFDetectionResult | undefined,
	probedPayload: string | undefined,
	baseline?: BaselineProfile,
): Promise<UserAgentBypassInfo> {
	const info: UserAgentBypassInfo = { bypassed: false, tested: 0, hits: [] };
	const probe = async (ua: LegitUserAgent) => {
		info.tested++;
		const res = await reissue(ua.userAgent).catch(() => undefined);
		const status = res ? res.status : 'ERR';
		// A network error or timeout says nothing about the WAF. Any other response
		// the WAF did not block got past it, whatever the origin then answered: a
		// 404, a 500 from a payload that broke a query, or a redirect.
		if (status === 'ERR') return;
		const { blocked, verdict } = evaluateWAFVerdict(status, res?.bodyText || '', detection, res?.response?.headers, probedPayload, baseline);
		if (blocked) return;
		info.bypassed = true;
		info.hits.push({ name: ua.name, userAgent: ua.userAgent, status, verdict: verdict as 'passed' | 'exposed' });
	};

	if (legitUserAgents.length === 0) return info;
	await probe(legitUserAgents[0]);
	let next = 1;
	const runProbes = async () => {
		while (!info.bypassed && next < legitUserAgents.length) {
			await probe(legitUserAgents[next++]);
		}
	};
	const poolSize = Math.min(UA_PROBE_CONCURRENCY, legitUserAgents.length - 1);
	await Promise.all(Array.from({ length: poolSize }, runProbes));
	return info;
}

/**
 * Replays a request that the WAF blocked (403/406) with a curated list of
 * proxy / IP-spoofing headers (X-Forwarded-For: 127.0.0.1, X-Real-IP, True-Client-IP, ...).
 * Mirrors `probeUserAgentBypass`: the first header goes alone, and any remaining
 * headers run through a pool of `UA_PROBE_CONCURRENCY` until a bypass is found.
 */
export async function probeIpHeaderBypass(
	reissue: (headerName: string, headerValue: string) => Promise<any>,
	trustedIpHeaders: TrustedIpHeader[],
	detection: WAFDetectionResult | undefined,
	probedPayload: string | undefined,
	baseline?: BaselineProfile,
): Promise<IpHeaderBypassInfo> {
	const info: IpHeaderBypassInfo = { bypassed: false, tested: 0, hits: [] };
	const probe = async (ipHeader: TrustedIpHeader) => {
		info.tested++;
		const res = await reissue(ipHeader.headerName, ipHeader.headerValue).catch(() => undefined);
		const status = res ? res.status : 'ERR';
		if (status === 'ERR') return;
		const { blocked, verdict } = evaluateWAFVerdict(status, res?.bodyText || '', detection, res?.response?.headers, probedPayload, baseline);
		if (blocked) return;
		info.bypassed = true;
		info.hits.push({
			name: ipHeader.name,
			headerName: ipHeader.headerName,
			headerValue: ipHeader.headerValue,
			status,
			verdict: verdict as 'passed' | 'exposed',
		});
	};

	if (trustedIpHeaders.length === 0) return info;
	await probe(trustedIpHeaders[0]);
	let next = 1;
	const runProbes = async () => {
		while (!info.bypassed && next < trustedIpHeaders.length) {
			await probe(trustedIpHeaders[next++]);
		}
	};
	const poolSize = Math.min(UA_PROBE_CONCURRENCY, trustedIpHeaders.length - 1);
	await Promise.all(Array.from({ length: poolSize }, runProbes));
	return info;
}

/**
 * Trusted-UA / IP-header probes in flight at once per blocked request. Kept below
 * the Workers limit of 6 simultaneously open connections.
 */
export const UA_PROBE_CONCURRENCY = 4;

/** Redirect hops sendRequest follows when followRedirect is on. */
export const MAX_REDIRECTS = 5;

/**
 * Cloudflare Workers subrequest limit per invocation: the Workers Paid default
 * since 2026-02 (it was 1000 before). Pinned with `[limits] subrequests` in
 * wrangler.toml so the deployment cannot silently fall below what this assumes;
 * change both together.
 */
export const WORKER_SUBREQUEST_LIMIT = 10_000;

/**
 * Subrequests held back from the page budget: inline WAF detection
 * (WAFDetector.activeDetection on the Worker is a baseline plus 4 payload
 * probes, each following up to 3 redirects = 20 fetches; the /cdn-cgi probe is
 * skipped on the Worker) plus baseline calibration and a small safety margin.
 */
const WORKER_RESERVED_SUBREQUESTS = 50;

/**
 * Largest page one Worker invocation can scan within WORKER_SUBREQUEST_LIMIT.
 * Each page is a separate invocation with its own budget, so paging is what
 * lets a scan of any size run; this only has to keep a single page within it.
 * Worst case per item is one baseline plus one probe per trusted identity and
 * trusted IP header, each following up to MAX_REDIRECTS hops when followRedirect is on.
 * handleApiCheckWithEnvelope clamps every Worker page to it.
 */
export function maxWorkerPageSize(opts: {
	legitUserAgentCount: number;
	trustedIpHeaderCount?: number;
	followRedirect: boolean;
}): number {
	const fetchesPerRequest = opts.followRedirect ? MAX_REDIRECTS + 1 : 1;
	const perItem = (1 + opts.legitUserAgentCount + (opts.trustedIpHeaderCount || 0)) * fetchesPerRequest;
	return Math.max(1, Math.floor((WORKER_SUBREQUEST_LIMIT - WORKER_RESERVED_SUBREQUESTS) / perItem));
}

// Helper function to send request with specified method and payload
export async function sendRequest(
	url: string,
	method: string,
	payload?: string,
	headersObj?: Record<string, string>,
	payloadTemplate?: string,
	followRedirect: boolean = false,
	useEnhancedPayloads: boolean = false,
	detectedWAF?: string,
	httpManipulation?: HTTPManipulationOptions,
	options?: { fetch?: typeof fetch; color?: boolean; quiet?: boolean; rawPayload?: boolean; allowLocal?: boolean; originIpOverride?: string },
) {
	const fetchFn = options?.fetch || globalThis.fetch;
	try {
		let resp: Response;
		const headers = headersObj ? new Headers(headersObj) : undefined;
		const startTime = Date.now();

		// Apply WAF-specific payload modifications if WAF is detected
		let finalPayload = payload;
		if (detectedWAF && payload) {
			const wafSpecificPayloads = generateWAFSpecificPayloads(detectedWAF, payload);
			if (wafSpecificPayloads.length > 1) {
				finalPayload = wafSpecificPayloads[1]; // Use first bypass variation
			}
		}

		// Build the final URL: if it contains {PAYLOAD}, substitute directly;
		// otherwise append as a query parameter using ? or &
		let finalUrl = url;
		if (finalPayload !== undefined) {
			if (url.includes('{PAYLOAD}')) {
				finalUrl = url.replace(/\{PAYLOAD\}/g, options?.rawPayload ? finalPayload : encodeURIComponent(finalPayload));
			} else if (method === 'GET' || method === 'DELETE') {
				const separator = url.includes('?') ? '&' : '?';
				if (finalPayload.startsWith('junk=') || options?.rawPayload) {
					finalUrl = url + `${separator}${finalPayload}`;
				} else {
					finalUrl = url + `${separator}test=${encodeURIComponent(finalPayload)}`;
				}
			}
		}

		// Validate finalUrl after substitution to prevent SSRF
		if (!isValidTargetUrl(finalUrl, { allowLocal: options?.allowLocal })) {
			console.error(`Blocked SSRF attempt to: ${redactUrl(finalUrl)}`);
			return { status: 'BLOCKED', is_redirect: false, responseTime: 0, error: 'ssrf_blocked', bodyText: '' };
		}

		// Origin-IP bypass test: resolve the target hostname to a user-supplied origin
		// IP. This is the WAF-bypass case where the operator knows the IP the WAF
		// forwards to and wants to check whether that origin is reachable (and
		// unprotected) directly. The request URL stays on the domain so the Host
		// header and TLS SNI remain correct (both are derived from the URL, and `Host`
		// is a forbidden request header that cannot be overridden); only the DNS
		// lookup is steered to the IP via cf.resolveOverride below.
		let overrideResolveIp: string | undefined;
		if (options?.originIpOverride) {
			const override = applyOriginIpOverride(finalUrl, options.originIpOverride);
			// The IP is validated by applyOriginIpOverride (public ranges only); a null
			// result means it was private/reserved/malformed — refuse rather than fetch.
			if (!override) {
				console.error('Blocked invalid or restricted origin IP override');
				return { status: 'BLOCKED', is_redirect: false, responseTime: 0, error: 'invalid_origin_ip', bodyText: '' };
			}
			overrideResolveIp = override.resolveIp;
		}

		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 10000);
		let responseTime = 0;
		let bodyText = '';

		try {
			// Manual redirect handling to prevent SSRF bypass
			let currentUrl = finalUrl;
			let currentMethod = method;
			let currentHeaders = headers;
			let currentBody: any = undefined;

			if (method === 'POST' || method === 'PUT') {
				if (payloadTemplate) {
					let jsonObj;
					try {
						jsonObj = JSON.parse(payloadTemplate);
						jsonObj = substitutePayload(jsonObj, finalPayload ?? '');
					} catch {
						jsonObj = { test: finalPayload ?? '' };
					}
					currentBody = JSON.stringify(jsonObj);
					const newHeaders = new Headers(currentHeaders || {});
					newHeaders.set('Content-Type', 'application/json');
					currentHeaders = newHeaders;
				} else if (finalPayload?.startsWith('junk=') || options?.rawPayload) {
					currentBody = finalPayload;
					const newHeaders = new Headers(currentHeaders || {});
					if (!newHeaders.has('Content-Type')) {
						newHeaders.set('Content-Type', 'application/x-www-form-urlencoded');
					}
					currentHeaders = newHeaders;
				} else {
					currentBody = new URLSearchParams({ test: finalPayload ?? '' });
				}
			}

			let redirectCount = 0;
			const maxRedirects = MAX_REDIRECTS;

			while (true) {
				const fetchOptions: RequestInit & { cf?: Record<string, unknown> } = {
					method: currentMethod,
					redirect: 'manual',
					headers: currentHeaders,
					body: currentBody,
					signal: controller.signal,
					// On Cloudflare Workers, resolveOverride steers the DNS lookup to the
					// chosen origin IP while the request URL — and therefore the Host
					// header and TLS SNI — stay on the target domain. Set per hop because
					// fetchOptions is rebuilt each redirect. Harmless where unsupported
					// (ignored by non-Workers fetch and by the test mock).
					...(overrideResolveIp ? { cf: { resolveOverride: overrideResolveIp } } : {}),
				};

				resp = await fetchFn(currentUrl, fetchOptions);

				if (followRedirect && resp.status >= 300 && resp.status < 400 && redirectCount < maxRedirects) {
					const location = resp.headers.get('Location');
					if (!location) break;

					const nextUrl = new URL(location, currentUrl).toString();
					if (!isValidTargetUrl(nextUrl, { allowLocal: options?.allowLocal })) {
						console.error(`Blocked SSRF redirect attempt to: ${redactUrl(nextUrl)}`);
						return { status: 'BLOCKED', is_redirect: true, responseTime: Date.now() - startTime, error: 'ssrf_blocked', bodyText: '' };
					}
					// Leaving the target's own domain means the response would describe some
					// other host, so stop here and report the redirect itself.
					if (!isInScopeRedirect(currentUrl, nextUrl)) {
						break;
					}

					const status = resp.status;
					// Standard HTTP behavior for redirects
					if (status === 301 || status === 302 || status === 303) {
						currentMethod = 'GET';
						currentBody = undefined;
						if (currentHeaders) {
							const newHeaders = new Headers(currentHeaders);
							newHeaders.delete('Content-Type');
							newHeaders.delete('Content-Length');
							currentHeaders = newHeaders;
						}
					}
					// For 307 and 308, we keep the original method and body

					// Release this hop's connection before opening the next one, so
					// concurrent probes following redirects do not pile up open sockets.
					try {
						await resp.body?.cancel();
					} catch {}
					currentUrl = nextUrl;
					redirectCount++;
					continue;
				}
				break;
			}

			responseTime = Date.now() - startTime;
			// Read the body while the timeout is still armed: the abort signal also
			// ends a body that trickles in, so the whole request, body included, stays
			// within the 10s budget callers rely on (e.g. the scheduled run's deadline).
			// Read the response itself, not a clone: clone() tees the stream, and the
			// unread branch would buffer a second copy of the whole body. Callers only
			// use bodyText and the response's status and headers.
			try {
				bodyText = await resp.text();
			} catch {}
		} finally {
			clearTimeout(timeoutId);
		}

		let logMsg: string;
		if (options?.color) {
			const whitePart = `\x1b[97mRequest to ${redactUrl(url)}\x1b[0m`;
			const methodPart = `\x1b[33m${method}\x1b[0m`;
			const payloadPart = `\x1b[36m${payload ?? '(none)'}\x1b[0m`;
			const headersPart = `\x1b[90m${JSON.stringify(redactHeaders(headersObj))}\x1b[0m`;
			
			let statusPart = String(resp.status);
			if (resp.status === 403) {
				statusPart = `\x1b[32m403\x1b[0m`;
			} else if (resp.status >= 200 && resp.status < 300) {
				statusPart = `\x1b[31m${resp.status}\x1b[0m`;
			} else if (resp.status >= 300 && resp.status < 400) {
				statusPart = `\x1b[33m${resp.status}\x1b[0m`;
			} else {
				statusPart = `\x1b[31m${resp.status}\x1b[0m`;
			}

			logMsg = `${whitePart} with method ${methodPart} and payload ${payloadPart} and headers ${headersPart} returned status ${statusPart} in ${responseTime}ms`;
		} else {
			logMsg = `Request to ${redactUrl(url)} with method ${method} and payload ${payload ?? '(none)'} and headers ${JSON.stringify(redactHeaders(headersObj))} returned status ${resp.status} in ${responseTime}ms`;
		}
		if (!options?.quiet) {
			console.log(logMsg);
		}

		return {
			status: resp.status,
			is_redirect: resp.status >= 300 && resp.status < 400,
			responseTime,
			response: resp,
			bodyText,
			error: null,
		};
	} catch (e: any) {
		console.error(`Request error for ${redactUrl(url)}:`, e);
		let errorType = 'network_error';
		if (e && (e.name === 'AbortError' || e.message?.toLowerCase().includes('aborted') || e.message?.toLowerCase().includes('timeout'))) {
			errorType = 'timeout';
		} else if (e && (e.code === 'ENOTFOUND' || e.message?.toLowerCase().includes('dns') || e.message?.toLowerCase().includes('getaddrinfo'))) {
			errorType = 'dns';
		} else if (e && (e.code === 'ECONNRESET' || e.message?.toLowerCase().includes('reset'))) {
			errorType = 'connection_reset';
		}
		return { status: 'ERR', is_redirect: false, responseTime: 0, error: errorType, bodyText: '' };
	}
}

/**
 * Checks whether a response body plausibly matches the expected content of a requested artifact.
 * Prevents SPAs and frameworks that return 200 with an HTML shell for unknown paths from being
 * falsely classified as 'exposed'.
 */
export function isPlausibleArtifactContent(bodyText: string, probedPayload?: string): boolean {
	if (!bodyText || bodyText.trim().length === 0) {
		return false;
	}

	const trimmed = bodyText.trimStart();
	const isHtml = /^(?:<!doctype\s+html|<html[\s>])/i.test(trimmed);

	const cleanTarget = probedPayload ? probedPayload.split(/[?#]/)[0].trim().toLowerCase() : '';
	const filename = cleanTarget.split('/').pop() || cleanTarget;
	const isHtmlTarget = filename.endsWith('.html') || filename.endsWith('.htm');

	// If the response is an HTML document but the requested artifact is not an HTML file,
	// it's an SPA shell, custom 404-as-200 page, or generic application HTML — not a leak.
	if (isHtml && !isHtmlTarget) {
		return false;
	}

	// 1. .env files
	if (filename === '.env' || filename.startsWith('.env.') || filename.endsWith('.env')) {
		return !isHtml && /^[A-Z_][A-Z0-9_]*=/m.test(bodyText);
	}

	// 2. .git/config
	if (cleanTarget.endsWith('.git/config') || (filename === 'config' && cleanTarget.includes('.git'))) {
		return !isHtml && bodyText.includes('[core]');
	}

	// 3. .git/HEAD
	if (cleanTarget.endsWith('.git/head') || (filename === 'head' && cleanTarget.includes('.git'))) {
		return !isHtml && /^ref:\s*refs\//m.test(bodyText);
	}

	// 4. Other .git paths (.git directory, .git/index, etc.)
	if (cleanTarget === '.git' || cleanTarget.endsWith('/.git')) {
		return !isHtml && (bodyText.includes('[core]') || /^ref:\s*refs\//m.test(bodyText) || bodyText.startsWith('DIRC'));
	}

	// 5. composer.json / package.json and lockfiles
	if (filename === 'package.json') {
		if (isHtml) return false;
		try {
			const parsed = JSON.parse(bodyText);
			if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
				const expectedKeys = [
					'name',
					'version',
					'dependencies',
					'devDependencies',
					'scripts',
					'main',
					'description',
					'author',
					'license',
					'repository',
				];
				return expectedKeys.some((k) => k in parsed);
			}
		} catch {
			return false;
		}
		return false;
	}

	if (filename === 'composer.json') {
		if (isHtml) return false;
		try {
			const parsed = JSON.parse(bodyText);
			if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
				const expectedKeys = ['name', 'require', 'require-dev', 'description', 'autoload', 'type', 'license', 'authors'];
				return expectedKeys.some((k) => k in parsed);
			}
		} catch {
			return false;
		}
		return false;
	}

	if (filename === 'package-lock.json' || filename === 'composer.lock') {
		if (isHtml) return false;
		try {
			const parsed = JSON.parse(bodyText);
			if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
				return 'packages' in parsed || 'dependencies' in parsed || 'lockfileVersion' in parsed;
			}
		} catch {
			return false;
		}
		return false;
	}

	// 6. .sql dumps
	if (filename.endsWith('.sql')) {
		return !isHtml && /(?:CREATE\s+TABLE|INSERT\s+INTO)/i.test(bodyText);
	}

	// 7. Archives (.zip, .tar.gz, .tgz, .tar, .gz, .7z, .rar, .bz2, .xz, .bak)
	if (filename.endsWith('.zip') || filename.endsWith('.war')) {
		return !isHtml && (bodyText.includes('PK\x03\x04') || bodyText.includes('PK\x05\x06') || bodyText.includes('PK\x07\x08'));
	}
	if (filename.endsWith('.tar.gz') || filename.endsWith('.tgz') || filename.endsWith('.gz')) {
		return !isHtml && bodyText.includes('\x1f\x8b');
	}
	if (filename.endsWith('.7z')) {
		return !isHtml && bodyText.includes('7z\xbc\xaf\x27\x1c');
	}
	if (filename.endsWith('.tar')) {
		return !isHtml && bodyText.includes('ustar');
	}
	if (filename.endsWith('.bak')) {
		return (
			!isHtml &&
			(bodyText.includes('PK\x03\x04') ||
				bodyText.includes('\x1f\x8b') ||
				/(?:CREATE\s+TABLE|INSERT\s+INTO)/i.test(bodyText) ||
				/^[A-Z_][A-Z0-9_]*=/m.test(bodyText) ||
				bodyText.includes('[core]'))
		);
	}

	// 8. .htaccess / .htpasswd
	if (filename === '.htaccess') {
		return (
			!isHtml &&
			/(?:RewriteEngine|RewriteRule|RewriteCond|Options|AuthType|Require|Order\s+(?:allow,deny|deny,allow)|Deny\s+from|Allow\s+from)/i.test(
				bodyText
			)
		);
	}
	if (filename === '.htpasswd') {
		return !isHtml && /^[a-zA-Z0-9_.-]+:(?:\$|\{SHA\}|[a-zA-Z0-9./]{13})/m.test(bodyText);
	}

	// 9. Crypto keys / certs
	if (filename === 'id_rsa' || filename.endsWith('.pem') || filename.endsWith('.key') || filename.endsWith('.crt')) {
		return !isHtml && /-----BEGIN [A-Z0-9 ]+-----/.test(bodyText);
	}
	if (filename === 'id_rsa.pub') {
		return !isHtml && /^ssh-(?:rsa|ed25519|dss)\s+/m.test(bodyText);
	}

	// 10. PHP configs
	if (filename === 'wp-config.php') {
		return !isHtml && /(?:DB_NAME|DB_USER|DB_PASSWORD|table_prefix|AUTH_KEY|SECURE_AUTH_KEY)/i.test(bodyText);
	}
	if (filename === 'config.php') {
		return !isHtml && /(?:<\?php|\$config|\$_CONFIG|db_password|database)/i.test(bodyText);
	}

	// Generic fallback:
	// If the body is HTML while the requested artifact is not HTML, it's not a leak.
	// Otherwise, non-empty non-HTML body matches the generic non-HTML probe.
	return !isHtml || isHtmlTarget;
}

/**
 * Evaluates whether a request response represents a WAF block and derives
 * a coarse verdict:
 * - 'blocked': WAF stopped the request before reaching origin.
 * - 'exposed': not blocked AND origin returned resource matching the probed artifact.
 * - 'passed': not blocked, but origin did not serve resource (404, 5xx, empty 2xx, or SPA HTML shell).
 */
export function evaluateWAFVerdict(
	status: number | string,
	bodyText: string = '',
	detection?: WAFDetectionResult,
	headers?: Headers,
	probedPayload?: string,
	baseline?: BaselineProfile,
): { blocked: boolean; verdict: 'blocked' | 'passed' | 'exposed'; baselineNote?: 'origin_blocked' | 'custom_block_page' } {
	let isBlocked = false;
	let hasExplicitWafSignal = false;

	// Characteristic WAF block status codes
	if (
		status === 403 ||
		status === '403' ||
		status === 406 ||
		status === '406' ||
		status === 429 ||
		status === '429' ||
		status === 'BLOCKED'
	) {
		isBlocked = true;
		if (status === 'BLOCKED') {
			hasExplicitWafSignal = true;
		}
	}

	// Response-level headers check
	if (headers) {
		const cfMitigated = headers.get('cf-mitigated');
		if (cfMitigated && (cfMitigated === 'challenge' || cfMitigated === 'block')) {
			isBlocked = true;
			hasExplicitWafSignal = true;
		}
		if (isBlocked) {
			const serverHdr = (headers.get('server') || '').toLowerCase();
			if (
				headers.get('cf-ray') ||
				headers.get('x-sucuri-id') ||
				headers.get('x-iinfo') ||
				headers.get('x-akamai-transformed') ||
				headers.get('x-amzn-waf-action') ||
				headers.get('x-wordfence-blocked') ||
				headers.get('x-bunkerweb') ||
				headers.get('x-coraza') ||
				/cloudflare|akamaighost|cloudfront|sucuri|big-ip|fortiweb|fortigate|bunkerweb|coraza|ddos-guard|qrator|stormwall|mod_security|barracuda/.test(
					serverHdr,
				)
			) {
				hasExplicitWafSignal = true;
			}
		}
	}

	if (isBlocked && detection?.detected) {
		hasExplicitWafSignal = true;
	}

	// Response-level body markers check
	if (bodyText) {
		// Captcha challenges in this response's body
		if (
			bodyText.includes('cf-turnstile') ||
			/https?:\/\/challenges\.cloudflare\.com\/turnstile\//.test(bodyText) ||
			/https?:\/\/(?:www\.)?google\.com\/recaptcha\//.test(bodyText) ||
			bodyText.includes('g-recaptcha') ||
			/https?:\/\/(?:www\.)?hcaptcha\.com\//.test(bodyText) ||
			bodyText.includes('h-captcha')
		) {
			isBlocked = true;
			hasExplicitWafSignal = true;
		} else if (
			// Imperva / Incapsula block markers anchored to vendor context or fuller block page phrasing
			((detection?.wafType === 'Imperva' ||
				detection?.wafType === 'Incapsula' ||
				/incapsula|imperva/i.test(bodyText)) &&
				/incident id/i.test(bodyText)) ||
			/request unsuccessful\. incapsula incident id/i.test(bodyText)
		) {
			isBlocked = true;
			hasExplicitWafSignal = true;
		} else if (
			// General WAF block markers
			/waf-block|blocked by[^\n]{0,100}waf|request blocked|access denied[^\n]{0,100}firewall|security incident|web application firewall/i.test(bodyText) ||
			/powered by[^\n]{0,100}imperva|protected with[^\n]{0,100}bunkerweb/i.test(bodyText)
		) {
			isBlocked = true;
			hasExplicitWafSignal = true;
		} else if (
			isBlocked &&
			/attention required! \| cloudflare|cloudflare ray id:|<title>just a moment\.\.\.<\/title>|\/cdn-cgi\/(?:challenge-platform|styles\/cf\.errors)|sorry, you have been blocked|generated by cloudfront|the request could not be satisfied|sucuri website firewall|mod_security|request blocked by security policy|the requested url was rejected|your support id is|generated by wordfence|web filter violation|errors\.aliyun\.com|stormwall|qrator|ddos-guard/i.test(
				bodyText,
			)
		) {
			hasExplicitWafSignal = true;
		}
	}

	const numStatus = typeof status === 'number' ? status : parseInt(String(status), 10);
	const baselineNumStatus =
		baseline && baseline.status !== undefined
			? typeof baseline.status === 'number'
				? baseline.status
				: parseInt(String(baseline.status), 10)
			: NaN;

	// Baseline Case A: Origin-403 disambiguation.
	// If the origin already returned 403/406 on a benign request (without WAF signals)
	// and the attack response returns the same status and structurally similar body
	// without explicit WAF headers/markers, it's an origin auth/rejection, not a WAF block.
	if (
		isBlocked &&
		!hasExplicitWafSignal &&
		baseline?.isOriginBlocked &&
		!isNaN(numStatus) &&
		numStatus === baselineNumStatus &&
		areBodiesStructurallySimilar(
			computeBodySignature(bodyText),
			bodyText.length,
			baseline.bodySignature,
			baseline.bodyLength,
		)
	) {
		return { blocked: false, verdict: 'passed', baselineNote: 'origin_blocked' };
	}

	// Baseline Case B: Custom Soft-Block Page (200 OK or 400 Bad Request).
	// If the benign baseline was a normal 200 OK, and this response returned 200 or 400
	// with a structurally different body containing explicit security rejection phrases,
	// classify it as blocked.
	if (
		!isBlocked &&
		baseline &&
		baselineNumStatus === 200 &&
		(numStatus === 200 || numStatus === 400) &&
		bodyText &&
		!areBodiesStructurallySimilar(
			computeBodySignature(bodyText),
			bodyText.length,
			baseline.bodySignature,
			baseline.bodyLength,
		) &&
		isSoftBlockBody(bodyText)
	) {
		return { blocked: true, verdict: 'blocked', baselineNote: 'custom_block_page' };
	}

	// 2. Derive verdict
	if (isBlocked) {
		return { blocked: true, verdict: 'blocked' };
	}

	if (!isNaN(numStatus) && numStatus >= 200 && numStatus < 300) {
		if (bodyText && bodyText.trim().length > 0 && isPlausibleArtifactContent(bodyText, probedPayload)) {
			return { blocked: false, verdict: 'exposed' };
		}
		return { blocked: false, verdict: 'passed' };
	}

	return { blocked: false, verdict: 'passed' };
}

/**
 * Sends a single benign reference request to build a BaselineProfile for
 * disambiguating origin-level 403/401 responses and detecting custom soft-block pages.
 */
export async function captureBaseline(
	url: string,
	method: string = 'GET',
	customHeaders?: string,
	payloadTemplate?: string,
	followRedirect: boolean = false,
	detection?: WAFDetectionResult,
	options?: { fetch?: typeof fetch; color?: boolean; quiet?: boolean; allowLocal?: boolean },
): Promise<BaselineProfile> {
	const benignToken = 'waf_baseline_check_9a7c';
	const headersObj = customHeaders ? processCustomHeaders(customHeaders, benignToken) : undefined;
	const res = await sendRequest(
		url,
		method,
		benignToken,
		headersObj,
		payloadTemplate,
		followRedirect,
		false,
		detection?.detected ? detection.wafType : undefined,
		undefined,
		options,
	);

	const status = res ? res.status : 'ERR';
	const bodyText = res?.bodyText || '';
	const contentType = res?.response?.headers?.get('content-type')?.split(';')[0]?.trim().toLowerCase() || '';
	const bodySignature = computeBodySignature(bodyText);
	const bodyLength = bodyText.length;

	if (status === 'ERR' || status === 'BLOCKED') {
		return {
			status,
			contentType,
			bodyLength,
			bodySignature,
			wafBlockedOnBenign: status === 'BLOCKED',
			isOriginBlocked: false,
		};
	}

	const numStatus = typeof status === 'number' ? status : parseInt(String(status), 10);
	const is403Or406 = numStatus === 403 || numStatus === 406;

	// Check if explicit WAF markers fired on the benign request itself.
	// Passing a synthetic isOriginBlocked=true baseline to evaluateWAFVerdict lets us
	// inspect whether `hasExplicitWafSignal` kept `blocked: true` on a 403/406 response.
	const rawVerdict = evaluateWAFVerdict(status, bodyText, detection, res?.response?.headers, benignToken);
	const originProbeVerdict = is403Or406
		? evaluateWAFVerdict(status, bodyText, detection, res?.response?.headers, benignToken, {
				status,
				contentType,
				bodyLength,
				bodySignature,
				wafBlockedOnBenign: false,
				isOriginBlocked: true,
			})
		: rawVerdict;

	const trimmedBody = bodyText.trim();
	const isHtmlBody =
		contentType.includes('text/html') || /^(?:<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>])/i.test(trimmedBody);
	const hasAuthKeywords =
		/unauthorized|unauthenticated|missing api key|invalid api key|bearer token|invalid token|authentication required|login required/i.test(
			trimmedBody,
		);
	const isLikelyOriginAuthResponse = !isHtmlBody || hasAuthKeywords;

	const wafBlockedOnBenign = is403Or406
		? originProbeVerdict.blocked || !isLikelyOriginAuthResponse
		: rawVerdict.blocked;
	const isOriginBlocked = is403Or406 && !wafBlockedOnBenign && rawVerdict.blocked && isLikelyOriginAuthResponse;

	return {
		status,
		contentType,
		bodyLength,
		bodySignature,
		wafBlockedOnBenign,
		isOriginBlocked,
	};
}

/**
 * Per-payload ParamCheck variation counts, keyed by the scan options that shape
 * them. The payload lists are module constants, so a count stays valid for the
 * life of the process (a Worker isolate serves the later pages of a scan from
 * it). Bounded so distinct option combinations cannot grow it without limit.
 */
const paramVariationCountCache = new Map<string, Map<string, Uint32Array>>();
const PARAM_VARIATION_COUNT_CACHE_SIZE = 16;

function rememberVariationCounts(key: string, counts: Map<string, Uint32Array>): void {
	if (paramVariationCountCache.size >= PARAM_VARIATION_COUNT_CACHE_SIZE) {
		const oldest = paramVariationCountCache.keys().next().value;
		if (oldest !== undefined) paramVariationCountCache.delete(oldest);
	}
	paramVariationCountCache.set(key, counts);
}

export interface CheckExecutionOptions {
	fetch?: typeof fetch;
	color?: boolean;
	quiet?: boolean;
	isWorker?: boolean;
	allowLocal?: boolean;
	pageSize?: number;
	/**
	 * Origin-IP bypass test. When set to a public IP literal, every scan request
	 * connects to that IP while still sending the target's hostname as the Host
	 * header — the "I know the origin behind the WAF" bypass check. Validated as a
	 * public IP before use (see applyOriginIpOverride / isValidOriginIp).
	 */
	originIpOverride?: string;
	/**
	 * Legitimate-User-Agent bypass test. `true` uses the curated list of
	 * trusted identities; an array supplies custom ones; falsy disables it.
	 * Blocked (403) requests are replayed under each identity to detect a
	 * User-Agent allow-list bypass.
	 */
	spoofUserAgents?: boolean | LegitUserAgent[];
	/**
	 * Trusted IP / proxy header bypass test. `true` uses the curated list of
	 * IP-spoofing headers (X-Forwarded-For: 127.0.0.1, X-Real-IP, True-Client-IP, ...);
	 * an array supplies custom ones; falsy disables it.
	 */
	spoofIpHeaders?: boolean | TrustedIpHeader[];
	/**
	 * Baseline calibration before scanning. `true` sends one benign calibration
	 * request; a `BaselineProfile` object reuses a previously captured baseline
	 * (e.g. across pages of a multi-page scan).
	 */
	calibrateBaseline?: boolean | BaselineProfile;
	/**
	 * Maximum number of scan items to execute in parallel (default: 1, preserving
	 * sequential behavior unless specified). Automatically steps down on 429 responses.
	 */
	concurrency?: number;
}

export async function handleApiCheckWithEnvelope(
	url: string,
	page: number,
	methods: string[],
	categories?: string[],
	payloadTemplate?: string,
	followRedirect: boolean = false,
	customHeaders?: string,
	falsePositiveTest: boolean = false,
	caseSensitiveTest: boolean = false,
	useEnhancedPayloads: boolean = false,
	useAdvancedPayloads: boolean = false,
	autoDetectWAF: boolean = false,
	useEncodingVariations: boolean = false,
	detectedWAF?: string,
	httpManipulation?: HTTPManipulationOptions,
	options?: CheckExecutionOptions,
): Promise<CheckResultEnvelope> {
	const METHODS = methods && methods.length ? methods : ['GET'];
	// Legitimate-User-Agent and Trusted-IP-Header bypass lists
	const legitUserAgents = resolveLegitUserAgents(options?.spoofUserAgents);
	const trustedIpHeaders = resolveTrustedIpHeaders(options?.spoofIpHeaders);
	let baseUrl: string;
	// Payloads per page. On the Worker, a page is clamped to what one invocation's
	// subrequest budget allows for this scan's identity/header lists and redirect setting;
	// the CLI has no such limit.
	const requestedPageSize =
		options?.pageSize !== undefined && Number.isFinite(options.pageSize) && options.pageSize > 0 ? Math.floor(options.pageSize) : 50;
	const limit = options?.isWorker
		? Math.min(
				requestedPageSize,
				maxWorkerPageSize({
					legitUserAgentCount: legitUserAgents.length,
					trustedIpHeaderCount: trustedIpHeaders.length,
					followRedirect,
				}),
			)
		: requestedPageSize;
	const start = page * limit;
	const end = start + limit;
	let offset = 0;
	try {
		const u = new URL(url);
		baseUrl = `${u.protocol}//${u.host}`;
	} catch {
		baseUrl = url;
	}

	// Case sensitive test: Modify URL hostname if flag is set
	if (caseSensitiveTest) {
		try {
			const u = new URL(url);
			const originalHostname = u.hostname;
			const modifiedHostname = randomUppercase(originalHostname);
			// Replace hostname only in the host portion of the URL (protocol://host)
			// to avoid accidentally replacing hostname matches in path/query
			const protocolAndSlashes = u.protocol + '//';
			const hostPortion = url.slice(protocolAndSlashes.length);
			const hostEnd = hostPortion.indexOf('/') === -1 ? hostPortion.length : hostPortion.indexOf('/');
			const hostPart = hostPortion.slice(0, hostEnd);
			const rest = hostPortion.slice(hostEnd);
			const newHostPart = hostPart.replace(originalHostname, modifiedHostname);
			url = protocolAndSlashes + newHostPart + rest;
			baseUrl = `${u.protocol}//${newHostPart}`;
		} catch (e) {
			url = randomUppercase(url);
			baseUrl = randomUppercase(baseUrl);
		}
	}

	// Auto-detect WAF if requested
	let wafDetectionResult: WAFDetectionResult | undefined;
	if (autoDetectWAF && detectedWAF) {
		// The caller already detected the WAF (the UI does so once before paging).
		// Re-probing here would repeat the whole detection against the target on
		// every page, so carry the known type instead. Only `detected` and
		// `wafType` are read below; the result is never returned to the caller.
		wafDetectionResult = {
			detected: true,
			wafType: detectedWAF,
			confidence: 100,
			confidencePercent: 100,
			confidenceThreshold: 40,
			evidence: ['WAF type supplied by caller'],
			suggestedBypassTechniques: [],
		};
	} else if (autoDetectWAF) {
		try {
			wafDetectionResult = await WAFDetector.activeDetection(url.replace(/\{PAYLOAD\}/g, ''), options);
			if (!options?.quiet) {
				console.log(`WAF Detection Result: ${JSON.stringify(wafDetectionResult)}`);
			}
		} catch (e) {
			if (!options?.quiet) {
				console.error('WAF detection failed:', e);
			}
		}
	}

	// Baseline calibration if requested
	let baselineProfile: BaselineProfile | undefined;
	if (options?.calibrateBaseline) {
		if (typeof options.calibrateBaseline === 'object') {
			baselineProfile = options.calibrateBaseline;
		} else {
			try {
				baselineProfile = await captureBaseline(
					url,
					METHODS[0] || 'GET',
					customHeaders,
					payloadTemplate,
					followRedirect,
					wafDetectionResult,
					options,
				);
			} catch (e) {
				if (!options?.quiet) {
					console.error('Baseline calibration failed:', e);
				}
			}
		}
	}

	// Choose payload source based on options
	let payloadSource = useEnhancedPayloads ? getEnhancedPayloads() : PAYLOADS;

	// Add advanced payloads if requested
	if (useAdvancedPayloads) {
		payloadSource = { ...payloadSource, ...ADVANCED_PAYLOADS };
	}

	const payloadEntries =
		(categories && categories.length
			? Object.entries(payloadSource).filter(([cat]) => categories.includes(cat))
			: Object.entries(payloadSource)) as [string, any][];

	// ParamCheck payloads expand into WAF-specific and encoding variations. Plan
	// them once, up front, so the reported total counts exactly the requests the
	// loop below makes.
	const wafTypeForVariations = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);
	const planParamVariations = (payload: string, category: string): string[] => {
		const payloadVariations = [payload];

		// Add WAF-specific bypass variations if WAF is detected
		if (wafTypeForVariations) {
			const wafSpecificPayloads = generateWAFSpecificPayloads(wafTypeForVariations, payload);
			if (wafSpecificPayloads.length > 1) {
				payloadVariations.push(...wafSpecificPayloads.slice(1));
			}
		}

		// Add encoding variations if enabled (works alongside WAF-specific)
		if (useEncodingVariations) {
			payloadVariations.push(...PayloadEncoder.generateBypassVariations(payload, category));
		}

		// Deduplicate
		return [...new Set(payloadVariations)];
	};
	// Seeded by the payload: every page of a paged scan is a separate call,
	// and Math.random would case a payload differently on each, changing how
	// many variations survive deduplication and shifting page boundaries.
	const paramPayload = (original: string) => (caseSensitiveTest ? randomUppercase(original, seededRandom(original)) : original);

	// How many variations each ParamCheck payload expands into. Every page needs
	// these counts (for the total, and to find where the page starts), but only
	// the payloads on the page need their variations, so the counts are cached
	// across pages and the variations are generated per page.
	const planKey = JSON.stringify([
		useEnhancedPayloads,
		useAdvancedPayloads,
		categories && categories.length ? categories : null,
		falsePositiveTest,
		caseSensitiveTest,
		wafTypeForVariations ?? null,
		useEncodingVariations,
	]);
	let variationCounts = paramVariationCountCache.get(planKey);
	// A count list that no longer lines up with its payload list (payload data
	// changed at runtime) is stale: recount rather than misplace page boundaries.
	if (
		variationCounts &&
		payloadEntries.some(
			([category, info]) =>
				(info.type || 'ParamCheck') === 'ParamCheck' &&
				variationCounts!.get(category)?.length !== (falsePositiveTest ? info.falsePayloads || [] : info.payloads || []).length,
		)
	) {
		variationCounts = undefined;
	}
	if (!variationCounts) {
		variationCounts = new Map();
		for (const [category, info] of payloadEntries) {
			if ((info.type || 'ParamCheck') !== 'ParamCheck') continue;
			const payloads: string[] = falsePositiveTest ? info.falsePayloads || [] : info.payloads || [];
			variationCounts.set(category, Uint32Array.from(payloads, (original) => planParamVariations(paramPayload(original), category).length));
		}
		rememberVariationCounts(planKey, variationCounts);
	}

	// Calculate total items matching category/method filters
	let totalItems = 0;
	for (const [category, info] of payloadEntries) {
		const checkType = info.type || 'ParamCheck';
		const payloads = falsePositiveTest ? info.falsePayloads || [] : info.payloads || [];
		if (checkType === 'ParamCheck') {
			for (const count of variationCounts.get(category) || []) {
				totalItems += count * METHODS.length;
			}
		} else if (checkType === 'FileCheck') {
			totalItems += payloads.length;
		} else if (checkType === 'Header') {
			totalItems += payloads.length * METHODS.length;
		}
	}

	const pageTasks: Array<() => Promise<AuditResultItem>> = [];
	let stoppedEarly = false;

	outerLoop: for (const [category, info] of payloadEntries) {
		const checkType = info.type || 'ParamCheck';
		const payloads = falsePositiveTest ? info.falsePayloads || [] : info.payloads || [];
		if (checkType === 'ParamCheck') {
			const counts = variationCounts.get(category);
			for (let i = 0; i < payloads.length; i++) {
				const itemsForPayload = (counts?.[i] ?? 0) * METHODS.length;
				// Entirely before this page: skip it without generating its variations.
				if (offset + itemsForPayload <= start) {
					offset += itemsForPayload;
					continue;
				}
				const payload = paramPayload(payloads[i]);
				const payloadVariations = planParamVariations(payload, category);
				for (const currentPayload of payloadVariations) {
					for (const method of METHODS) {
						if (offset >= end) {
							stoppedEarly = true;
							break outerLoop;
						}
						if (offset >= start) {
							const detectedWAFType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);
							let finalPayload = currentPayload;
							const finalMethod = method;

							const headersObj = customHeaders ? processCustomHeaders(customHeaders, currentPayload) : undefined;

							if (httpManipulation?.enableParameterPollution) {
								const pollutedPayloads = generateHTTPManipulationPayloads(currentPayload, 'pollution');
								if (pollutedPayloads.length > 1) {
									finalPayload = pollutedPayloads[1];
								}
							} else if (httpManipulation?.enableInspectionLimitPadding) {
								const paddingSize = httpManipulation.paddingSize || '16kb';
								finalPayload = HTTPManipulator.generateQueryPadding('test', currentPayload, paddingSize);
							}

							pageTasks.push(async () => {
								const res = await sendRequest(
									url,
									finalMethod,
									finalPayload,
									headersObj,
									payloadTemplate,
									followRedirect,
									useEnhancedPayloads,
									detectedWAFType,
									undefined,
									options,
								);

								const bodyText = res?.bodyText || '';
								const itemStatus = res ? res.status : 'ERR';
								const itemError = res?.error || null;
								const { blocked, verdict, baselineNote } = evaluateWAFVerdict(
									itemStatus,
									bodyText,
									wafDetectionResult,
									res?.response?.headers,
									currentPayload,
									baselineProfile,
								);

								let userAgentBypass: UserAgentBypassInfo | undefined;
								if (legitUserAgents.length && blocked && (itemStatus === 403 || itemStatus === '403' || itemStatus === 406 || itemStatus === '406')) {
									userAgentBypass = await probeUserAgentBypass(
										(ua) =>
											sendRequest(
												url,
												finalMethod,
												finalPayload,
												{ ...(headersObj || {}), 'User-Agent': ua },
												payloadTemplate,
												followRedirect,
												useEnhancedPayloads,
												detectedWAFType,
												undefined,
												options,
											),
										legitUserAgents,
										wafDetectionResult,
										currentPayload,
										baselineProfile,
									);
								}

								let ipHeaderBypass: IpHeaderBypassInfo | undefined;
								if (trustedIpHeaders.length && blocked && (itemStatus === 403 || itemStatus === '403' || itemStatus === 406 || itemStatus === '406')) {
									ipHeaderBypass = await probeIpHeaderBypass(
										(hName, hVal) =>
											sendRequest(
												url,
												finalMethod,
												finalPayload,
												{ ...(headersObj || {}), [hName]: hVal },
												payloadTemplate,
												followRedirect,
												useEnhancedPayloads,
												detectedWAFType,
												undefined,
												options,
											),
										trustedIpHeaders,
										wafDetectionResult,
										currentPayload,
										baselineProfile,
									);
								}

								return {
									category,
									payload: currentPayload,
									originalPayload: payload,
									method,
									status: itemStatus,
									is_redirect: res ? res.is_redirect : false,
									responseTime: res ? res.responseTime : 0,
									wafDetected: wafDetectionResult?.detected || false,
									wafType: detectedWAFType || 'Unknown',
									bypassTechnique: currentPayload !== payload ? 'Advanced' : 'Standard',
									blocked,
									verdict,
									...(baselineNote ? { baselineNote } : {}),
									error: itemError,
									userAgentBypass,
									...(ipHeaderBypass ? { ipHeaderBypass } : {}),
								};
							});
						}
						offset++;
					}
				}
			}
		} else if (checkType === 'FileCheck') {
			for (let payload of payloads) {
				if (caseSensitiveTest) {
					payload = randomUppercase(payload);
				}
				if (offset >= end) {
					stoppedEarly = true;
					break outerLoop;
				}
				if (offset >= start) {
					const currentPayload = payload;
					const fileUrl = baseUrl.replace(/\/$/, '') + '/' + currentPayload.replace(/^\//, '');
					const headersObj = customHeaders ? processCustomHeaders(customHeaders, currentPayload) : undefined;
					const detectedWAFType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);

					pageTasks.push(async () => {
						const res = await sendRequest(
							fileUrl,
							'GET',
							undefined,
							headersObj,
							undefined,
							followRedirect,
							useEnhancedPayloads,
							detectedWAFType,
							undefined,
							options,
						);

						const bodyText = res?.bodyText || '';
						const itemStatus = res ? res.status : 'ERR';
						const itemError = res?.error || null;
						// FileCheck requests distinct paths (/.git, /config.php) rather than the base URL,
						// so a root-URL 403 baseline should not suppress path-level WAF blocks.
						const fileCheckBaseline = baselineProfile?.isOriginBlocked ? undefined : baselineProfile;
						const { blocked, verdict, baselineNote } = evaluateWAFVerdict(
							itemStatus,
							bodyText,
							wafDetectionResult,
							res?.response?.headers,
							currentPayload,
							fileCheckBaseline,
						);

						let userAgentBypass: UserAgentBypassInfo | undefined;
						if (legitUserAgents.length && blocked && (itemStatus === 403 || itemStatus === '403' || itemStatus === 406 || itemStatus === '406')) {
							userAgentBypass = await probeUserAgentBypass(
								(ua) =>
									sendRequest(
										fileUrl,
										'GET',
										undefined,
										{ ...(headersObj || {}), 'User-Agent': ua },
										undefined,
										followRedirect,
										useEnhancedPayloads,
										detectedWAFType,
										undefined,
										options,
									),
								legitUserAgents,
								wafDetectionResult,
								currentPayload,
								fileCheckBaseline,
							);
						}

						let ipHeaderBypass: IpHeaderBypassInfo | undefined;
						if (trustedIpHeaders.length && blocked && (itemStatus === 403 || itemStatus === '403' || itemStatus === 406 || itemStatus === '406')) {
							ipHeaderBypass = await probeIpHeaderBypass(
								(hName, hVal) =>
									sendRequest(
										fileUrl,
										'GET',
										undefined,
										{ ...(headersObj || {}), [hName]: hVal },
										undefined,
										followRedirect,
										useEnhancedPayloads,
										detectedWAFType,
										undefined,
										options,
									),
								trustedIpHeaders,
								wafDetectionResult,
								currentPayload,
								fileCheckBaseline,
							);
						}

						return {
							category,
							payload: currentPayload,
							method: 'GET',
							status: itemStatus,
							is_redirect: res ? res.is_redirect : false,
							responseTime: res ? res.responseTime : 0,
							wafDetected: wafDetectionResult?.detected || false,
							wafType: detectedWAFType || 'Unknown',
							blocked,
							verdict,
							...(baselineNote ? { baselineNote } : {}),
							error: itemError,
							userAgentBypass,
							...(ipHeaderBypass ? { ipHeaderBypass } : {}),
						};
					});
				}
				offset++;
			}
		} else if (checkType === 'Header') {
			for (let payload of payloads) {
				if (caseSensitiveTest) {
					payload = randomUppercase(payload);
				}
				const headersObj: Record<string, string> = {};
				for (const line of payload.split(/\r?\n/)) {
					const idx = line.indexOf(':');
					if (idx > 0) {
						const name = line.slice(0, idx).trim();
						const value = line.slice(idx + 1).trim();
						headersObj[name] = value;
					}
				}

				if (customHeaders) {
					const customHeadersObj = processCustomHeaders(customHeaders, payload);
					Object.assign(headersObj, customHeadersObj);
				}

				for (const method of METHODS) {
					if (offset >= end) {
						stoppedEarly = true;
						break outerLoop;
					}
					if (offset >= start) {
						const currentPayload = payload;
						const currentHeadersObj = { ...headersObj };
						const currentMethod = method;
						const detectedWAFType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);

						pageTasks.push(async () => {
							const res = await sendRequest(
								url,
								currentMethod,
								undefined,
								currentHeadersObj,
								payloadTemplate,
								followRedirect,
								useEnhancedPayloads,
								detectedWAFType,
								undefined,
								options,
							);

							const bodyText = res?.bodyText || '';
							const itemStatus = res ? res.status : 'ERR';
							const itemError = res?.error || null;
							const { blocked, verdict, baselineNote } = evaluateWAFVerdict(
								itemStatus,
								bodyText,
								wafDetectionResult,
								res?.response?.headers,
								currentPayload,
								baselineProfile,
							);

							// Skip the User-Agent category: its payload IS the UA header, so
							// swapping in a trusted UA would be a meaningless "bypass".
							let userAgentBypass: UserAgentBypassInfo | undefined;
							if (
								legitUserAgents.length &&
								category !== 'User-Agent' &&
								blocked &&
								(itemStatus === 403 || itemStatus === '403' || itemStatus === 406 || itemStatus === '406')
							) {
								userAgentBypass = await probeUserAgentBypass(
									(ua) =>
										sendRequest(
											url,
											currentMethod,
											undefined,
											{ ...currentHeadersObj, 'User-Agent': ua },
											payloadTemplate,
											followRedirect,
											useEnhancedPayloads,
											detectedWAFType,
											undefined,
											options,
										),
									legitUserAgents,
									wafDetectionResult,
									currentPayload,
									baselineProfile,
								);
							}

							// Filter out any trusted IP header whose headerName is already being tested by this Header payload
							let ipHeaderBypass: IpHeaderBypassInfo | undefined;
							if (
								trustedIpHeaders.length &&
								blocked &&
								(itemStatus === 403 || itemStatus === '403' || itemStatus === 406 || itemStatus === '406')
							) {
								const existingKeysLower = new Set(Object.keys(currentHeadersObj).map((k) => k.toLowerCase()));
								const eligibleIpHeaders = trustedIpHeaders.filter(
									(h) => !existingKeysLower.has(h.headerName.toLowerCase()),
								);
								if (eligibleIpHeaders.length > 0) {
									ipHeaderBypass = await probeIpHeaderBypass(
										(hName, hVal) =>
											sendRequest(
												url,
												currentMethod,
												undefined,
												{ ...currentHeadersObj, [hName]: hVal },
												payloadTemplate,
												followRedirect,
												useEnhancedPayloads,
												detectedWAFType,
												undefined,
												options,
											),
										eligibleIpHeaders,
										wafDetectionResult,
										currentPayload,
										baselineProfile,
									);
								}
							}

							return {
								category,
								payload: currentPayload,
								method: currentMethod,
								status: itemStatus,
								is_redirect: res ? res.is_redirect : false,
								responseTime: res ? res.responseTime : 0,
								wafDetected: wafDetectionResult?.detected || false,
								wafType: detectedWAFType || 'Unknown',
								blocked,
								verdict,
								...(baselineNote ? { baselineNote } : {}),
								error: itemError,
								userAgentBypass,
								...(ipHeaderBypass ? { ipHeaderBypass } : {}),
							};
						});
					}
					offset++;
				}
			}
		}
	}

	const effectiveConcurrency =
		options?.concurrency !== undefined && Number.isFinite(options.concurrency) && options.concurrency > 0
			? Math.floor(options.concurrency)
			: 1;

	const results = await mapWithConcurrency<() => Promise<AuditResultItem>, AuditResultItem>(
		pageTasks,
		{
			concurrency: effectiveConcurrency,
			isRateLimited: (item: AuditResultItem) => item.status === 429 || item.status === '429',
		},
		(task) => task(),
	);

	return {
		results,
		page,
		pageSize: limit,
		total: totalItems,
		hasMore: stoppedEarly || end < totalItems,
		...(baselineProfile ? { baseline: baselineProfile } : {}),
	};
}

export async function handleApiCheckFiltered(
	url: string,
	page: number,
	methods: string[],
	categories?: string[],
	payloadTemplate?: string,
	followRedirect: boolean = false,
	customHeaders?: string,
	falsePositiveTest: boolean = false,
	caseSensitiveTest: boolean = false,
	useEnhancedPayloads: boolean = false,
	useAdvancedPayloads: boolean = false,
	autoDetectWAF: boolean = false,
	useEncodingVariations: boolean = false,
	detectedWAF?: string,
	httpManipulation?: HTTPManipulationOptions,
	options?: CheckExecutionOptions,
): Promise<AuditResultItem[]> {
	const envelope = await handleApiCheckWithEnvelope(
		url,
		page,
		methods,
		categories,
		payloadTemplate,
		followRedirect,
		customHeaders,
		falsePositiveTest,
		caseSensitiveTest,
		useEnhancedPayloads,
		useAdvancedPayloads,
		autoDetectWAF,
		useEncodingVariations,
		detectedWAF,
		httpManipulation,
		options,
	);
	return envelope.results;
}
