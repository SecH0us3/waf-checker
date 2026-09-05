import { PAYLOADS, ENHANCED_PAYLOADS } from './payloads';
import { WAFDetector, WAFDetectionResult } from './waf-detection';
import { PayloadEncoder } from './encoding';
import {
	generateWAFSpecificPayloads,
	generateHTTPManipulationPayloads,
	ADVANCED_PAYLOADS,
	generateEncodedPayloads,
} from './advanced-payloads';
import { HTTPManipulationOptions, HTTPManipulator } from './http-manipulation';
import { isValidTargetUrl } from './utils/security';
import { substitutePayload, processCustomHeaders, randomUppercase, redactHeaders, redactUrl } from './utils/payload-utils';
import { AuditResultItem, CheckResultEnvelope } from './reports/types';

// Вспомогательная функция для отправки запроса с нужным методом и payload
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
	options?: { fetch?: typeof fetch; color?: boolean; quiet?: boolean; rawPayload?: boolean; allowLocal?: boolean },
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

		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 10000);

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
			const maxRedirects = 5;

			while (true) {
				const fetchOptions: RequestInit = {
					method: currentMethod,
					redirect: 'manual',
					headers: currentHeaders,
					body: currentBody,
					signal: controller.signal,
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

					currentUrl = nextUrl;
					redirectCount++;
					continue;
				}
				break;
			}
		} finally {
			clearTimeout(timeoutId);
		}

		const responseTime = Date.now() - startTime;
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

		let bodyText = '';
		try {
			const clone = resp.clone();
			bodyText = await clone.text();
		} catch {}

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
	probedPayload?: string
): { blocked: boolean; verdict: 'blocked' | 'passed' | 'exposed' } {
	let isBlocked = false;

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
	}

	// Response-level headers check
	if (!isBlocked && headers) {
		const cfMitigated = headers.get('cf-mitigated');
		if (cfMitigated && (cfMitigated === 'challenge' || cfMitigated === 'block')) {
			isBlocked = true;
		}
	}

	// Response-level body markers check
	if (!isBlocked && bodyText) {
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
		} else if (
			// Imperva / Incapsula block markers anchored to vendor context or fuller block page phrasing
			((detection?.wafType === 'Imperva' ||
				detection?.wafType === 'Incapsula' ||
				/incapsula|imperva/i.test(bodyText)) &&
				/incident id/i.test(bodyText)) ||
			/request unsuccessful\. incapsula incident id/i.test(bodyText)
		) {
			isBlocked = true;
		} else if (
			// General WAF block markers
			/waf-block|blocked by[^\n]{0,100}waf|request blocked|access denied[^\n]{0,100}firewall|security incident/i.test(bodyText) ||
			/powered by[^\n]{0,100}imperva|protected with[^\n]{0,100}bunkerweb/i.test(bodyText)
		) {
			isBlocked = true;
		}
	}

	// 2. Derive verdict
	if (isBlocked) {
		return { blocked: true, verdict: 'blocked' };
	}

	const numStatus = typeof status === 'number' ? status : parseInt(status, 10);
	if (!isNaN(numStatus) && numStatus >= 200 && numStatus < 300) {
		if (bodyText && bodyText.trim().length > 0 && isPlausibleArtifactContent(bodyText, probedPayload)) {
			return { blocked: false, verdict: 'exposed' };
		}
		return { blocked: false, verdict: 'passed' };
	}

	return { blocked: false, verdict: 'passed' };
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
	options?: { fetch?: typeof fetch; color?: boolean; quiet?: boolean; isWorker?: boolean; allowLocal?: boolean; pageSize?: number },
): Promise<CheckResultEnvelope> {
	const METHODS = methods && methods.length ? methods : ['GET'];
	const results: AuditResultItem[] = [];
	let baseUrl: string;
	const limit = options?.pageSize && options.pageSize > 0 ? options.pageSize : 50;
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
	if (autoDetectWAF) {
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

	// Choose payload source based on options
	let payloadSource = useEnhancedPayloads ? ENHANCED_PAYLOADS : PAYLOADS;

	// Add advanced payloads if requested
	if (useAdvancedPayloads) {
		payloadSource = { ...payloadSource, ...ADVANCED_PAYLOADS };
	}

	const payloadEntries =
		(categories && categories.length
			? Object.entries(payloadSource).filter(([cat]) => categories.includes(cat))
			: Object.entries(payloadSource)) as [string, any][];

	// Calculate total items matching category/method filters
	let totalItems = 0;
	for (const [_, info] of payloadEntries) {
		const checkType = info.type || 'ParamCheck';
		const payloads = falsePositiveTest ? info.falsePayloads || [] : info.payloads || [];
		if (checkType === 'ParamCheck') {
			totalItems += payloads.length * METHODS.length;
		} else if (checkType === 'FileCheck') {
			totalItems += payloads.length;
		} else if (checkType === 'Header') {
			totalItems += payloads.length * METHODS.length;
		}
	}

	for (const [category, info] of payloadEntries) {
		const checkType = info.type || 'ParamCheck';
		const payloads = falsePositiveTest ? info.falsePayloads || [] : info.payloads || [];
		if (checkType === 'ParamCheck') {
			for (let payload of payloads) {
				// Use let so we can reassign
				if (caseSensitiveTest) {
					payload = randomUppercase(payload); // Modify payload
				}

				// Generate payload variations
				let payloadVariations = [payload];

				// Add WAF-specific bypass variations if WAF is detected
				const wafType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);
				if (wafType) {
					const wafSpecificPayloads = generateWAFSpecificPayloads(wafType, payload);
					if (wafSpecificPayloads.length > 1) {
						payloadVariations.push(...wafSpecificPayloads.slice(1));
					}
				}

				// Add encoding variations if enabled (works alongside WAF-specific)
				if (useEncodingVariations) {
					const encodedVariations = PayloadEncoder.generateBypassVariations(payload, category);
					payloadVariations.push(...encodedVariations);
				}

				// Deduplicate
				payloadVariations = [...new Set(payloadVariations)];

				for (const currentPayload of payloadVariations) {
					for (const method of METHODS) {
						if (offset >= end) {
							return { results, page, pageSize: limit, total: totalItems, hasMore: true };
						}
						if (offset >= start) {
							// Check if detected WAF is CloudFront
							const detectedWAFType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);
							let finalPayload = currentPayload;
							let finalMethod = method;

							// Process custom headers if provided
							const headersObj = customHeaders ? processCustomHeaders(customHeaders, currentPayload) : undefined;

							// Apply HTTP manipulation if enabled
							if (httpManipulation?.enableParameterPollution) {
								const pollutedPayloads = generateHTTPManipulationPayloads(currentPayload, 'pollution');
								if (pollutedPayloads.length > 1) {
									finalPayload = pollutedPayloads[1]; // Use first variation
								}
							} else if (httpManipulation?.enableInspectionLimitPadding) {
								const paddingSize = httpManipulation.paddingSize || '16kb';
								const variations = HTTPManipulator.generatePaddingVariations('test', currentPayload, paddingSize);
								finalPayload = variations.queryPadding;
							}

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
							const { blocked, verdict } = evaluateWAFVerdict(itemStatus, bodyText, wafDetectionResult, res?.response?.headers, currentPayload);

							results.push({
								category,
								payload: currentPayload,
								originalPayload: payload, // Keep track of original
								method,
								status: itemStatus,
								is_redirect: res ? res.is_redirect : false,
								responseTime: res ? res.responseTime : 0,
								wafDetected: wafDetectionResult?.detected || false,
								wafType: detectedWAFType || 'Unknown',
								bypassTechnique: currentPayload !== payload ? 'Advanced' : 'Standard',
								blocked,
								verdict,
								error: itemError,
							});
						}
						offset++;
					}
				}
			}
		} else if (checkType === 'FileCheck') {
			for (let payload of payloads) {
				// Use let so we can reassign
				if (caseSensitiveTest) {
					payload = randomUppercase(payload); // Modify payload
				}
				if (offset >= end) {
					return { results, page, pageSize: limit, total: totalItems, hasMore: true };
				}
				if (offset >= start) {
					// Use potentially modified baseUrl for the base, and modified payload for the file path
					const fileUrl = baseUrl.replace(/\/$/, '') + '/' + payload.replace(/^\//, '');
					// Process custom headers if provided
					const headersObj = customHeaders ? processCustomHeaders(customHeaders, payload) : undefined;
					const res = await sendRequest(
						fileUrl,
						'GET',
						undefined,
						headersObj,
						undefined,
						followRedirect,
						useEnhancedPayloads,
						detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined),
						undefined,
						options,
					);

					const bodyText = res?.bodyText || '';
					const itemStatus = res ? res.status : 'ERR';
					const itemError = res?.error || null;
					const { blocked, verdict } = evaluateWAFVerdict(itemStatus, bodyText, wafDetectionResult, res?.response?.headers, payload);

					results.push({
						category,
						payload,
						method: 'GET',
						status: itemStatus,
						is_redirect: res ? res.is_redirect : false,
						responseTime: res ? res.responseTime : 0,
						wafDetected: wafDetectionResult?.detected || false,
						wafType: detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : 'Unknown'),
						blocked,
						verdict,
						error: itemError,
					});
				}
				offset++;
			}
		} else if (checkType === 'Header') {
			for (let payload of payloads) {
				// Use let so we can reassign
				if (caseSensitiveTest) {
					payload = randomUppercase(payload); // Modify payload
				}
				// Create headers from payload (potentially modified)
				const headersObj: Record<string, string> = {};
				for (const line of payload.split(/\r?\n/)) {
					// Use the potentially modified payload here
					const idx = line.indexOf(':');
					if (idx > 0) {
						const name = line.slice(0, idx).trim();
						const value = line.slice(idx + 1).trim();
						headersObj[name] = value;
					}
				}

				// Add custom headers if provided
				if (customHeaders) {
					const customHeadersObj = processCustomHeaders(customHeaders, payload);
					// Merge headers (custom headers override payload headers if same name)
					Object.assign(headersObj, customHeadersObj);
				}

				for (const method of METHODS) {
					if (offset >= end) {
						return { results, page, pageSize: limit, total: totalItems, hasMore: true };
					}
					if (offset >= start) {
						const res = await sendRequest(
							url,
							method,
							undefined,
							headersObj,
							payloadTemplate,
							followRedirect,
							useEnhancedPayloads,
							detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined),
							undefined,
							options,
						);

						const bodyText = res?.bodyText || '';
						const itemStatus = res ? res.status : 'ERR';
						const itemError = res?.error || null;
						const { blocked, verdict } = evaluateWAFVerdict(itemStatus, bodyText, wafDetectionResult, res?.response?.headers, payload);

						results.push({
							category,
							payload,
							method,
							status: itemStatus,
							is_redirect: res ? res.is_redirect : false,
							responseTime: res ? res.responseTime : 0,
							wafDetected: wafDetectionResult?.detected || false,
							wafType: detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : 'Unknown'),
							blocked,
							verdict,
							error: itemError,
						});
					}
					offset++;
				}
			}
		}
	}
	return { results, page, pageSize: limit, total: totalItems, hasMore: end < totalItems };
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
	options?: { fetch?: typeof fetch; color?: boolean; quiet?: boolean; isWorker?: boolean; allowLocal?: boolean; pageSize?: number },
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
