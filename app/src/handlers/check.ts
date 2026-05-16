import { PAYLOADS, ENHANCED_PAYLOADS, PayloadCategory } from '../payloads';
import { WAFDetector, WAFDetectionResult } from '../waf-detection';
import { PayloadEncoder } from '../encoding';
import {
	generateWAFSpecificPayloads,
	generateHTTPManipulationPayloads,
	ADVANCED_PAYLOADS,
	generateEncodedPayloads,
} from '../advanced-payloads';
import { HTTPManipulationOptions } from '../http-manipulation';
import { isValidTargetUrl } from '../utils/security';
import { substitutePayload, processCustomHeaders, randomUppercase, redactHeaders, redactUrl } from '../utils/payload-utils';

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
) {
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
				finalUrl = url.replace(/\{PAYLOAD\}/g, encodeURIComponent(finalPayload));
			} else if (method === 'GET' || method === 'DELETE') {
				const separator = url.includes('?') ? '&' : '?';
				finalUrl = url + `${separator}test=${encodeURIComponent(finalPayload)}`;
			}
		}

		// Validate finalUrl after substitution to prevent SSRF
		if (!isValidTargetUrl(finalUrl)) {
			console.error(`Blocked SSRF attempt to: ${redactUrl(finalUrl)}`);
			return { status: 'BLOCKED', is_redirect: false, responseTime: 0 };
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
					const newHeaders = new Headers(headersObj || {});
					newHeaders.set('Content-Type', 'application/json');
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

				resp = await fetch(currentUrl, fetchOptions);

				if (followRedirect && resp.status >= 300 && resp.status < 400 && redirectCount < maxRedirects) {
					const location = resp.headers.get('Location');
					if (!location) break;

					const nextUrl = new URL(location, currentUrl).toString();
					if (!isValidTargetUrl(nextUrl)) {
						console.error(`Blocked SSRF redirect attempt to: ${redactUrl(nextUrl)}`);
						return { status: 'BLOCKED', is_redirect: true, responseTime: Date.now() - startTime };
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
		console.log(
			`Request to ${redactUrl(url)} with method ${method} and payload ${payload ?? '(none)'} and headers ${JSON.stringify(redactHeaders(headersObj))} returned status ${resp.status} in ${responseTime}ms`,
		);

		return {
			status: resp.status,
			is_redirect: resp.status >= 300 && resp.status < 400,
			responseTime,
			response: resp,
		};
	} catch (e) {
		console.error(`Request error for ${redactUrl(url)}:`, e);
		return { status: 'ERR', is_redirect: false, responseTime: 0 };
	}
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
): Promise<any[]> {
	const METHODS = methods && methods.length ? methods : ['GET'];
	const results: any[] = [];
	let baseUrl: string;
	const limit = 50;
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
			wafDetectionResult = await WAFDetector.activeDetection(url.replace(/\{PAYLOAD\}/g, ''));
			console.log(`WAF Detection Result: ${JSON.stringify(wafDetectionResult)}`);
		} catch (e) {
			console.error('WAF detection failed:', e);
		}
	}

	// Choose payload source based on options
	let payloadSource = useEnhancedPayloads ? ENHANCED_PAYLOADS : PAYLOADS;

	// Add advanced payloads if requested
	if (useAdvancedPayloads) {
		payloadSource = { ...payloadSource, ...ADVANCED_PAYLOADS };
	}

	// Generate encoded payload variations if requested
	if (useEncodingVariations) {
		const encodedPayloads = generateEncodedPayloads(payloadSource);
		payloadSource = { ...payloadSource, ...encodedPayloads };
	}

	const payloadEntries =
		categories && categories.length
			? Object.entries(payloadSource).filter(([cat]) => categories.includes(cat))
			: Object.entries(payloadSource);
	for (const [category, info] of payloadEntries) {
		const checkType = info.type || 'ParamCheck';
		const payloads = falsePositiveTest ? info.falsePayloads || [] : info.payloads || [];
		if (checkType === 'ParamCheck') {
			for (let payload of payloads) {
				// Use let so we can reassign
				if (caseSensitiveTest) {
					payload = randomUppercase(payload); // Modify payload
				}

				// Generate payload variations — WAF-specific and encoding are additive
				let payloadVariations = [payload];

				// Add WAF-specific bypass variations if WAF is detected
				const wafType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);
				if (wafType) {
					const wafSpecificPayloads = generateWAFSpecificPayloads(wafType, payload);
					if (wafSpecificPayloads.length > 1) {
						payloadVariations.push(...wafSpecificPayloads);
					}
				}

				// Add encoding variations if enabled (works alongside WAF-specific)
				if (useEncodingVariations) {
					const encodedVariations = PayloadEncoder.generateBypassVariations(payload, category);
					payloadVariations.push(...encodedVariations);
				}

				// Deduplicate
				payloadVariations = [...new Set(payloadVariations)];

				// Test each payload variation
				for (const currentPayload of payloadVariations) {
					for (const method of METHODS) {
						if (offset >= end) return results;
						if (offset >= start) {
							// Process custom headers if provided
							let headersObj = customHeaders ? processCustomHeaders(customHeaders, currentPayload) : undefined;

							// Apply HTTP manipulation if enabled
							let finalPayload = currentPayload;
							let finalMethod = method;
							if (httpManipulation?.enableParameterPollution) {
								const pollutedPayloads = generateHTTPManipulationPayloads(currentPayload, 'pollution');
								if (pollutedPayloads.length > 1) {
									finalPayload = pollutedPayloads[1]; // Use first variation
								}
							}

							const detectedWAFType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : undefined);

							const res = await sendRequest(
								url,
								finalMethod,
								finalPayload,
								headersObj,
								payloadTemplate,
								followRedirect,
								useEnhancedPayloads,
								detectedWAFType,
							);
							results.push({
								category,
								payload: currentPayload,
								originalPayload: payload, // Keep track of original
								method,
								status: res ? res.status : 'ERR',
								is_redirect: res ? res.is_redirect : false,
								responseTime: res ? res.responseTime : 0,
								wafDetected: wafDetectionResult?.detected || false,
								wafType: detectedWAFType || 'Unknown',
								bypassTechnique: currentPayload !== payload ? 'Advanced' : 'Standard',
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
				if (offset >= end) return results;
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
					);
					results.push({
						category,
						payload,
						method: 'GET',
						status: res ? res.status : 'ERR',
						is_redirect: res ? res.is_redirect : false,
						responseTime: res ? res.responseTime : 0,
						wafDetected: wafDetectionResult?.detected || false,
						wafType: detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : 'Unknown'),
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
					if (offset >= end) return results;
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
						);
						results.push({
							category,
							payload,
							method,
							status: res ? res.status : 'ERR',
							is_redirect: res ? res.is_redirect : false,
							responseTime: res ? res.responseTime : 0,
							wafDetected: wafDetectionResult?.detected || false,
							wafType: detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : 'Unknown'),
						});
					}
					offset++;
				}
			}
		}
	}
	return results;
}
