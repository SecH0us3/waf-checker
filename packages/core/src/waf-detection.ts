// WAF Detection and Fingerprinting Module
// Based on response headers, behavior patterns, and timing analysis

import { redactHeaders } from './utils/payload-utils';
import { isValidTargetUrl } from './utils/security';

export interface WAFDetectionResult {
	detected: boolean;
	wafType: string;
	confidence: number;
	evidence: string[];
	suggestedBypassTechniques: string[];
	captchaDetected?: string;
}

import { WAFSignature, WAF_SIGNATURES } from './waf-signatures';

export class WAFDetector {
	private static readonly WAF_SIGNATURES: WAFSignature[] = WAF_SIGNATURES;

	/**
	 * Get list of supported WAF vendor names
	 */
	static getSupportedWafs(): string[] {
		return this.WAF_SIGNATURES.map((sig) => sig.name).filter((name) => name !== 'Generic WAF');
	}

	/**
	 * Detect WAF from HTTP response
	 */
	static async detectFromResponse(response: Response, responseBody?: string, responseTime?: number, isWorker?: boolean): Promise<WAFDetectionResult> {
		const evidence: string[] = [];
		let bestMatch = {
			name: 'Unknown',
			confidence: 0,
			evidence: [] as string[],
		};

		let captchaDetected: string | undefined = undefined;
		if (responseBody) {
			if (responseBody.includes('challenges.cloudflare.com/turnstile')) {
				captchaDetected = 'Cloudflare Turnstile';
			} else if (responseBody.includes('google.com/recaptcha')) {
				captchaDetected = 'Google reCAPTCHA';
			} else if (responseBody.includes('hcaptcha.com')) {
				captchaDetected = 'hCaptcha';
			}
		}

		for (const signature of this.WAF_SIGNATURES) {
			let confidence = 0;
			const matchEvidence: string[] = [];

			// Check headers
			for (const [headerName, pattern] of Object.entries(signature.headers)) {
				const headerValue = response.headers.get(headerName);
				if (headerValue) {
					// Cloudflare Workers inject cf-* and server: cloudflare headers into fetch responses
					if (isWorker && signature.name === 'Cloudflare' && (headerName === 'server' || headerName.startsWith('cf-'))) {
						continue;
					}

					if (typeof pattern === 'string') {
						if (headerValue.toLowerCase().includes(pattern.toLowerCase())) {
							confidence += 30;
							const displayValue = redactHeaders({ [headerName]: headerValue })[headerName];
							matchEvidence.push(`Header ${headerName}: ${displayValue}`);
						}
					} else if (pattern instanceof RegExp) {
						if (pattern.test(headerValue)) {
							confidence += 30;
							const displayValue = redactHeaders({ [headerName]: headerValue })[headerName];
							matchEvidence.push(`Header ${headerName}: ${displayValue} (matches ${pattern})`);
						}
					}
				}
			}

			// Check status codes
			if (signature.statusCodes && signature.statusCodes.includes(response.status)) {
				confidence += 20;
				matchEvidence.push(`Status code: ${response.status}`);
			}

			// Check cookie patterns
			if (signature.cookiePatterns) {
				const cookies = response.headers.get('set-cookie');
				if (cookies) {
					for (const pattern of signature.cookiePatterns) {
						if (pattern.test(cookies)) {
							confidence += 25;
							matchEvidence.push(`Cookie pattern match: ${pattern}`);
						}
					}
				}
			}

			// Check response body patterns
			if (responseBody && signature.bodyPatterns) {
				for (const pattern of signature.bodyPatterns) {
					if (pattern.test(responseBody)) {
						confidence += 25;
						matchEvidence.push(`Body pattern match: ${pattern}`);
					}
				}
			}

			// Check response time patterns (WAFs often add latency)
			if (responseTime && responseTime > 500) {
				confidence += 5;
				// Don't add to evidence as it's circumstantial
			}

			// Update best match
			if (confidence > bestMatch.confidence) {
				bestMatch = {
					name: signature.name,
					confidence,
					evidence: matchEvidence,
				};
			}
		}

		const detected = bestMatch.confidence > 40;
		const suggestedBypassTechniques = this.getSuggestedBypassTechniques(bestMatch.name);

		return {
			detected,
			wafType: detected ? bestMatch.name : 'Unknown',
			confidence: bestMatch.confidence,
			evidence: bestMatch.evidence,
			suggestedBypassTechniques,
			captchaDetected
		};
	}

	/**
	 * Perform active WAF detection by sending probe requests
	 */
	static async activeDetection(url: string, options?: { fetch?: typeof fetch; isWorker?: boolean }): Promise<WAFDetectionResult> {
		if (!isValidTargetUrl(url)) {
			throw new Error('Invalid URL or restricted IP');
		}
		const fetchFn = options?.fetch || globalThis.fetch;
		const probePayloads = ["' OR '1'='1", '<script>alert(1)</script>', '../../../etc/passwd', 'UNION SELECT 1,2,3--'];

		const probePromises = probePayloads.map(async (payload) => {
			try {
				const separator = url.includes('?') ? '&' : '?';
				const startTime = Date.now();
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 10000);

				let response;
				try {
					response = await fetchFn(`${url}${separator}test=${encodeURIComponent(payload)}`, {
						method: 'GET',
						redirect: 'manual',
						signal: controller.signal,
					});
				} finally {
					clearTimeout(timeoutId);
				}
				const responseTime = Date.now() - startTime;

				let responseBody = '';
				const contentLength = response.headers.get('content-length');
				if (contentLength && parseInt(contentLength, 10) > 1048576) {
					responseBody = '[Response Too Large]';
				} else {
					responseBody = await response.text();
				}

				const detection = await this.detectFromResponse(response, responseBody, responseTime, options?.isWorker);
				return detection.detected || detection.captchaDetected ? detection : null;
			} catch (error) {
				console.error('Active detection probe failed:', error);
				return null;
			}
		});

		const results = (await Promise.all(probePromises)).filter((r): r is WAFDetectionResult => r !== null);

		// Return the detection result with highest confidence, or if a captcha was detected
		if (results.length > 0) {
			return results.reduce((best, current) => {
				if (current.confidence > best.confidence || (current.captchaDetected && !best.captchaDetected)) {
					return current;
				}
				return best;
			});
		}

		return {
			detected: false,
			wafType: 'Unknown',
			confidence: 0,
			evidence: [],
			suggestedBypassTechniques: [],
		};
	}

	/**
	 * Get suggested bypass techniques for detected WAF
	 */
	private static getSuggestedBypassTechniques(wafType: string): string[] {
		const techniques: { [key: string]: string[] } = {
			Cloudflare: [
				"Unicode encoding (\\u0027 instead of ')",
				'Double URL encoding (%2527 instead of %27)',
				'Mixed case keywords (uNiOn instead of UNION)',
				'Alternative space characters (\\u00A0)',
				'Comment-based obfuscation (/**/)',
			],
			'AWS WAF': [
				'Unicode normalization bypasses',
				'Character set encoding variations',
				'Request method variations',
				'Content-Type manipulation',
			],
			'DDoS-Guard': [
				'HTTP parameter pollution',
				'Double URL encoding',
				'Request rate pacing',
				'Header case manipulation',
				'Alternative whitespace characters',
			],
			Imperva: ['Parameter pollution', 'HTTP verb tampering', 'Custom header injection', 'Encoding combinations'],
			'F5 BIG-IP': ['Request smuggling techniques', 'HTTP/1.0 downgrade', 'Custom User-Agent strings'],
			ModSecurity: ['Comment-based SQL obfuscation', 'Case sensitivity exploits', 'Regex pattern bypasses', 'Alternative operators'],
			Akamai: ['IP-based bypasses', 'Origin server direct access', 'Cache poisoning techniques'],
			'Azure Front Door': [
				'Case variations for SQL keywords',
				'Parameter pollution (duplicate params)',
				'Unicode encoding variations',
				'CRLF injection in headers',
			],
			'Google Cloud Armor': [
				'Advanced request smuggling',
				'Complex encoding combinations',
				'Custom header injection (X-Forwarded-For)',
				'Path normalization bypasses',
			],
			'Citrix NetScaler': [
				'URL encoding (double/triple)',
				'HTTP method variations (tampering)',
				'Parameter name obfuscation',
				'Cookie-based bypass techniques',
			],
			'Palo Alto Networks': [
				'Double slash path obfuscation (//)',
				'Path normalization bypass (/./)',
				'Mixed case payload encoding',
				'Tab character (%09) as space alternative',
			],
			'Sophos WAF': [
				'Random case variations for keywords',
				'Double URL encoding',
				'Null byte injection (%00)',
				'HTTP parameter pollution',
			],
			'Generic WAF': [
				'Double URL encoding',
				'Unicode encoding',
				'Mixed case obfuscation',
				'Comment insertion',
				'Parameter pollution',
				'HTTP verb tampering',
			],
		};

		return techniques[wafType] || techniques['Generic WAF'];
	}

	/**
	 * Detect WAF bypass opportunities
	 */
	static async detectBypassOpportunities(url: string, options?: { fetch?: typeof fetch }): Promise<{
		httpMethodsBypass: boolean;
		headerBypass: boolean;
		encodingBypass: boolean;
		parameterPollution: boolean;
	}> {
		if (!isValidTargetUrl(url)) {
			throw new Error('Invalid URL or restricted IP');
		}
		const fetchFn = options?.fetch || globalThis.fetch;
		const opportunities = {
			httpMethodsBypass: false,
			headerBypass: false,
			encodingBypass: false,
			parameterPollution: false,
		};

		try {
			const separator = url.includes('?') ? '&' : '?';
			const encodedPayload = '%2527%2520OR%25201%253D1';

			const [methodResponse, headerResponse, encodingResponse, pollutionResponse] = await Promise.all([
				// Test HTTP method bypass
				fetchFn(url, { method: 'TRACE', redirect: 'manual' }),

				// Test header bypass with X-Original-URL
				fetchFn(url, {
					method: 'GET',
					headers: { 'X-Original-URL': '/admin' },
					redirect: 'manual',
				}),

				// Test encoding bypass
				fetchFn(`${url}${separator}test=${encodedPayload}`, {
					method: 'GET',
					redirect: 'manual',
				}),

				// Test parameter pollution
				fetchFn(`${url}${separator}test=safe&test=malicious`, {
					method: 'GET',
					redirect: 'manual',
				}),
			]);

			if (methodResponse.status !== 405) {
				opportunities.httpMethodsBypass = true;
			}

			if (headerResponse.status === 200) {
				opportunities.headerBypass = true;
			}

			if (encodingResponse.status === 200) {
				opportunities.encodingBypass = true;
			}

			if (pollutionResponse.status === 200) {
				opportunities.parameterPollution = true;
			}
		} catch (error) {
			console.error('Bypass opportunity detection failed:', error);
		}

		return opportunities;
	}
}
