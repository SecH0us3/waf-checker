import { PAYLOADS, ENHANCED_PAYLOADS, PayloadCategory } from './payloads';
import { WAFDetector, WAFDetectionResult } from './waf-detection';
import { PayloadEncoder, ProtocolManipulation } from './encoding';
import {
	generateWAFSpecificPayloads,
	generateHTTPManipulationPayloads,
	ADVANCED_PAYLOADS,
	generateEncodedPayloads,
} from './advanced-payloads';
import { HTTPManipulator, ManipulatedRequest, HTTPManipulationOptions } from './http-manipulation';

// Вспомогательная функция для отправки запроса с нужным методом и payload
async function sendRequest(
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
		const redirectOption = followRedirect ? 'follow' : 'manual';
		const startTime = Date.now();

		// Apply WAF-specific payload modifications if WAF is detected
		let finalPayload = payload;
		if (detectedWAF && payload) {
			const wafSpecificPayloads = generateWAFSpecificPayloads(detectedWAF, payload);
			if (wafSpecificPayloads.length > 1) {
				finalPayload = wafSpecificPayloads[1]; // Use first bypass variation
			}
		}

		switch (method) {
			case 'GET':
			case 'DELETE':
				resp = await fetch(finalPayload !== undefined ? url + `?test=${encodeURIComponent(finalPayload)}` : url, {
					method,
					redirect: redirectOption,
					headers,
				});
				break;
			case 'POST':
			case 'PUT':
				if (payloadTemplate) {
					let jsonObj;
					try {
						jsonObj = JSON.parse(payloadTemplate);
						jsonObj = substitutePayload(jsonObj, finalPayload ?? '');
					} catch {
						jsonObj = { test: finalPayload ?? '' };
					}
					resp = await fetch(url, {
						method,
						redirect: redirectOption,
						body: JSON.stringify(jsonObj),
						headers: new Headers({ ...(headersObj || {}), 'Content-Type': 'application/json' }),
					});
				} else {
					resp = await fetch(url, { method, redirect: redirectOption, body: new URLSearchParams({ test: finalPayload ?? '' }), headers });
				}
				break;
			default:
				return null;
		}

		const responseTime = Date.now() - startTime;
		console.log(
			`Request to ${url} with method ${method} and payload ${payload} and headers ${JSON.stringify(headersObj)} returned status ${resp.status} in ${responseTime}ms`,
		);

		return {
			status: resp.status,
			is_redirect: resp.status >= 300 && resp.status < 400,
			responseTime,
			response: resp,
		};
	} catch (e) {
		return { status: 'ERR', is_redirect: false, responseTime: 0 };
	}
}

// Лучше сразу загрузить index.html при старте (если возможно)
let INDEX_HTML = '';

export default {
	async fetch(request: Request): Promise<Response> {
		const urlObj = new URL(request.url);
		if (urlObj.pathname === '/') {
			return new Response(INDEX_HTML, { headers: { 'content-type': 'text/html; charset=UTF-8' } });
		}
		if (urlObj.pathname === '/api/waf-detect') {
			return await handleWAFDetection(request);
		}
		if (urlObj.pathname === '/api/check') {
			const url = urlObj.searchParams.get('url');
			if (!url) return new Response('Missing url param', { status: 400 });
			if (url.includes('secmy')) {
				return new Response(JSON.stringify([]), { headers: { 'content-type': 'application/json; charset=UTF-8' } });
			}
			const page = parseInt(urlObj.searchParams.get('page') || '0', 10);
			const methods = (urlObj.searchParams.get('methods') || 'GET')
				.split(',')
				.map((m) => m.trim())
				.filter(Boolean);
			const categoriesParam = urlObj.searchParams.get('categories');
			let categories: string[] | undefined = undefined;
			if (categoriesParam) {
				categories = categoriesParam
					.split(',')
					.map((c) => c.trim())
					.filter(Boolean);
			}
			let payloadTemplate: string | undefined = undefined;
			let customHeaders: string | undefined = undefined;
			if (request.method === 'POST') {
				try {
					const body: any = await request.json();
					if (body && typeof body.payloadTemplate === 'string') {
						payloadTemplate = body.payloadTemplate;
					}
					if (body && typeof body.customHeaders === 'string') {
						customHeaders = body.customHeaders;
					}
					if (body && typeof body.detectedWAF === 'string') {
						// detectedWAF can also come from request body
					}
				} catch (e) {
					console.error('Error parsing request body:', e);
				}
			}
			// Новый параметр followRedirect
			const followRedirect = urlObj.searchParams.get('followRedirect') === '1';
			// Новый параметр falsePositiveTest
			const falsePositiveTest = urlObj.searchParams.get('falsePositiveTest') === '1';
			// New parameter caseSensitiveTest
			const caseSensitiveTest = urlObj.searchParams.get('caseSensitiveTest') === '1';
			// Enhanced payloads option
			const useEnhancedPayloads = urlObj.searchParams.get('enhancedPayloads') === '1';
			// Use advanced WAF bypass payloads
			const useAdvancedPayloads = urlObj.searchParams.get('useAdvancedPayloads') === '1';
			// Auto WAF detection
			const autoDetectWAF = urlObj.searchParams.get('autoDetectWAF') === '1';
			// Use encoding variations
			const useEncodingVariations = urlObj.searchParams.get('useEncodingVariations') === '1';
			// HTTP manipulation option
			const enableHTTPManipulation = urlObj.searchParams.get('httpManipulation') === '1';
			// Detected WAF type
			const detectedWAF = urlObj.searchParams.get('detectedWAF') || undefined;

			const results = await handleApiCheckFiltered(
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
				enableHTTPManipulation
					? {
							enableParameterPollution: true,
							enableVerbTampering: true,
							enableContentTypeConfusion: true,
						}
					: undefined,
			);
			return new Response(JSON.stringify(results), { headers: { 'content-type': 'application/json; charset=UTF-8' } });
		}
		if (urlObj.pathname === '/api/http-manipulation') {
			return await handleHTTPManipulation(request);
		}
		if (urlObj.pathname === '/api/batch/start') {
			return await handleBatchStart(request);
		}
		if (urlObj.pathname === '/api/batch/status') {
			return await handleBatchStatus(request);
		}
		if (urlObj.pathname === '/api/batch/stop') {
			return await handleBatchStop(request);
		}
		return new Response('Not found', { status: 404 });
	},
};

async function handleApiCheckFiltered(
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
	let originalUrl = url; // Keep original for potential error logging or if modification fails
	let originalBaseUrl = baseUrl; // Keep original baseUrl

	if (caseSensitiveTest) {
		try {
			const u = new URL(url);
			const modifiedHostname = randomUppercase(u.hostname);
			u.hostname = modifiedHostname;
			url = u.toString();
			baseUrl = `${u.protocol}//${u.host}`;
			console.log(`Case Sensitive Test: Modified URL from ${originalUrl} to ${url}`);
		} catch (e) {
			console.log(`Case Sensitive Test: Failed to parse URL ${originalUrl}, error: ${e}`);
			// Fallback: uppercase the whole URL and baseUrl string if parsing fails
			url = randomUppercase(url);
			baseUrl = randomUppercase(baseUrl);
			console.log(`Case Sensitive Test: Fallback - modified URL from ${originalUrl} to ${url}`);
		}
	}

	// Auto-detect WAF if requested
	let wafDetectionResult: WAFDetectionResult | undefined;
	if (autoDetectWAF) {
		try {
			wafDetectionResult = await WAFDetector.activeDetection(url);
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

				// Generate WAF-specific bypass variations if WAF is detected
				let payloadVariations = [payload];
				if (detectedWAF && wafDetectionResult?.detected) {
					const wafSpecificPayloads = generateWAFSpecificPayloads(wafDetectionResult.wafType, payload);
					payloadVariations = wafSpecificPayloads.length > 1 ? wafSpecificPayloads : [payload];
				} else if (detectedWAF) {
					const wafSpecificPayloads = generateWAFSpecificPayloads(detectedWAF, payload);
					payloadVariations = wafSpecificPayloads.length > 1 ? wafSpecificPayloads : [payload];
				}

				// Generate encoding variations if enabled
				if (useEncodingVariations && !detectedWAF) {
					const encodedVariations = PayloadEncoder.generateBypassVariations(payload, category);
					payloadVariations = encodedVariations;
				}

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

// New endpoint for HTTP manipulation testing
async function handleHTTPManipulation(request: Request): Promise<Response> {
	const urlObj = new URL(request.url);
	const targetUrl = urlObj.searchParams.get('url');

	if (!targetUrl) {
		return new Response(JSON.stringify({ error: 'Missing url parameter' }), {
			status: 400,
			headers: { 'content-type': 'application/json; charset=UTF-8' },
		});
	}

	try {
		const testPayload = 'test_payload';
		const manipulationOptions: HTTPManipulationOptions = {
			enableVerbTampering: true,
			enableParameterPollution: true,
			enableContentTypeConfusion: true,
			enableRequestSmuggling: false,
			enableHostHeaderInjection: true,
		};

		// Generate manipulated requests
		const manipulatedRequests = HTTPManipulator.generateManipulatedRequests(targetUrl, 'GET', testPayload, manipulationOptions);

		// Execute limited number of requests for testing
		const limitedRequests = manipulatedRequests.slice(0, 10);
		const results = await HTTPManipulator.batchExecuteRequests(limitedRequests, false, 3);

		return new Response(
			JSON.stringify({
				total_techniques: manipulatedRequests.length,
				tested_techniques: limitedRequests.length,
				results,
				timestamp: new Date().toISOString(),
			}),
			{
				headers: { 'content-type': 'application/json; charset=UTF-8' },
			},
		);
	} catch (error) {
		return new Response(
			JSON.stringify({
				error: 'HTTP manipulation test failed',
				message: error instanceof Error ? error.message : 'Unknown error',
			}),
			{
				status: 500,
				headers: { 'content-type': 'application/json; charset=UTF-8' },
			},
		);
	}
}

// New endpoint for WAF detection
async function handleWAFDetection(request: Request): Promise<Response> {
	const urlObj = new URL(request.url);
	const targetUrl = urlObj.searchParams.get('url');

	if (!targetUrl) {
		return new Response(JSON.stringify({ error: 'Missing url parameter' }), {
			status: 400,
			headers: { 'content-type': 'application/json; charset=UTF-8' },
		});
	}

	try {
		const detection = await WAFDetector.activeDetection(targetUrl);
		const bypassOpportunities = await WAFDetector.detectBypassOpportunities(targetUrl);

		return new Response(
			JSON.stringify({
				detection,
				bypassOpportunities,
				timestamp: new Date().toISOString(),
			}),
			{
				headers: { 'content-type': 'application/json; charset=UTF-8' },
			},
		);
	} catch (error) {
		return new Response(
			JSON.stringify({
				error: 'WAF detection failed',
				message: error instanceof Error ? error.message : 'Unknown error',
			}),
			{
				status: 500,
				headers: { 'content-type': 'application/json; charset=UTF-8' },
			},
		);
	}
}

// Helper function to parse and process custom headers
function processCustomHeaders(customHeadersStr: string, payload?: string): Record<string, string> {
	const headersObj: Record<string, string> = {};
	if (!customHeadersStr || !customHeadersStr.trim()) return headersObj;

	for (const line of customHeadersStr.split(/\r?\n/)) {
		const idx = line.indexOf(':');
		if (idx > 0) {
			const name = line.slice(0, idx).trim();
			let value = line.slice(idx + 1).trim();
			// Replace {PAYLOAD} placeholder with actual payload
			if (payload && value.includes('{PAYLOAD}')) {
				value = value.replace(/\{PAYLOAD\}/g, payload);
			}
			headersObj[name] = value;
		}
	}
	return headersObj;
}

// Helper function to substitute payload in JSON template
function substitutePayload(obj: any, payload: string): any {
	if (typeof obj === 'string') {
		return obj.replace(/\{PAYLOAD\}/g, payload);
	} else if (Array.isArray(obj)) {
		return obj.map((item) => substitutePayload(item, payload));
	} else if (obj && typeof obj === 'object') {
		const result: any = {};
		for (const [key, value] of Object.entries(obj)) {
			result[key] = substitutePayload(value, payload);
		}
		return result;
	}
	return obj;
}

// Helper function to randomly uppercase characters in a string
function randomUppercase(str: string): string {
	let result = '';
	for (let i = 0; i < str.length; i++) {
		const char = str[i];
		// Randomly uppercase 50% of alphabetic characters
		if (char.match(/[a-zA-Z]/) && Math.random() > 0.5) {
			if (char === char.toLowerCase()) {
				result += char.toUpperCase();
			} else {
				result += char.toLowerCase();
			}
		} else {
			result += char;
		}
	}
	return result;
}

// Global batch state storage (in production, use a database or KV store)
const batchJobs = new Map<
	string,
	{
		id: string;
		status: 'running' | 'completed' | 'stopped' | 'error';
		progress: number;
		currentUrl: string;
		startTime: string;
		results: any[];
		error?: string;
		totalUrls: number;
		completedUrls: number;
	}
>();

// Cleanup old batch jobs periodically to prevent memory leaks
function cleanupOldBatchJobs() {
	const cutoffTime = Date.now() - 24 * 60 * 60 * 1000; // 24 hours ago

	for (const [jobId, job] of batchJobs.entries()) {
		const jobStartTime = new Date(job.startTime).getTime();
		if (jobStartTime < cutoffTime && job.status !== 'running') {
			batchJobs.delete(jobId);
			console.log(`Cleaned up old batch job: ${jobId}`);
		}
	}
}

async function handleBatchStart(request: Request): Promise<Response> {
	// Run cleanup on each batch start request
	cleanupOldBatchJobs();

	try {
		const body = await request.json();
		const { urls, config } = body;

		// Remove delay from config as it's handled client-side
		if (config && config.delayBetweenRequests) {
			delete config.delayBetweenRequests;
		}

		if (!urls || !Array.isArray(urls) || urls.length === 0) {
			return new Response(JSON.stringify({ error: 'No URLs provided' }), {
				status: 400,
				headers: { 'content-type': 'application/json' },
			});
		}

		if (urls.length > 100) {
			return new Response(JSON.stringify({ error: 'Maximum 100 URLs allowed' }), {
				status: 400,
				headers: { 'content-type': 'application/json' },
			});
		}

		// Validate URLs
		const validUrls: string[] = [];
		const invalidUrls: string[] = [];

		for (const url of urls) {
			try {
				const urlObj = new URL(url);
				// Check if protocol is HTTP or HTTPS
				if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
					invalidUrls.push(`${url} (unsupported protocol: ${urlObj.protocol})`);
				} else {
					validUrls.push(url);
				}
			} catch {
				invalidUrls.push(`${url} (invalid URL format)`);
			}
		}

		if (invalidUrls.length > 0) {
			return new Response(
				JSON.stringify({
					error: `Invalid URLs found: ${invalidUrls.join(', ')}`,
					validUrls: validUrls.length,
					invalidUrls: invalidUrls.length,
				}),
				{
					status: 400,
					headers: { 'content-type': 'application/json' },
				},
			);
		}

		if (validUrls.length === 0) {
			return new Response(JSON.stringify({ error: 'No valid URLs provided' }), {
				status: 400,
				headers: { 'content-type': 'application/json' },
			});
		}

		const jobId = `batch_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
		const startTime = new Date().toISOString();

		// Initialize batch job
		batchJobs.set(jobId, {
			id: jobId,
			status: 'running',
			progress: 0,
			currentUrl: '',
			startTime,
			results: [],
			totalUrls: validUrls.length,
			completedUrls: 0,
		});

		console.log(`Batch job ${jobId} initialized with ${validUrls.length} valid URLs (${invalidUrls.length} invalid URLs filtered out)`);

		// Start batch processing asynchronously
		processBatchAsync(jobId, validUrls, config || {});

		return new Response(
			JSON.stringify({
				jobId,
				status: 'started',
				totalUrls: validUrls.length,
				filteredUrls: invalidUrls.length,
			}),
			{
				headers: { 'content-type': 'application/json' },
			},
		);
	} catch (error) {
		return new Response(JSON.stringify({ error: 'Invalid request body' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}
}

async function handleBatchStatus(request: Request): Promise<Response> {
	// Occasionally run cleanup on status requests (every ~20th request)
	if (Math.random() < 0.05) {
		cleanupOldBatchJobs();
	}

	const urlObj = new URL(request.url);
	const jobId = urlObj.searchParams.get('jobId');

	if (!jobId) {
		return new Response(JSON.stringify({ error: 'Missing jobId parameter' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}

	const job = batchJobs.get(jobId);
	if (!job) {
		console.log(`Job ${jobId} not found. Available jobs:`, Array.from(batchJobs.keys()));
		return new Response(JSON.stringify({ error: 'Job not found' }), {
			status: 404,
			headers: { 'content-type': 'application/json' },
		});
	}

	console.log(`Status request for job ${jobId}:`, {
		progress: job.progress,
		completedUrls: job.completedUrls,
		totalUrls: job.totalUrls,
		currentUrl: job.currentUrl,
		status: job.status,
	});

	return new Response(JSON.stringify(job), {
		headers: { 'content-type': 'application/json' },
	});
}

async function handleBatchStop(request: Request): Promise<Response> {
	const urlObj = new URL(request.url);
	const jobId = urlObj.searchParams.get('jobId');

	if (!jobId) {
		return new Response(JSON.stringify({ error: 'Missing jobId parameter' }), {
			status: 400,
			headers: { 'content-type': 'application/json' },
		});
	}

	const job = batchJobs.get(jobId);
	if (!job) {
		return new Response(JSON.stringify({ error: 'Job not found' }), {
			status: 404,
			headers: { 'content-type': 'application/json' },
		});
	}

	if (job.status === 'running') {
		job.status = 'stopped';
		job.error = 'Stopped by user';
	}

	return new Response(JSON.stringify({ status: 'stopped' }), {
		headers: { 'content-type': 'application/json' },
	});
}

async function processBatchAsync(jobId: string, urls: string[], config: any) {
	const job = batchJobs.get(jobId);
	if (!job) return;

	const maxConcurrent = Math.min(config.maxConcurrent || 3, 5);
	let completedCount = 0;

	const semaphore = { permits: maxConcurrent, queue: [] as Array<() => void> };

	async function acquireSemaphore(): Promise<void> {
		if (semaphore.permits > 0) {
			semaphore.permits--;
			return Promise.resolve();
		}
		return new Promise<void>((resolve) => {
			semaphore.queue.push(resolve);
		});
	}

	function releaseSemaphore(): void {
		semaphore.permits++;
		if (semaphore.queue.length > 0) {
			const resolve = semaphore.queue.shift();
			if (resolve) {
				semaphore.permits--;
				resolve();
			}
		}
	}

	function updateProgress(currentUrl: string = '') {
		const currentJob = batchJobs.get(jobId);
		if (currentJob && currentJob.status === 'running') {
			currentJob.completedUrls = completedCount;
			currentJob.progress = Math.round((completedCount / urls.length) * 100);
			currentJob.currentUrl = currentUrl;
			console.log(`Batch ${jobId} progress: ${currentJob.progress}% (${completedCount}/${urls.length}) - ${currentUrl}`);
		}
	}

	const processUrl = async (url: string, index: number): Promise<string | null> => {
		const currentJob = batchJobs.get(jobId);
		if (!currentJob || currentJob.status !== 'running') return null;

		await acquireSemaphore();

		try {
			// Update current URL being processed
			updateProgress(url);

			// Delay is now handled on client-side

			const currentJobCheck = batchJobs.get(jobId);
			if (!currentJobCheck || currentJobCheck.status !== 'running') return null;

			// Run tests for this URL with timeout
			const urlResults = await Promise.race([
				testSingleUrlForBatch(url, config),
				new Promise<never>(
					(_, reject) => setTimeout(() => reject(new Error('URL test timeout')), 300000), // 5 minute timeout
				),
			]);

			const finalJob = batchJobs.get(jobId);
			if (finalJob && finalJob.status === 'running') {
				const resultEntry = {
					url,
					success: true,
					results: urlResults,
					timestamp: new Date().toISOString(),
					totalTests: urlResults.length,
					bypassedTests: urlResults.filter((r) => r.status === 200 || r.status === '200').length,
					bypassRate:
						urlResults.length > 0
							? Math.round((urlResults.filter((r) => r.status === 200 || r.status === '200').length / urlResults.length) * 100)
							: 0,
				};

				finalJob.results.push(resultEntry);
				completedCount++;
				updateProgress(url);
			}

			return url;
		} catch (error) {
			console.error(`Error processing URL ${url}:`, error);
			const errorJob = batchJobs.get(jobId);
			if (errorJob && errorJob.status === 'running') {
				errorJob.results.push({
					url,
					success: false,
					error: error instanceof Error ? error.message : 'Unknown error',
					timestamp: new Date().toISOString(),
					totalTests: 0,
					bypassedTests: 0,
					bypassRate: 0,
				});

				completedCount++;
				updateProgress(url);
			}
			return null;
		} finally {
			releaseSemaphore();
		}
	};

	try {
		const promises = urls.map((url, index) => processUrl(url, index));
		await Promise.allSettled(promises);

		const finalJob = batchJobs.get(jobId);
		if (finalJob) {
			finalJob.status = finalJob.status === 'running' ? 'completed' : finalJob.status;
			finalJob.progress = 100;
			finalJob.completedUrls = completedCount;
			finalJob.currentUrl = '';
			console.log(`Batch ${jobId} finished with status: ${finalJob.status}`);
		}
	} catch (error) {
		console.error(`Batch ${jobId} failed:`, error);
		const errorJob = batchJobs.get(jobId);
		if (errorJob) {
			errorJob.status = 'error';
			errorJob.error = error instanceof Error ? error.message : 'Unknown error';
		}
	}
}

async function testSingleUrlForBatch(url: string, config: any): Promise<any[]> {
	console.log(`Starting batch test for URL: ${url}`);
	const methods = config.methods || ['GET'];
	const categories = config.categories || ['SQL Injection', 'XSS'];

	let allResults: any[] = [];
	let page = 0;
	let maxPages = 10; // Limit to prevent infinite loops

	while (page < maxPages) {
		const params = new URLSearchParams({
			url,
			methods: methods.join(','),
			categories: categories.join(','),
			page: page.toString(),
			followRedirect: config.followRedirect ? '1' : '0',
			falsePositiveTest: config.falsePositiveTest ? '1' : '0',
			caseSensitiveTest: config.caseSensitiveTest ? '1' : '0',
			enhancedPayloads: config.enhancedPayloads ? '1' : '0',
			useAdvancedPayloads: config.useAdvancedPayloads ? '1' : '0',
			autoDetectWAF: config.autoDetectWAF ? '1' : '0',
			useEncodingVariations: config.useEncodingVariations ? '1' : '0',
			httpManipulation: config.httpManipulation ? '1' : '0',
		});

		try {
			const results = await handleApiCheckFiltered(
				url,
				page,
				methods,
				categories,
				config.payloadTemplate,
				config.followRedirect || false,
				config.customHeaders,
				config.falsePositiveTest || false,
				config.caseSensitiveTest || false,
				config.enhancedPayloads || false,
				config.useAdvancedPayloads || false,
				config.autoDetectWAF || false,
				config.useEncodingVariations || false,
				undefined,
				config.httpManipulation
					? {
							enableParameterPollution: true,
							enableVerbTampering: true,
							enableContentTypeConfusion: true,
						}
					: undefined,
			);

			if (!results || !results.length) {
				console.log(`No more results for ${url} at page ${page}`);
				break;
			}

			allResults = allResults.concat(results);
			console.log(`Batch test ${url}: page ${page} completed, ${results.length} results, total: ${allResults.length}`);
			page++;

			// Limit results to prevent memory issues
			if (allResults.length > 1000) {
				console.log(`Result limit reached for ${url}`);
				break;
			}
		} catch (error) {
			console.error(`Error testing ${url} at page ${page}:`, error);
			break;
		}
	}

	console.log(`Batch test completed for ${url}: ${allResults.length} total results`);
	return allResults;
}
