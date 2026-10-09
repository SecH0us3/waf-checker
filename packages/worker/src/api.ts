import { handleApiCheckFiltered, handleApiCheckWithEnvelope } from './handlers/check';
import { handleWAFDetection } from './handlers/waf-detect';
import { handleHTTPManipulation } from './handlers/http-manip';
import {
	isValidTargetUrl,
	runReverseEngineeringAudit,
	generateVirtualPatches,
	WAFDetector,
	resolveWorkerPageSize,
	LEGIT_USER_AGENTS,
} from '@waf-checker/core';
import {
	handleScheduleSubscribe,
	handleScheduleVerify,
	handleScheduleUnsubscribe,
	handleScheduledCron,
} from './handlers/schedule';
import { WorkerEnv } from './types/monitor';

export const SELF_HOSTS = ['secmy.org', 'secmy.app'];

export function isSelfScan(targetUrlOrHost: string): boolean {
	try {
		let host = targetUrlOrHost.toLowerCase();
		if (host.includes('://')) {
			const u = new URL(targetUrlOrHost.replace(/\{PAYLOAD\}/g, 'test-payload'));
			host = u.hostname.toLowerCase();
		}
		return SELF_HOSTS.some((h) => host === h || host.endsWith(`.${h}`));
	} catch {
		return false;
	}
}

export default {
	async fetch(request: Request, env: WorkerEnv): Promise<Response> {
		const urlObj = new URL(request.url);
		if (!urlObj.pathname.startsWith('/api/')) {
			return env.ASSETS.fetch(request);
		}
		if (urlObj.pathname === '/api/virtual-patch') {
			if (request.method !== 'POST') {
				return new Response(JSON.stringify({ error: 'Method not allowed. Use POST.' }), {
					status: 405,
					headers: { 'content-type': 'application/json' },
				});
			}
			try {
				const body: any = await request.json();
				const results = body?.results;
				if (!results || !Array.isArray(results)) {
					return new Response(JSON.stringify({ error: 'Missing results array in request body' }), {
						status: 400,
						headers: { 'content-type': 'application/json' },
					});
				}
				const options = body?.options || {};
				if (options.targetUrl && !isValidTargetUrl(options.targetUrl)) {
					return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), {
						status: 400,
						headers: { 'content-type': 'application/json' },
					});
				}
				const report = generateVirtualPatches(results, options);
				return new Response(JSON.stringify(report), {
					headers: { 'content-type': 'application/json; charset=UTF-8' },
				});
			} catch (err: any) {
				return new Response(JSON.stringify({ error: err.message }), {
					status: 500,
					headers: { 'content-type': 'application/json' },
				});
			}
		}
		if (urlObj.pathname === '/api/reverse-engineer') {
			let url = urlObj.searchParams.get('url');
			if (!url && request.method === 'POST') {
				try {
					const body: any = await request.clone().json();
					if (body && typeof body.url === 'string') url = body.url;
				} catch {}
			}
			if (!url) return new Response('Missing url param', { status: 400 });
			if (!isValidTargetUrl(url)) {
				return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), { status: 400 });
			}
			try {
				const report = await runReverseEngineeringAudit(url, { isWorker: true });
				return new Response(JSON.stringify(report), { headers: { 'content-type': 'application/json; charset=UTF-8' } });
			} catch (err: any) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { 'content-type': 'application/json' } });
			}
		}
		if (urlObj.pathname === '/api/waf-detect') {
			const url = urlObj.searchParams.get('url');
			if (url && !isValidTargetUrl(url)) return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), { status: 400 });
			return await handleWAFDetection(request);
		}
		if (urlObj.pathname === '/api/check') {
			const url = urlObj.searchParams.get('url');
			if (!url) return new Response('Missing url param', { status: 400 });

			// Validate template URL by substituting placeholder with a safe value first.
			// This prevents valid templates like http://{PAYLOAD}.example.com from being rejected.
			const testUrl = url.replace(/\{PAYLOAD\}/g, 'test-payload');
			if (!isValidTargetUrl(testUrl)) {
				return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), { status: 400 });
			}

			if (isSelfScan(url)) {
				return new Response(JSON.stringify({ error: 'self-scan refused', code: 'SELF_SCAN_REFUSED' }), {
					status: 422,
					headers: { 'content-type': 'application/json; charset=UTF-8' },
				});
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
			let bodyDetectedWAF: string | undefined = undefined;
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
						bodyDetectedWAF = body.detectedWAF;
					}
				} catch (e) {
					console.error('Error parsing request body:', e);
				}
			}
			const followRedirect = urlObj.searchParams.get('followRedirect') === '1';
			const falsePositiveTest = urlObj.searchParams.get('falsePositiveTest') === '1';
			const caseSensitiveTest = urlObj.searchParams.get('caseSensitiveTest') === '1';
			const useEnhancedPayloads = urlObj.searchParams.get('enhancedPayloads') === '1';
			const useAdvancedPayloads = urlObj.searchParams.get('useAdvancedPayloads') === '1';
			const autoDetectWAF = urlObj.searchParams.get('autoDetectWAF') === '1';
			const useEncodingVariations = urlObj.searchParams.get('useEncodingVariations') === '1';
			const enableHTTPManipulation = urlObj.searchParams.get('httpManipulation') === '1';
			const enablePadding = urlObj.searchParams.get('enablePadding') === '1' || Boolean(urlObj.searchParams.get('paddingSize'));
			const paddingSize = urlObj.searchParams.get('paddingSize') || '16kb';
			// Legitimate-User-Agent bypass test. Opt-in at the raw API (it can multiply
			// request volume ~16x per blocked payload); the UI/CLI enable it by default
			// and send spoofUserAgent=1.
			const spoofUserAgents = urlObj.searchParams.get('spoofUserAgent') === '1';
			const detectedWAF = urlObj.searchParams.get('detectedWAF') || bodyDetectedWAF || undefined;

			const wantsEnvelope =
				urlObj.searchParams.get('envelope') === '1' ||
				urlObj.searchParams.get('envelope') === 'true' ||
				request.headers.get('accept')?.includes('application/vnd.waf-checker.v2+json');
			// Clamped to what one invocation's subrequest budget allows for this scan's
			// options (see resolveWorkerPageSize); the frontend keeps paging until empty.
			const pageSizeParam = urlObj.searchParams.get('pageSize') || urlObj.searchParams.get('limit');
			const pageSize = resolveWorkerPageSize(pageSizeParam ? parseInt(pageSizeParam, 10) : undefined, {
				legitUserAgentCount: spoofUserAgents ? LEGIT_USER_AGENTS.length : 0,
				followRedirect,
			});

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
				(enableHTTPManipulation || enablePadding)
					? {
							enableParameterPollution: enableHTTPManipulation,
							enableVerbTampering: enableHTTPManipulation,
							enableContentTypeConfusion: enableHTTPManipulation,
							enableInspectionLimitPadding: enablePadding,
							paddingSize: paddingSize as any,
						}
					: undefined,
				{ isWorker: true, pageSize, spoofUserAgents },
			);

			if (wantsEnvelope) {
				return new Response(JSON.stringify(envelope), { headers: { 'content-type': 'application/json; charset=UTF-8' } });
			}
			return new Response(JSON.stringify(envelope.results), { headers: { 'content-type': 'application/json; charset=UTF-8' } });
		}
		if (urlObj.pathname === '/api/audit') {
			let url = urlObj.searchParams.get('url');
			let bodyPayloadTemplate: string | undefined = undefined;
			let bodyCustomHeaders: string | undefined = undefined;
			let bodyCategories: string[] | undefined = undefined;
			// WAF type found on an earlier page ('' = none found). Passing it back
			// skips re-detection and keeps the payload plan, and so the page
			// boundaries, identical across pages.
			let knownWAF: string | undefined = urlObj.searchParams.has('detectedWAF')
				? urlObj.searchParams.get('detectedWAF') || ''
				: undefined;

			if (request.method === 'POST') {
				try {
					const body: any = await request.clone().json();
					if (body && typeof body.url === 'string') url = body.url;
					if (body && Array.isArray(body.categories)) bodyCategories = body.categories;
					if (body && typeof body.payloadTemplate === 'string') bodyPayloadTemplate = body.payloadTemplate;
					if (body && typeof body.customHeaders === 'string') bodyCustomHeaders = body.customHeaders;
					if (body && typeof body.detectedWAF === 'string' && knownWAF === undefined) knownWAF = body.detectedWAF;
				} catch {}
			}

			if (!url) {
				return new Response(JSON.stringify({ error: 'Missing url parameter' }), {
					status: 400,
					headers: { 'content-type': 'application/json; charset=UTF-8' },
				});
			}
			const testUrl = url.replace(/\{PAYLOAD\}/g, 'test-payload');
			if (!isValidTargetUrl(testUrl)) {
				return new Response(JSON.stringify({ error: 'Invalid URL or restricted IP' }), {
					status: 400,
					headers: { 'content-type': 'application/json; charset=UTF-8' },
				});
			}
			if (isSelfScan(url)) {
				return new Response(JSON.stringify({ error: 'self-scan refused', code: 'SELF_SCAN_REFUSED' }), {
					status: 422,
					headers: { 'content-type': 'application/json; charset=UTF-8' },
				});
			}

			const categoriesParam = urlObj.searchParams.get('categories');
			let categories = bodyCategories;
			if (categoriesParam) {
				categories = categoriesParam
					.split(',')
					.map((c) => c.trim())
					.filter(Boolean);
			}

			// One request by default: the full plan (~500 items, ~1200 with a detected
			// WAF's variations, each following up to 5 redirects) fits one invocation's
			// subrequest budget, so the default page covers it and hasMore is false.
			// Paging stays as a guard: if a plan ever outgrows the budget, the page is
			// clamped and hasMore says so instead of results being dropped silently.
			// Clients continue with `page + 1` and `detectedWAF`.
			const pageParam = parseInt(urlObj.searchParams.get('page') || '0', 10);
			const page = Number.isFinite(pageParam) && pageParam > 0 ? pageParam : 0;
			const pageSizeParam = urlObj.searchParams.get('pageSize');
			const pageSize = resolveWorkerPageSize(pageSizeParam ? parseInt(pageSizeParam, 10) : undefined, {
				legitUserAgentCount: 0,
				followRedirect: true,
			}, Number.MAX_SAFE_INTEGER);

			const detection =
				knownWAF === undefined ? await WAFDetector.activeDetection(url.replace(/\{PAYLOAD\}/g, ''), { isWorker: true }) : null;
			const detectedWAF = knownWAF ?? (detection?.detected && detection.wafType ? detection.wafType : '');
			const envelope = await handleApiCheckWithEnvelope(
				url,
				page,
				['GET'],
				categories,
				bodyPayloadTemplate,
				// Follow redirects: an unfollowed 3xx (http->https, canonical host) tells us
				// nothing about whether the file is exposed, and would be reported as a
				// checked-but-not-exposed path. In-scope only, enforced in sendRequest.
				true,
				bodyCustomHeaders,
				false,
				false,
				false,
				false,
				false,
				false,
				detectedWAF || undefined,
				undefined,
				{ isWorker: true, pageSize },
			);

			// Patches for this page's results; for one bundle over a multi-page audit,
			// POST the combined results to /api/virtual-patch.
			const patches = generateVirtualPatches(envelope.results, { targetUrl: url });

			return new Response(
				JSON.stringify({
					detection,
					detectedWAF,
					results: envelope.results,
					patches,
					page: envelope.page,
					pageSize: envelope.pageSize,
					total: envelope.total,
					hasMore: envelope.hasMore,
				}),
				{ headers: { 'content-type': 'application/json; charset=UTF-8' } },
			);
		}
		if (urlObj.pathname === '/api/http-manipulation') {
			return await handleHTTPManipulation(request);
		}
		if (urlObj.pathname === '/api/schedule/subscribe') {
			return await handleScheduleSubscribe(request, env);
		}
		if (urlObj.pathname === '/api/schedule/verify') {
			return await handleScheduleVerify(request, env);
		}
		if (urlObj.pathname === '/api/schedule/unsubscribe') {
			return await handleScheduleUnsubscribe(request, env);
		}
		return new Response('Not found', { status: 404 });
	},
	async scheduled(event: ScheduledEvent, env: WorkerEnv, ctx?: ExecutionContext): Promise<void> {
		// Awaited, and failures rethrown, so a broken run is recorded as a failed
		// cron invocation. Handing the promise to waitUntil() without a catch made
		// every rejection an unhandled one and every run look successful.
		const run = handleScheduledCron(env).catch((err) => {
			console.error('Scheduled monitoring run failed:', err);
			throw err;
		});
		if (ctx && typeof ctx.waitUntil === 'function') {
			ctx.waitUntil(run);
		}
		await run;
	},
};
