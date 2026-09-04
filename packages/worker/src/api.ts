import { handleApiCheckFiltered, handleApiCheckWithEnvelope } from './handlers/check';
import { handleWAFDetection } from './handlers/waf-detect';
import { handleHTTPManipulation } from './handlers/http-manip';
import { handleBatchStart, handleBatchStatus, handleBatchStop } from './handlers/batch';
import { isValidTargetUrl, runReverseEngineeringAudit, generateVirtualPatches, WAFDetector } from '@waf-checker/core';

function isSelfScan(targetUrl: string): boolean {
	try {
		const u = new URL(targetUrl.replace(/\{PAYLOAD\}/g, 'test-payload'));
		const host = u.hostname.toLowerCase();
		return host === 'secmy.org' || host.endsWith('.secmy.org');
	} catch {
		return false;
	}
}

export default {
	async fetch(request: Request, env: { ASSETS: { fetch: typeof fetch } }): Promise<Response> {
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
			const detectedWAF = urlObj.searchParams.get('detectedWAF') || bodyDetectedWAF || undefined;

			const wantsEnvelope =
				urlObj.searchParams.get('envelope') === '1' ||
				urlObj.searchParams.get('envelope') === 'true' ||
				request.headers.get('accept')?.includes('application/vnd.waf-checker.v2+json');
			const pageSizeParam = urlObj.searchParams.get('pageSize') || urlObj.searchParams.get('limit');
			const pageSize = pageSizeParam ? parseInt(pageSizeParam, 10) : undefined;

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
				{ isWorker: true, pageSize },
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

			if (request.method === 'POST') {
				try {
					const body: any = await request.clone().json();
					if (body && typeof body.url === 'string') url = body.url;
					if (body && Array.isArray(body.categories)) bodyCategories = body.categories;
					if (body && typeof body.payloadTemplate === 'string') bodyPayloadTemplate = body.payloadTemplate;
					if (body && typeof body.customHeaders === 'string') bodyCustomHeaders = body.customHeaders;
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

			const detection = await WAFDetector.activeDetection(url.replace(/\{PAYLOAD\}/g, ''), { isWorker: true });
			const envelope = await handleApiCheckWithEnvelope(
				url,
				0,
				['GET'],
				categories,
				bodyPayloadTemplate,
				false,
				bodyCustomHeaders,
				false,
				false,
				false,
				false,
				false,
				false,
				detection?.detected ? detection.wafType : undefined,
				undefined,
				{ isWorker: true, pageSize: 500 },
			);

			const patches = generateVirtualPatches(envelope.results, { targetUrl: url });

			return new Response(
				JSON.stringify({
					detection,
					results: envelope.results,
					patches,
				}),
				{ headers: { 'content-type': 'application/json; charset=UTF-8' } },
			);
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
