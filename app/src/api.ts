import { handleApiCheckFiltered } from './handlers/check';
import { handleWAFDetection } from './handlers/waf-detect';
import { handleHTTPManipulation } from './handlers/http-manip';
import { handleBatchStart, handleBatchStatus, handleBatchStop } from './handlers/batch';

export default {
	async fetch(request: Request, env: { ASSETS: { fetch: typeof fetch } }): Promise<Response> {
		const urlObj = new URL(request.url);
		if (urlObj.pathname === '/') {
			return env.ASSETS.fetch(request);
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
			// Validate URL protocol to prevent SSRF
			try {
				const parsedUrl = new URL(url.replace(/\{PAYLOAD\}/g, 'test'));
				if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
					return new Response(JSON.stringify({ error: 'Only http and https protocols are allowed' }), {
						status: 400,
						headers: { 'content-type': 'application/json; charset=UTF-8' },
					});
				}
			} catch {
				return new Response(JSON.stringify({ error: 'Invalid URL format' }), {
					status: 400,
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
			const detectedWAF = urlObj.searchParams.get('detectedWAF') || bodyDetectedWAF || undefined;

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
