import { handleApiCheckFiltered } from './handlers/check';
import { handleWAFDetection } from './handlers/waf-detect';
import { handleHTTPManipulation } from './handlers/http-manip';
import { handleBatchStart, handleBatchStatus, handleBatchStop } from './handlers/batch';

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
