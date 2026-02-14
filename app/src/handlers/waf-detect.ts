import { WAFDetector } from '../waf-detection';

export async function handleWAFDetection(request: Request): Promise<Response> {
    const urlObj = new URL(request.url);
    const targetUrl = urlObj.searchParams.get('url');

    if (!targetUrl) {
        return new Response(JSON.stringify({ error: 'Missing url parameter' }), {
            status: 400,
            headers: { 'content-type': 'application/json; charset=UTF-8' },
        });
    }

    try {
        // Strip {PAYLOAD} from URL if present — WAF detection uses its own probe payloads
        const resolvedUrl = targetUrl.replace(/\{PAYLOAD\}/g, '');
        const detection = await WAFDetector.activeDetection(resolvedUrl);
        const bypassOpportunities = await WAFDetector.detectBypassOpportunities(resolvedUrl);

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
