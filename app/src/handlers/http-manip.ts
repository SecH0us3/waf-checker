import { HTTPManipulator, HTTPManipulationOptions } from '../http-manipulation';

export async function handleHTTPManipulation(request: Request): Promise<Response> {
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
            enableParameterPollution: false,
            enableContentTypeConfusion: false,
            enableRequestSmuggling: false,
            enableHostHeaderInjection: false,
        };

        // Substitute {PAYLOAD} in the URL if present
        const resolvedUrl = targetUrl.includes('{PAYLOAD}')
            ? targetUrl.replace(/\{PAYLOAD\}/g, encodeURIComponent(testPayload))
            : targetUrl;

        // Generate manipulated requests
        const manipulatedRequests = HTTPManipulator.generateManipulatedRequests(resolvedUrl, 'GET', testPayload, manipulationOptions);

        // Execute all manipulated requests
        const results = await HTTPManipulator.batchExecuteRequests(manipulatedRequests, false, 5);

        return new Response(
            JSON.stringify({
                total_techniques: manipulatedRequests.length,
                tested_techniques: manipulatedRequests.length,
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
