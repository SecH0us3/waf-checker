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

        switch (method) {
            case 'GET':
            case 'DELETE':
                resp = await fetch(finalUrl, {
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
                    resp = await fetch(finalUrl, {
                        method,
                        redirect: redirectOption,
                        body: JSON.stringify(jsonObj),
                        headers: new Headers({ ...(headersObj || {}), 'Content-Type': 'application/json' }),
                    });
                } else {
                    resp = await fetch(finalUrl, { method, redirect: redirectOption, body: new URLSearchParams({ test: finalPayload ?? '' }), headers });
                }
                break;
            default:
                return null;
        }

        const responseTime = Date.now() - startTime;
        console.log(
            `Request to ${url} with method ${method} and payload ${payload ?? '(none)'} and headers ${JSON.stringify(headersObj)} returned status ${resp.status} in ${responseTime}ms`,
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
