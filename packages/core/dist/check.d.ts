import { HTTPManipulationOptions } from './http-manipulation';
export declare function sendRequest(url: string, method: string, payload?: string, headersObj?: Record<string, string>, payloadTemplate?: string, followRedirect?: boolean, useEnhancedPayloads?: boolean, detectedWAF?: string, httpManipulation?: HTTPManipulationOptions, options?: {
    fetch?: typeof fetch;
    color?: boolean;
}): Promise<{
    status: string;
    is_redirect: boolean;
    responseTime: number;
    response?: undefined;
} | {
    status: number;
    is_redirect: boolean;
    responseTime: number;
    response: Response;
}>;
export declare function handleApiCheckFiltered(url: string, page: number, methods: string[], categories?: string[], payloadTemplate?: string, followRedirect?: boolean, customHeaders?: string, falsePositiveTest?: boolean, caseSensitiveTest?: boolean, useEnhancedPayloads?: boolean, useAdvancedPayloads?: boolean, autoDetectWAF?: boolean, useEncodingVariations?: boolean, detectedWAF?: string, httpManipulation?: HTTPManipulationOptions, options?: {
    fetch?: typeof fetch;
    color?: boolean;
}): Promise<any[]>;
