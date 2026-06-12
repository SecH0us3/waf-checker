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
export declare class HTTPManipulator {
    /**
     * Get uncommon HTTP methods for testing
     */
    static getUncommonMethods(): string[];
    /**
     * Generate HTTP method overrides via headers
     */
    static generateMethodOverrides(baseMethod: string, targetMethod: string): Record<string, string>[];
    /**
     * Generate parameter pollution variations
     */
    static generateParameterPollution(paramName: string, payload: string): string[];
    /**
     * Get Content-Type variations for testing
     */
    static getContentTypeVariations(): Record<string, string>[];
    /**
     * Generate request smuggling payloads
     */
    static generateRequestSmugglingHeaders(): Record<string, string>[];
    /**
     * Generate Host header injection variations
     */
    static generateHostHeaderVariations(originalHost: string, injectedHost: string): Record<string, string>[];
    /**
     * Generate manipulated requests for testing
     */
    static generateManipulatedRequests(originalUrl: string, originalMethod?: string, payload?: string, options?: HTTPManipulationOptions): ManipulatedRequest[];
    /**
     * Execute manipulated request
     */
    static executeManipulatedRequest(request: ManipulatedRequest, followRedirects?: boolean, options?: {
        fetch?: typeof fetch;
    }): Promise<{
        status: number | string;
        method: string;
        responseTime: number;
        headers: Record<string, string>;
        technique: string;
        description: string;
        error?: string;
    }>;
    /**
     * Batch execute multiple manipulated requests with adaptive concurrency and exponential backoff
     */
    static batchExecuteRequests(requests: ManipulatedRequest[], followRedirects?: boolean, concurrency?: number, delay?: number, options?: {
        fetch?: typeof fetch;
    }): Promise<any[]>;
    /**
     * Analyze results for bypass opportunities
     */
    static analyzeResults(results: any[]): {
        successfulTechniques: string[];
        suspiciousTechniques: string[];
        recommendations: string[];
    };
}
