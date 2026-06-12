export interface WAFDetectionResult {
    detected: boolean;
    wafType: string;
    confidence: number;
    evidence: string[];
    suggestedBypassTechniques: string[];
}
export interface WAFSignature {
    name: string;
    headers: {
        [key: string]: string | RegExp;
    };
    statusCodes?: number[];
    bodyPatterns?: RegExp[];
    cookiePatterns?: RegExp[];
    responseTime?: {
        min?: number;
        max?: number;
    };
}
export declare class WAFDetector {
    private static readonly WAF_SIGNATURES;
    /**
     * Get list of supported WAF vendor names
     */
    static getSupportedWafs(): string[];
    /**
     * Detect WAF from HTTP response
     */
    static detectFromResponse(response: Response, responseBody?: string, responseTime?: number): Promise<WAFDetectionResult>;
    /**
     * Perform active WAF detection by sending probe requests
     */
    static activeDetection(url: string, options?: {
        fetch?: typeof fetch;
    }): Promise<WAFDetectionResult>;
    /**
     * Get suggested bypass techniques for detected WAF
     */
    private static getSuggestedBypassTechniques;
    /**
     * Detect WAF bypass opportunities
     */
    static detectBypassOpportunities(url: string, options?: {
        fetch?: typeof fetch;
    }): Promise<{
        httpMethodsBypass: boolean;
        headerBypass: boolean;
        encodingBypass: boolean;
        parameterPollution: boolean;
    }>;
}
