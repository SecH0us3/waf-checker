export interface EncodingOptions {
    doubleUrlEncode?: boolean;
    unicodeEncode?: boolean;
    htmlEntityEncode?: boolean;
    mixedCaseEncode?: boolean;
    hexEncode?: boolean;
    octalEncode?: boolean;
    base64Encode?: boolean;
    urlEncode?: boolean;
}
export declare class PayloadEncoder {
    /**
     * Double URL encode payload
     * Example: ' -> %27 -> %2527
     */
    static doubleUrlEncode(payload: string): string;
    /**
     * Unicode encode special characters
     * Example: ' -> \u0027
     */
    static unicodeEncode(payload: string): string;
    /**
     * HTML entity encode special characters
     * Example: ' -> &#39; or &#x27;
     */
    static htmlEntityEncode(payload: string, useHex?: boolean): string;
    /**
     * Mixed case encoding for keywords
     * Example: UNION SELECT -> uNiOn SeLeCt
     */
    static mixedCaseEncode(payload: string): string;
    /**
     * Hex encode characters
     * Example: ' -> 0x27
     */
    static hexEncode(payload: string): string;
    /**
     * Octal encode characters
     * Example: ' -> \047
     */
    static octalEncode(payload: string): string;
    /**
     * Base64 encode payload
     */
    static base64Encode(payload: string): string;
    /**
     * Apply multiple encoding techniques
     */
    static applyEncodings(payload: string, options: EncodingOptions): string[];
    /**
     * SQL injection specific obfuscation techniques
     */
    static sqlObfuscation(payload: string): string[];
    /**
     * XSS specific obfuscation techniques
     */
    static xssObfuscation(payload: string): string[];
    /**
     * Generate comprehensive bypass variations for any payload
     */
    static generateBypassVariations(payload: string, attackType?: string): string[];
}
/**
 * WAF-specific bypass utilities
 */
export declare class WAFBypasses {
    /**
     * Cloudflare specific bypasses
     */
    static cloudflareBypass(payload: string): string[];
    /**
     * AWS WAF specific bypasses
     */
    static awsWafBypass(payload: string): string[];
    /**
     * ModSecurity bypasses
     */
    static modSecurityBypass(payload: string): string[];
    /**
     * Akamai specific bypasses
     */
    static akamaiBypass(payload: string): string[];
    /**
     * Azure specific bypasses
     */
    static azureBypass(payload: string): string[];
    /**
     * Palo Alto Networks specific bypasses
     */
    static panosBypass(payload: string): string[];
    /**
     * Sophos WAF specific bypasses
     */
    static sophosBypass(payload: string): string[];
    /**
     * Generate random case variations
     */
    private static randomCase;
}
