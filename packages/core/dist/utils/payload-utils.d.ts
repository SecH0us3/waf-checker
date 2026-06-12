/**
 * Helper function to substitute payload in JSON template
 */
export declare function substitutePayload(obj: any, payload: string): any;
/**
 * Helper function to parse and process custom headers
 */
export declare function processCustomHeaders(customHeadersStr: string, payload?: string): Record<string, string>;
/**
 * Helper function to randomly uppercase characters in a string
 */
export declare function randomUppercase(str: string): string;
/**
 * Redacts sensitive headers from a headers object
 */
export declare function redactHeaders(headers?: Record<string, string>): Record<string, string>;
/**
 * Redacts sensitive query parameters from a URL
 */
export declare function redactUrl(urlStr: string): string;
