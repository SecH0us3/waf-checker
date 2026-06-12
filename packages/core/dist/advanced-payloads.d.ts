import { PayloadCategory } from './payloads';
export declare const ADVANCED_PAYLOADS: Record<string, PayloadCategory>;
/**
 * Generate dynamic bypass payloads using encoding techniques
 */
export declare function generateEncodedPayloads(originalPayloads: Record<string, PayloadCategory>): Record<string, PayloadCategory>;
/**
 * WAF-specific bypass payload generator
 */
export declare function generateWAFSpecificPayloads(wafType: string, basePayload: string): string[];
/**
 * Generate HTTP manipulation specific payloads
 */
export declare function generateHTTPManipulationPayloads(basePayload: string, technique?: 'verb' | 'pollution' | 'content-type' | 'smuggling'): string[];
