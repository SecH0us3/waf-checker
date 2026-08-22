import { generateEncodedPayloads } from './advanced-payloads';
import { PAYLOADS as DATA_PAYLOADS } from './payloads-data/base';

export type PayloadCategory = {
	type: 'ParamCheck' | 'FileCheck' | 'Header';
	payloads: string[];
	falsePayloads: string[];
};

export const PAYLOADS: Record<string, PayloadCategory> = DATA_PAYLOADS;

// Export enhanced payload collection with all encoding variations
export const ENHANCED_PAYLOADS = {
	...PAYLOADS,
	...generateEncodedPayloads(PAYLOADS),
};
