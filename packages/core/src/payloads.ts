import { generateEncodedPayloads } from './advanced-payloads';
import { PAYLOADS as DATA_PAYLOADS } from './payloads-data/base';

export type PayloadCategory = {
	type: 'ParamCheck' | 'FileCheck' | 'Header';
	payloads: string[];
	falsePayloads: string[];
};

export const PAYLOADS: Record<string, PayloadCategory> = DATA_PAYLOADS;

let enhancedPayloads: Record<string, PayloadCategory> | undefined;

/**
 * Base payloads plus every encoding variation of them. Built on first use:
 * generating the variations costs ~100 ms of CPU and ~20 MB of heap, which
 * every import (each Worker cold start, each CLI run) would otherwise pay
 * whether or not the scan asks for enhanced payloads.
 */
export function getEnhancedPayloads(): Record<string, PayloadCategory> {
	if (!enhancedPayloads) {
		enhancedPayloads = {
			...PAYLOADS,
			...generateEncodedPayloads(PAYLOADS),
		};
	}
	return enhancedPayloads;
}

// Export enhanced payload collection with all encoding variations.
// A lazy view over getEnhancedPayloads(): the collection is only generated
// when something actually reads from it.
export const ENHANCED_PAYLOADS: Record<string, PayloadCategory> = new Proxy({} as Record<string, PayloadCategory>, {
	get: (_target, key) => Reflect.get(getEnhancedPayloads(), key),
	has: (_target, key) => Reflect.has(getEnhancedPayloads(), key),
	ownKeys: () => Reflect.ownKeys(getEnhancedPayloads()),
	getOwnPropertyDescriptor: (_target, key) => {
		const desc = Reflect.getOwnPropertyDescriptor(getEnhancedPayloads(), key);
		// The proxy target is empty, so a reported property must be configurable.
		if (desc) desc.configurable = true;
		return desc;
	},
});
