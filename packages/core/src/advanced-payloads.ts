import { PayloadCategory } from './payloads';
import { PayloadEncoder, WAFBypasses } from './encoding';
import { ADVANCED_PAYLOADS } from './payloads-data/advanced';

export { ADVANCED_PAYLOADS };

/**
 * Generate dynamic bypass payloads using encoding techniques
 */
export function generateEncodedPayloads(originalPayloads: Record<string, PayloadCategory>): Record<string, PayloadCategory> {
	const encodedPayloads: Record<string, PayloadCategory> = {};

	for (const [categoryName, category] of Object.entries(originalPayloads)) {
		const encodedCategory: PayloadCategory = {
			type: category.type,
			payloads: [],
			falsePayloads: category.falsePayloads || [],
		};

		// Generate encoded variations for each payload
		for (const payload of category.payloads) {
			const variations = PayloadEncoder.generateBypassVariations(payload, categoryName);
			encodedCategory.payloads.push(...variations);
		}

		// Remove duplicates
		encodedCategory.payloads = [...new Set(encodedCategory.payloads)];

		encodedPayloads[`${categoryName} - Encoded`] = encodedCategory;
	}

	return encodedPayloads;
}

/**
 * Bypass candidates for a known WAF type, in order, or undefined when the type
 * has no dedicated bypasses and the generic encoding variations apply.
 */
function wafBypassCandidates(wafType: string, basePayload: string): Iterable<string> | undefined {
	switch (wafType.toLowerCase()) {
		case 'cloudflare':
			return WAFBypasses.cloudflareCandidates(basePayload);
		case 'aws':
		case 'awswaf':
		case 'aws waf':
			return WAFBypasses.awsWafCandidates(basePayload);
		case 'modsecurity':
			return WAFBypasses.modSecurityCandidates(basePayload);
		case 'akamai':
			return WAFBypasses.akamaiCandidates(basePayload);
		case 'azure':
		case 'azure front door':
		case 'azure waf':
			return WAFBypasses.azureCandidates(basePayload);
		case 'palo alto networks':
		case 'palo alto':
		case 'pan-os':
			return WAFBypasses.panosCandidates(basePayload);
		case 'sophos':
		case 'sophos waf':
		case 'sophos utm':
			return WAFBypasses.sophosCandidates(basePayload);
		case 'imperva':
		case 'incapsula':
			return WAFBypasses.impervaCandidates(basePayload);
		case 'f5':
		case 'f5 big-ip':
		case 'f5 big ip':
			return WAFBypasses.f5BigIpCandidates(basePayload);
		case 'google':
		case 'google cloud armor':
		case 'cloud armor':
		case 'gcp':
			return WAFBypasses.googleCloudArmorCandidates(basePayload);
		case 'signal sciences':
		case 'signalsciences':
			return WAFBypasses.signalSciencesCandidates(basePayload);
		case 'nginx':
		case 'nginx app protect':
		case 'naxsi':
			return WAFBypasses.nginxAppProtectCandidates(basePayload);
		case 'haproxy':
			return WAFBypasses.haproxyCandidates(basePayload);
		case 'ibm datapower':
		case 'datapower':
			return WAFBypasses.ibmDataPowerCandidates(basePayload);
		case 'reblaze':
			return WAFBypasses.reblazeCandidates(basePayload);
		case 'dotdefender':
			return WAFBypasses.dotDefenderCandidates(basePayload);
		case 'qrator':
		case 'qrator waf':
		default:
			// Generic encodings: not a WAFBypasses candidate list.
			return undefined;
	}
}

/**
 * WAF-specific bypass payload generator
 */
export function generateWAFSpecificPayloads(wafType: string, basePayload: string): string[] {
	const candidates = wafBypassCandidates(wafType, basePayload);
	return candidates
		? [...new Set([basePayload, ...candidates])]
		: PayloadEncoder.generateBypassVariations(basePayload);
}

/**
 * The first bypass variation for a WAF type, i.e. generateWAFSpecificPayloads(...)[1],
 * or the payload itself when there is none. Stops at the first candidate that
 * differs from the payload instead of generating and deduplicating them all:
 * sendRequest needs only this one, for every request and every trusted-UA /
 * IP-header probe of a scan against a known WAF.
 */
export function firstWAFSpecificVariant(wafType: string, basePayload: string): string {
	const candidates = wafBypassCandidates(wafType, basePayload);
	if (!candidates) {
		const variations = PayloadEncoder.generateBypassVariations(basePayload);
		return variations.length > 1 ? variations[1] : basePayload;
	}
	for (const candidate of candidates) {
		if (candidate !== basePayload) return candidate;
	}
	return basePayload;
}

/**
 * Generate HTTP manipulation specific payloads
 */
export function generateHTTPManipulationPayloads(
	basePayload: string,
	technique: 'verb' | 'pollution' | 'content-type' | 'smuggling' = 'pollution',
): string[] {
	const variations = [basePayload];

	switch (technique) {
		case 'pollution':
			// Parameter pollution variations
			variations.push(`param=${encodeURIComponent(basePayload)}&param=${encodeURIComponent(basePayload)}`);
			variations.push(`param[]=${encodeURIComponent(basePayload)}&param[]=${encodeURIComponent(basePayload)}`);
			variations.push(`param=${encodeURIComponent(basePayload)}&PARAM=${encodeURIComponent(basePayload)}`);
			break;

		case 'content-type':
			// Content-Type specific formatting
			variations.push(`{"payload": "${basePayload.replace(/"/g, '\\"')}"}`);
			variations.push(`<?xml version="1.0"?><payload>${basePayload.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</payload>`);
			variations.push(`payload=${encodeURIComponent(basePayload)}`);
			break;

		case 'smuggling':
			// Request smuggling variations
			variations.push(`0\r\n\r\n${basePayload}`);
			variations.push(`${basePayload.length.toString(16)}\r\n${basePayload}\r\n0\r\n\r\n`);
			break;
	}

	return [...new Set(variations)];
}
