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
 * WAF-specific bypass payload generator
 */
export function generateWAFSpecificPayloads(wafType: string, basePayload: string): string[] {
	switch (wafType.toLowerCase()) {
		case 'cloudflare':
			return WAFBypasses.cloudflareBypass(basePayload);
		case 'aws':
		case 'awswaf':
		case 'aws waf':
			return WAFBypasses.awsWafBypass(basePayload);
		case 'modsecurity':
			return WAFBypasses.modSecurityBypass(basePayload);
		case 'akamai':
			return WAFBypasses.akamaiBypass(basePayload);
		case 'azure':
		case 'azure front door':
		case 'azure waf':
			return WAFBypasses.azureBypass(basePayload);
		case 'palo alto networks':
		case 'palo alto':
		case 'pan-os':
			return WAFBypasses.panosBypass(basePayload);
		case 'sophos':
		case 'sophos waf':
		case 'sophos utm':
			return WAFBypasses.sophosBypass(basePayload);
		case 'imperva':
		case 'incapsula':
			return WAFBypasses.impervaBypass(basePayload);
		case 'f5':
		case 'f5 big-ip':
		case 'f5 big ip':
			return WAFBypasses.f5BigIpBypass(basePayload);
		case 'google':
		case 'google cloud armor':
		case 'cloud armor':
		case 'gcp':
			return WAFBypasses.googleCloudArmorBypass(basePayload);
		case 'signal sciences':
		case 'signalsciences':
			return WAFBypasses.signalSciencesBypass(basePayload);
		case 'nginx':
		case 'nginx app protect':
		case 'naxsi':
			return WAFBypasses.nginxAppProtectBypass(basePayload);
		case 'haproxy':
			return WAFBypasses.haproxyBypass(basePayload);
		case 'ibm datapower':
		case 'datapower':
			return WAFBypasses.ibmDataPowerBypass(basePayload);
		case 'reblaze':
			return WAFBypasses.reblazeBypass(basePayload);
		case 'dotdefender':
			return WAFBypasses.dotDefenderBypass(basePayload);
		default:
			return PayloadEncoder.generateBypassVariations(basePayload);
	}
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
