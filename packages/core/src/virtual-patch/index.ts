import { AuditResultItem } from '../reports/types';
import {
	VirtualPatchOptions,
	VirtualPatchReport,
	GeneratedPatch,
	VendorPatchBundle,
	PatchVendor,
} from './types';
import { generateCloudflarePatches } from './generators/cloudflare';
import { generateAwsPatches } from './generators/aws';
import { generateModSecurityPatches } from './generators/modsecurity';
import { generateNginxPatches } from './generators/nginx';

export * from './types';
export * from './heuristics';
export * from './generators/cloudflare';
export * from './generators/aws';
export * from './generators/modsecurity';
export * from './generators/nginx';

/**
 * Filters audit results to isolate confirmed WAF bypasses (HTTP 200).
 */
export function filterBypasses(results: AuditResultItem[]): AuditResultItem[] {
	return results.filter((r) => r.status === 200 || r.status === '200');
}

/**
 * Main orchestrator: generates ready-to-deploy virtual patches and Terraform configurations
 * for all detected WAF bypasses across Cloudflare, AWS WAF, ModSecurity, and NGINX.
 */
export function generateVirtualPatches(
	results: AuditResultItem[],
	options: VirtualPatchOptions = {}
): VirtualPatchReport {
	const bypasses = filterBypasses(results);
	const targetVendor = options.vendor || 'all';
	const allPatches: GeneratedPatch[] = [];

	if (bypasses.length > 0) {
		if (targetVendor === 'all' || targetVendor === 'cloudflare') {
			allPatches.push(...generateCloudflarePatches(bypasses, options));
		}
		if (targetVendor === 'all' || targetVendor === 'aws') {
			allPatches.push(...generateAwsPatches(bypasses, options));
		}
		if (targetVendor === 'all' || targetVendor === 'modsecurity') {
			allPatches.push(...generateModSecurityPatches(bypasses, options));
		}
		if (targetVendor === 'all' || targetVendor === 'nginx') {
			allPatches.push(...generateNginxPatches(bypasses, options));
		}
	}

	// Build vendor-level bundle strings for easy 1-click copy / download
	const bundles: Record<string, VendorPatchBundle> = {};
	const vendorsToBundle: PatchVendor[] =
		targetVendor === 'all'
			? ['cloudflare', 'aws', 'modsecurity', 'nginx']
			: [targetVendor];

	for (const v of vendorsToBundle) {
		const vendorPatches = allPatches.filter((p) => p.vendor === v);
		const nativeParts = vendorPatches.map((p) => p.nativeRule);
		const tfParts = vendorPatches
			.filter((p) => p.terraformHcl)
			.map((p) => p.terraformHcl!);

		bundles[v] = {
			vendor: v,
			native: nativeParts.join('\n\n'),
			terraform: tfParts.length > 0 ? tfParts.join('\n\n') : undefined,
			ruleCount: vendorPatches.length,
		};
	}

	return {
		targetUrl: options.targetUrl,
		generatedAt: new Date().toISOString(),
		totalBypasses: bypasses.length,
		bypasses,
		patches: allPatches,
		bundles,
	};
}
