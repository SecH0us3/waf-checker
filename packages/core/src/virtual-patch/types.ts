import { AuditResultItem } from '../reports/types';

export type PatchVendor = 'cloudflare' | 'aws' | 'modsecurity' | 'nginx' | 'all';
export type PatchTier = 'strict' | 'heuristic' | 'both';
export type PatchAction = 'block' | 'simulate';

export interface VirtualPatchOptions {
	/**
	 * Target WAF vendor dialect. Default: 'all'.
	 */
	vendor?: PatchVendor;

	/**
	 * Defense tier: 'strict' (exact token match), 'heuristic' (generalized regex pattern), or 'both'.
	 * Default: 'both'.
	 */
	tier?: PatchTier;

	/**
	 * Rule action: 'block' (HTTP 403 / Drop) or 'simulate' (count / log).
	 * Default: 'block'.
	 */
	action?: PatchAction;

	/**
	 * Whether to restrict the rule inspection to the specific URL path (e.g. /api/login).
	 * Default: false.
	 */
	scopeToPath?: boolean;

	/**
	 * Target URL being audited. Used for endpoint scoping and metadata comments.
	 */
	targetUrl?: string;

	/**
	 * Consolidate bypasses by attack category to conserve rule quotas (AWS WCUs, Cloudflare limits).
	 * Default: true.
	 */
	groupByCategory?: boolean;

	/**
	 * Starting numeric ID for rule engines requiring unique rule IDs (e.g. ModSecurity).
	 * Default: 1000000 (reserving 900000-999999 for OWASP Core Rule Set).
	 */
	ruleIdPrefix?: number;

	/**
	 * Include Terraform HCL snippets where supported (Cloudflare & AWS WAF).
	 * Default: true.
	 */
	includeTerraform?: boolean;
}

export interface GeneratedPatch {
	vendor: PatchVendor;
	name: string;
	category: string;
	tier: 'strict' | 'heuristic';
	nativeRule: string;
	terraformHcl?: string;
	description: string;
}

export interface VendorPatchBundle {
	vendor: PatchVendor;
	native: string;
	terraform?: string;
	ruleCount: number;
}

export interface VirtualPatchReport {
	targetUrl?: string;
	generatedAt: string;
	totalBypasses: number;
	bypasses: AuditResultItem[];
	patches: GeneratedPatch[];
	bundles: Record<string, VendorPatchBundle>;
}
