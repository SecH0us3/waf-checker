import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import { CATEGORY_HEURISTICS, detectInspectionLocation, escapeRegex, sanitizeStrictToken, escapeHclString } from '../heuristics';

/**
 * Extracts URL path component for scoping if enabled.
 */
function getUrlPath(targetUrl?: string): string | null {
	if (!targetUrl) return null;
	try {
		const parsed = new URL(targetUrl);
		return parsed.pathname !== '/' ? parsed.pathname : null;
	} catch {
		return null;
	}
}

/**
 * Maps logical location to Cloudflare Wirefilter field.
 */
function getCloudflareField(location: 'query' | 'body' | 'header' | 'uri', category: string): string {
	switch (location) {
		case 'header':
			if (category === 'User-Agent') return 'http.request.headers["user-agent"]';
			if (category.includes('JWT')) return 'http.request.headers["authorization"]';
			return 'http.request.headers["x-forwarded-for"]';
		case 'uri':
			return 'http.request.uri.path';
		case 'body':
			return 'http.request.body.raw';
		case 'query':
		default:
			return 'http.request.uri.query';
	}
}

/**
 * Generates Cloudflare Ruleset Engine rules (Wirefilter expressions and Terraform HCL).
 */
export function generateCloudflarePatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const action = options.action === 'simulate' ? 'log' : 'block';
	const urlPath = options.scopeToPath ? getUrlPath(options.targetUrl) : null;
	const pathScope = urlPath ? `(http.request.uri.path eq "${urlPath}") and ` : '';

	const groups: Record<string, AuditResultItem[]> = {};
	if (options.groupByCategory !== false) {
		for (const b of bypasses) {
			const cat = b.category || 'General Attack';
			if (!groups[cat]) groups[cat] = [];
			groups[cat].push(b);
		}
	} else {
		bypasses.forEach((b, idx) => {
			groups[`${b.category || 'Attack'}_${idx}`] = [b];
		});
	}

	let ruleIndex = 1;
	for (const [category, items] of Object.entries(groups)) {
		const sampleItem = items[0];
		const location = detectInspectionLocation(category, sampleItem.method, sampleItem.payload);
		const cfField = getCloudflareField(location, category);
		const sanitizedCat = category.replace(/[^a-zA-Z0-9]/g, '_');

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = Array.from(new Set(items.map((i) => sanitizeStrictToken(i.payload, category)))).filter(Boolean);
			const matchClauses = tokens.map(
				(t) => `(lower(${cfField}) contains "${t.replace(/\\/g, '\\\\').replace(/"/g, '\\"').toLowerCase()}")`
			);
			const condition = matchClauses.length === 1 ? matchClauses[0] : `(${matchClauses.join(' or ')})`;
			const fullExpression = `${pathScope}${condition}`;
			const ruleRef = `waf_checker_cf_${sanitizedCat}_strict_${ruleIndex}`;

			const terraformSnippet = `resource "cloudflare_ruleset" "virtual_patch_${sanitizedCat}_strict" {
  zone_id     = var.cloudflare_zone_id
  name        = "WAF-Checker Virtual Patch [${category}] (Strict)"
  description = "Auto-generated strict hotfix for verified bypass tokens"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "${ruleRef}"
      description = "Block verified ${category} bypass tokens"
      expression  = "${escapeHclString(fullExpression)}"
      action      = "${action}"
      enabled     = true
    }
  ]
}`;

			patches.push({
				vendor: 'cloudflare',
				name: `Cloudflare: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule: fullExpression,
				terraformHcl: terraformSnippet,
				description: `Strict match on ${tokens.length} verified ${category} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const pattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);
			const fullExpression = `${pathScope}(${cfField} matches r#"${pattern}"#)`;
			const ruleRef = `waf_checker_cf_${sanitizedCat}_heuristic_${ruleIndex}`;

			const terraformSnippet = `resource "cloudflare_ruleset" "virtual_patch_${sanitizedCat}_heuristic" {
  zone_id     = var.cloudflare_zone_id
  name        = "WAF-Checker Virtual Patch [${category}] (Heuristic)"
  description = "Auto-generated generalized heuristic rule for ${category}"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "${ruleRef}"
      description = "Heuristic regex defense for ${category}"
      expression  = "${escapeHclString(fullExpression)}"
      action      = "${action}"
      enabled     = true
    }
  ]
}`;

			patches.push({
				vendor: 'cloudflare',
				name: `Cloudflare: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule: fullExpression,
				terraformHcl: terraformSnippet,
				description: heuristic ? heuristic.description : `Heuristic pattern defense for ${category}`,
			});
		}

		ruleIndex++;
	}

	return patches;
}
