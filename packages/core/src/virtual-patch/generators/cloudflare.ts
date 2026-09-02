import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import { CATEGORY_HEURISTICS, detectInspectionLocation, escapeRegex, sanitizeStrictToken } from '../heuristics';

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

	// Group by category if requested
	const groups: Record<string, AuditResultItem[]> = {};
	if (options.groupByCategory !== false) {
		for (const b of bypasses) {
			groups[b.category] = groups[b.category] || [];
			groups[b.category].push(b);
		}
	} else {
		bypasses.forEach((b, idx) => {
			groups[`${b.category}_${idx + 1}`] = [b];
		});
	}

	let ruleIndex = 1;
	for (const [groupKey, items] of Object.entries(groups)) {
		const category = items[0].category;
		const location = detectInspectionLocation(category, items[0].method, items[0].payload);
		const cfField = getCloudflareField(location, category);
		const sanitizedCat = category.toLowerCase().replace(/[^a-z0-9]/g, '_');

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = [...new Set(items.map((it) => sanitizeStrictToken(it.payload)))];
			const conditions = tokens.map((token) => {
				const escaped = token.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
				return `(lower(${cfField}) contains "${escaped.toLowerCase()}")`;
			});

			const exprBody = conditions.length === 1 ? conditions[0] : `(${conditions.join(' or ')})`;
			const fullExpression = `${pathScope}${exprBody}`;
			const ruleRef = `waf_checker_cf_${sanitizedCat}_strict_${ruleIndex}`;

			const terraformSnippet = `resource "cloudflare_ruleset" "virtual_patch_${sanitizedCat}_strict" {
  zone_id     = var.cloudflare_zone_id
  name        = "WAF-Checker Virtual Patch [${category}] (Strict)"
  description = "Auto-generated virtual patch for ${category} bypasses"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "${ruleRef}"
      description = "Block verified ${category} bypass tokens"
      expression  = "${fullExpression.replace(/"/g, '\\"')}"
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
      expression  = "${fullExpression.replace(/"/g, '\\"')}"
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
