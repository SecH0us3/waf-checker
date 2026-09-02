import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import { CATEGORY_HEURISTICS, detectInspectionLocation, escapeRegex, sanitizeStrictToken } from '../heuristics';

function getUrlPath(targetUrl?: string): string | null {
	if (!targetUrl) return null;
	try {
		const parsed = new URL(targetUrl);
		return parsed.pathname !== '/' ? parsed.pathname : null;
	} catch {
		return null;
	}
}

function getModSecTarget(location: 'query' | 'body' | 'header' | 'uri', category: string): string {
	switch (location) {
		case 'header':
			if (category === 'User-Agent') return 'REQUEST_HEADERS:User-Agent';
			if (category.includes('JWT')) return 'REQUEST_HEADERS:Authorization';
			return 'REQUEST_HEADERS:X-Forwarded-For';
		case 'uri':
			return 'REQUEST_URI';
		case 'body':
			return 'REQUEST_BODY';
		case 'query':
		default:
			return 'ARGS|REQUEST_URI';
	}
}

export function generateModSecurityPatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const isSimulate = options.action === 'simulate';
	const actionStr = isSimulate ? 'pass,log,auditlog' : 'deny,status:403';
	const actionPrefix = isSimulate ? '[SIMULATION] ' : '';
	const urlPath = options.scopeToPath ? getUrlPath(options.targetUrl) : null;
	let currentId = options.ruleIdPrefix || 900000;

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

	for (const [groupKey, items] of Object.entries(groups)) {
		const category = items[0].category;
		const location = detectInspectionLocation(category, items[0].method, items[0].payload);
		const targetVar = getModSecTarget(location, category);

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = [...new Set(items.map((it) => sanitizeStrictToken(it.payload)))];
			const lines: string[] = [
				`# ------------------------------------------------------------------------`,
				`# WAF-Checker Virtual Patch: ${category} (Strict)`,
				`# ${actionPrefix}Blocks ${tokens.length} verified attack bypass signature(s)`,
				`# ------------------------------------------------------------------------`,
			];

			tokens.forEach((token) => {
				const escapedToken = token.replace(/"/g, '\\"');
				if (urlPath) {
					lines.push(
						`SecRule REQUEST_URI "@beginsWith ${urlPath}" \\`,
						`    "id:${currentId},phase:2,chain,${actionStr},t:none,msg:'${actionPrefix}WAF-Checker Virtual Patch: ${category}',tag:'waf-checker',tag:'virtual-patch'"`,
						`    SecRule ${targetVar} "@contains ${escapedToken}" "t:none,t:urlDecodeUni,t:lowercase"`
					);
				} else {
					lines.push(
						`SecRule ${targetVar} "@contains ${escapedToken}" \\`,
						`    "id:${currentId},phase:2,${actionStr},t:none,t:urlDecodeUni,t:lowercase,msg:'${actionPrefix}WAF-Checker Virtual Patch: ${category}',tag:'waf-checker',tag:'virtual-patch'"`
					);
				}
				currentId++;
			});

			const nativeRule = lines.join('\n');
			patches.push({
				vendor: 'modsecurity',
				name: `ModSecurity: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule,
				description: `ModSecurity SecRule exact string match on ${tokens.length} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const pattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);
			const escapedPattern = pattern.replace(/"/g, '\\"');

			const lines: string[] = [
				`# ------------------------------------------------------------------------`,
				`# WAF-Checker Virtual Patch: ${category} (Heuristic Regex)`,
				`# ${actionPrefix}Generalized rule for ${category} attack vector`,
				`# ------------------------------------------------------------------------`,
			];

			if (urlPath) {
				lines.push(
					`SecRule REQUEST_URI "@beginsWith ${urlPath}" \\`,
					`    "id:${currentId},phase:2,chain,${actionStr},t:none,msg:'${actionPrefix}WAF-Checker Heuristic Defense: ${category}',tag:'waf-checker',tag:'heuristic'"`,
					`    SecRule ${targetVar} "@rx ${escapedPattern}" "t:none,t:urlDecodeUni,t:lowercase"`
				);
			} else {
				lines.push(
					`SecRule ${targetVar} "@rx ${escapedPattern}" \\`,
					`    "id:${currentId},phase:2,${actionStr},t:none,t:urlDecodeUni,t:lowercase,msg:'${actionPrefix}WAF-Checker Heuristic Defense: ${category}',tag:'waf-checker',tag:'heuristic'"`
				);
			}
			currentId++;

			const nativeRule = lines.join('\n');
			patches.push({
				vendor: 'modsecurity',
				name: `ModSecurity: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule,
				description: heuristic ? heuristic.description : `ModSecurity SecRule heuristic regex for ${category}`,
			});
		}
	}

	return patches;
}
