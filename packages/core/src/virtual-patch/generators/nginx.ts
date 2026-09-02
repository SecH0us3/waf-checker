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

function getNginxVariable(location: 'query' | 'body' | 'header' | 'uri', category: string): string {
	switch (location) {
		case 'header':
			if (category === 'User-Agent') return '$http_user_agent';
			if (category.includes('JWT')) return '$http_authorization';
			return '$http_x_forwarded_for';
		case 'uri':
			return '$request_uri';
		case 'body':
			// Nginx native rewrite module cannot inspect request bodies directly without lua
			return '$request_uri';
		case 'query':
		default:
			return '$query_string';
	}
}

export function generateNginxPatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const isSimulate = options.action === 'simulate';
	const actionSnippet = isSimulate
		? `# Simulation mode: log to custom header instead of blocking\n    add_header X-WAF-Simulation-Triggered "1" always;`
		: `return 403;`;
	const urlPath = options.scopeToPath ? getUrlPath(options.targetUrl) : null;

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
		const nginxVar = getNginxVariable(location, category);
		const sanitizedCat = category.toLowerCase().replace(/[^a-z0-9]/g, '_');

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = [...new Set(items.map((it) => sanitizeStrictToken(it.payload)))];
			const escapedAlternation = tokens.map((tok) => escapeRegex(tok)).join('|');

			const lines: string[] = [
				`# --- WAF-Checker Virtual Patch: ${category} (Strict) ---`,
			];

			if (urlPath) {
				lines.push(
					`location ${urlPath} {`,
					`    # Match verified bypass signatures within ${urlPath}`,
					`    if (${nginxVar} ~* "(${escapedAlternation})") {`,
					`        ${actionSnippet}`,
					`    }`,
					`}`
				);
			} else {
				lines.push(
					`# Drop-in check for server/location block`,
					`if (${nginxVar} ~* "(${escapedAlternation})") {`,
					`    ${actionSnippet}`,
					`}`
				);
			}

			// Add high-performance map snippet comment
			lines.push(
				``,
				`# High-Performance Alternative (Add in http {} block):`,
				`# map ${nginxVar} $waf_patch_${sanitizedCat}_blocked {`,
				`#     default 0;`,
				...tokens.map((t) => `#     "~*${escapeRegex(t)}" 1;`),
				`# }`,
				`# Inside server/location: if ($waf_patch_${sanitizedCat}_blocked) { ${isSimulate ? 'add_header X-WAF-Simulation "1";' : 'return 403;'} }`
			);

			const nativeRule = lines.join('\n');
			patches.push({
				vendor: 'nginx',
				name: `NGINX: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule,
				description: `Nginx regex block matching ${tokens.length} verified ${category} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const pattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);

			const lines: string[] = [
				`# --- WAF-Checker Heuristic Defense: ${category} ---`,
			];

			if (urlPath) {
				lines.push(
					`location ${urlPath} {`,
					`    if (${nginxVar} ~* "${pattern}") {`,
					`        ${actionSnippet}`,
					`    }`,
					`}`
				);
			} else {
				lines.push(
					`if (${nginxVar} ~* "${pattern}") {`,
					`    ${actionSnippet}`,
					`}`
				);
			}

			const nativeRule = lines.join('\n');
			patches.push({
				vendor: 'nginx',
				name: `NGINX: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule,
				description: heuristic ? heuristic.description : `Nginx heuristic regex defense for ${category}`,
			});
		}
	}

	return patches;
}
