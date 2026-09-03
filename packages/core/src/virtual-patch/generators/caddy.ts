import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import {
	CATEGORY_HEURISTICS,
	detectInspectionLocation,
	escapeRegex,
	sanitizeStrictToken,
} from '../heuristics';

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
 * Generates Caddyfile named matchers and directive blocks.
 */
export function generateCaddyPatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const isSimulate = options.action === 'simulate';
	const urlPath = options.scopeToPath ? getUrlPath(options.targetUrl) : null;

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

	for (const [category, items] of Object.entries(groups)) {
		const sampleItem = items[0];
		const location = detectInspectionLocation(category, sampleItem.method, sampleItem.payload);
		const sanitizedCat = category.toLowerCase().replace(/[^a-z0-9]/g, '_');

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = Array.from(new Set(items.map((i) => sanitizeStrictToken(i.payload, category)))).filter(
				Boolean
			);

			const matcherName = `@waf_patch_${sanitizedCat}_strict`;
			const lines: string[] = [
				`# --- WAF-Checker Virtual Patch: ${category} (Strict) ---`,
				`${matcherName} {`,
			];

			if (urlPath) {
				lines.push(`    path ${urlPath}*`);
			}

			if (location === 'uri') {
				const exts = tokens.filter((t) => t.startsWith('.') && t !== '.git' && t !== '.svn' && t !== '.hg');
				const vcs = tokens.filter((t) => t === '.git' || t === '.svn' || t === '.hg');
				const files = tokens.filter((t) => !t.startsWith('.'));

				if (exts.length > 0) {
					lines.push(`    path *${exts.join(' *')}`);
				}
				if (vcs.length > 0) {
					lines.push(`    path ${vcs.map((v) => `*/${v}/*`).join(' ')}`);
				}
				if (files.length > 0) {
					lines.push(`    path ${files.map((f) => (f.startsWith('/') ? f : `/${f}`)).join(' ')}`);
				}
			} else if (location === 'header') {
				const hdrName = category === 'User-Agent' ? 'User-Agent' : 'Authorization';
				for (const tok of tokens) {
					lines.push(`    header ${hdrName} *${tok}*`);
				}
			} else {
				for (const tok of tokens) {
					lines.push(`    query *${tok.replace(/\s+/g, '*')}*`);
				}
			}

			lines.push(`}`);
			if (isSimulate) {
				lines.push(`header ${matcherName} X-WAF-Simulation "blocked"`);
			} else {
				lines.push(`respond ${matcherName} 403`);
			}

			const nativeRule = lines.join('\n');
			patches.push({
				vendor: 'caddy',
				name: `Caddy: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule,
				description: `Caddy named matcher matching ${tokens.length} verified ${category} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const rawPattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);

			const matcherName = `@waf_patch_${sanitizedCat}_heuristic`;
			const lines: string[] = [
				`# --- WAF-Checker Virtual Patch: ${category} (Heuristic) ---`,
				`${matcherName} {`,
			];

			if (urlPath) {
				lines.push(`    path ${urlPath}*`);
			}

			if (location === 'uri') {
				lines.push(`    path_regexp "(?i)${rawPattern.replace(/"/g, '\\"')}"`);
			} else if (location === 'header') {
				const hdrName = category === 'User-Agent' ? 'User-Agent' : 'Authorization';
				lines.push(`    header_regexp ${hdrName} "(?i)${rawPattern.replace(/"/g, '\\"')}"`);
			} else {
				lines.push(`    query_regexp "(?i)${rawPattern.replace(/"/g, '\\"')}"`);
			}

			lines.push(`}`);
			if (isSimulate) {
				lines.push(`header ${matcherName} X-WAF-Simulation "blocked"`);
			} else {
				lines.push(`respond ${matcherName} 403`);
			}

			const nativeRule = lines.join('\n');
			patches.push({
				vendor: 'caddy',
				name: `Caddy: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule,
				description: heuristic ? heuristic.description : `Caddy regex matcher defense for ${category}`,
			});
		}
	}

	return patches;
}
