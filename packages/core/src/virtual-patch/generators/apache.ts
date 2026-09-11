import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import {
	CATEGORY_HEURISTICS,
	detectInspectionLocation,
	escapeRegex,
	sanitizeStrictToken,
	escapeDoubleQuotes,
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
 * Map an inspection location to the Apache mod_rewrite variable that carries it.
 * Apache's rewrite engine cannot read the request body, so body checks fall
 * back to the query string with an explicit note.
 */
function getApacheVariable(location: 'query' | 'body' | 'header' | 'uri', category: string): string {
	switch (location) {
		case 'header':
			if (category === 'User-Agent') return '%{HTTP_USER_AGENT}';
			if (category.includes('JWT')) return '%{HTTP:Authorization}';
			return '%{HTTP:X-Forwarded-For}';
		case 'uri':
			return '%{REQUEST_URI}';
		case 'body':
		case 'query':
		default:
			return '%{QUERY_STRING}';
	}
}

/**
 * Generates Apache mod_rewrite rules (drop-in for httpd.conf, a <VirtualHost>
 * / <Directory> block, or an .htaccess file). Each attack category yields a
 * `RewriteCond` guarding a `RewriteRule` that returns 403 (block) or tags the
 * request via an environment variable (simulate).
 */
export function generateApachePatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const isSimulate = options.action === 'simulate';
	const urlPath = options.scopeToPath ? getUrlPath(options.targetUrl) : null;

	const actionFlag = (envKey: string) => (isSimulate ? `[E=${envKey}:1,L]` : '[F,L]');

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
		const apacheVar = getApacheVariable(location, category);
		const sanitizedCat = category.toUpperCase().replace(/[^A-Z0-9]/g, '_');

		const headerLines = (tier: string): string[] => {
			const lines = [
				`# --- WAF-Checker Virtual Patch: ${category} (${tier}) ---`,
				`# Requires mod_rewrite. Place in httpd.conf, a <VirtualHost>/<Directory>, or .htaccess.`,
				`# Prepend "RewriteEngine On" once per context.`,
			];
			if (location === 'body') {
				lines.push(
					`# NOTE: Apache mod_rewrite cannot inspect request bodies; matching the query string only.`,
					`# For body inspection use mod_security (SecRule REQUEST_BODY ...).`
				);
			} else if (location === 'query') {
				lines.push(`# NOTE: %{QUERY_STRING} is URL-encoded; add decoded variants if the app decodes params.`);
			}
			return lines;
		};

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = Array.from(new Set(items.map((i) => sanitizeStrictToken(i.payload, category)))).filter(Boolean);
			const alternation = tokens.map((t) => escapeRegex(t)).join('|');
			const envKey = `WAF_SIM_${sanitizedCat}_STRICT`;

			const lines = headerLines('Strict');
			if (urlPath) {
				lines.push(`RewriteCond %{REQUEST_URI} "^${escapeDoubleQuotes(escapeRegex(urlPath))}" [NC]`);
			}
			lines.push(
				`RewriteCond ${apacheVar} "(${escapeDoubleQuotes(alternation)})" [NC]`,
				`RewriteRule ^ - ${actionFlag(envKey)}`
			);
			if (isSimulate) {
				lines.push(`# Optional (mod_headers): Header always set X-WAF-Simulation-Triggered "1" env=${envKey}`);
			}

			patches.push({
				vendor: 'apache',
				name: `Apache: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule: lines.join('\n'),
				description: `Apache mod_rewrite rule matching ${tokens.length} verified ${category} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const rawPattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);
			const envKey = `WAF_SIM_${sanitizedCat}_HEURISTIC`;

			const lines = headerLines('Heuristic');
			if (urlPath) {
				lines.push(`RewriteCond %{REQUEST_URI} "^${escapeDoubleQuotes(escapeRegex(urlPath))}" [NC]`);
			}
			lines.push(
				`RewriteCond ${apacheVar} "${escapeDoubleQuotes(rawPattern)}" [NC]`,
				`RewriteRule ^ - ${actionFlag(envKey)}`
			);
			if (isSimulate) {
				lines.push(`# Optional (mod_headers): Header always set X-WAF-Simulation-Triggered "1" env=${envKey}`);
			}

			patches.push({
				vendor: 'apache',
				name: `Apache: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule: lines.join('\n'),
				description: heuristic ? heuristic.description : `Apache mod_rewrite heuristic defense for ${category}`,
			});
		}
	}

	return patches;
}
