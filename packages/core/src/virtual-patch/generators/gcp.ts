import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import {
	CATEGORY_HEURISTICS,
	detectInspectionLocation,
	escapeRegex,
	sanitizeStrictToken,
	escapeHclString,
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
 * Escapes characters for embedding inside CEL single-quoted string literals.
 */
function escapeCelString(str: string): string {
	return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

/**
 * Maps logical location to Google Cloud Armor CEL (Common Expression Language) request field.
 */
function getCelField(location: 'query' | 'body' | 'header' | 'uri', category: string): string {
	switch (location) {
		case 'header':
			if (category === 'User-Agent') return "request.headers['user-agent']";
			if (category.includes('JWT')) return "request.headers['authorization']";
			return "request.headers['x-forwarded-for']";
		case 'uri':
			return 'request.path';
		case 'body':
		case 'query':
		default:
			return 'request.query';
	}
}

/**
 * Generates Google Cloud Armor security policy rules (CEL expressions, gcloud CLI commands, and Terraform HCL).
 */
export function generateGcpPatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const isSimulate = options.action === 'simulate';
	const urlPath = options.scopeToPath ? getUrlPath(options.targetUrl) : null;
	const pathScope = urlPath ? `request.path == '${escapeCelString(urlPath)}' && ` : '';
	let currentPriority = options.ruleIdPrefix ? Math.floor(options.ruleIdPrefix / 1000) : 1000;

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
		const celField = getCelField(location, category);
		const sanitizedCat = category.replace(/[^a-zA-Z0-9]/g, '_');
		const gcloudPreviewFlag = isSimulate ? ' --preview' : '';

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = Array.from(new Set(items.map((i) => sanitizeStrictToken(i.payload, category)))).filter(
				Boolean
			);

			const matchClauses: string[] = [];
			if (location === 'uri') {
				for (const tok of tokens) {
					if (tok === '.git' || tok === '.svn' || tok === '.hg') {
						matchClauses.push(`request.path.matches('/\\\\.(?:${tok.slice(1)})')`);
					} else if (tok.startsWith('.')) {
						matchClauses.push(`request.path.lower().endsWith('${escapeCelString(tok.toLowerCase())}')`);
					} else {
						const cleanTok = tok.startsWith('/') ? tok : `/${tok}`;
						matchClauses.push(`request.path.lower().endsWith('${escapeCelString(cleanTok.toLowerCase())}')`);
					}
				}
			} else {
				for (const tok of tokens) {
					const escaped = escapeCelString(tok.toLowerCase());
					matchClauses.push(`${celField}.lower().contains('${escaped}')`);
				}
			}

			const condition = matchClauses.length === 1 ? matchClauses[0] : `(${matchClauses.join(' || ')})`;
			const fullExpression = `${pathScope}${condition}`;

			const terraformSnippet = `resource "google_compute_security_policy" "virtual_patch_${sanitizedCat}_strict" {
  name        = "waf-checker-security-policy"
  description = "Auto-generated Cloud Armor virtual patch for ${category} (Strict)"

  rule {
    action      = "deny(403)"
    priority    = "${currentPriority}"
    description = "Block verified ${category} bypass tokens"
    preview     = ${isSimulate}

    match {
      expr {
        expression = "${escapeHclString(fullExpression)}"
      }
    }
  }
}`;

			const gcloudCmd = `gcloud compute security-policies rules create ${currentPriority} \\
    --security-policy="waf-checker-policy" \\
    --expression="${fullExpression.replace(/"/g, '\\"')}" \\
    --action="deny-403" \\
    --description="Block verified ${category} bypass tokens"${gcloudPreviewFlag}`;

			patches.push({
				vendor: 'gcp',
				name: `Google Cloud Armor: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule: fullExpression,
				terraformHcl: terraformSnippet,
				gcloudCommand: gcloudCmd,
				description: `Cloud Armor CEL rule matching ${tokens.length} verified ${category} bypass token(s)`,
			});
			currentPriority += 10;
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const rawPattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);
			const fullExpression = `${pathScope}(${celField}.matches('${escapeCelString(rawPattern)}'))`;

			const terraformSnippet = `resource "google_compute_security_policy" "virtual_patch_${sanitizedCat}_heuristic" {
  name        = "waf-checker-security-policy"
  description = "Auto-generated Cloud Armor heuristic defense for ${category}"

  rule {
    action      = "deny(403)"
    priority    = "${currentPriority}"
    description = "Heuristic regex defense for ${category}"
    preview     = ${isSimulate}

    match {
      expr {
        expression = "${escapeHclString(fullExpression)}"
      }
    }
  }
}`;

			const gcloudCmd = `gcloud compute security-policies rules create ${currentPriority} \\
    --security-policy="waf-checker-policy" \\
    --expression="${fullExpression.replace(/"/g, '\\"')}" \\
    --action="deny-403" \\
    --description="Heuristic regex defense for ${category}"${gcloudPreviewFlag}`;

			patches.push({
				vendor: 'gcp',
				name: `Google Cloud Armor: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule: fullExpression,
				terraformHcl: terraformSnippet,
				gcloudCommand: gcloudCmd,
				description: heuristic ? heuristic.description : `Cloud Armor heuristic regex defense for ${category}`,
			});
			currentPriority += 10;
		}
	}

	return patches;
}
