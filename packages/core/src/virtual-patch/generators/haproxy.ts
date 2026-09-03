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

function escapeHAProxyString(str: string): string {
	return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$');
}

/**
 * Generates HAProxy ACL configuration snippets (native haproxy.cfg).
 */
export function generateHAProxyPatches(
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

			const aclLines: string[] = [
				`# --- WAF-Checker Virtual Patch: ${category} (Strict) ---`,
			];
			const aclConditionNames: string[] = [];

			if (urlPath) {
				aclLines.push(`acl is_scoped_path_${sanitizedCat} path_beg ${urlPath}`);
			}

			if (location === 'uri') {
				const exts = tokens.filter((t) => t.startsWith('.') && t !== '.git' && t !== '.svn' && t !== '.hg');
				const vcs = tokens.filter((t) => t === '.git' || t === '.svn' || t === '.hg');
				const files = tokens.filter((t) => !t.startsWith('.'));

				if (exts.length > 0) {
					const aclName = `is_${sanitizedCat}_ext`;
					aclLines.push(`acl ${aclName} path_end -i -- ${exts.join(' ')}`);
					aclConditionNames.push(aclName);
				}
				if (vcs.length > 0) {
					const aclName = `is_${sanitizedCat}_vcs`;
					aclLines.push(`acl ${aclName} path_beg -i -- ${vcs.map((v) => `/${v}`).join(' ')}`);
					aclConditionNames.push(aclName);
				}
				if (files.length > 0) {
					const aclName = `is_${sanitizedCat}_files`;
					aclLines.push(`acl ${aclName} path_end -i -- ${files.map((f) => (f.startsWith('/') ? f : `/${f}`)).join(' ')}`);
					aclConditionNames.push(aclName);
				}
			} else if (location === 'header') {
				const hdrName = category === 'User-Agent' ? 'User-Agent' : 'Authorization';
				const aclName = `is_${sanitizedCat}_hdr`;
				aclLines.push(`acl ${aclName} req.hdr(${hdrName}) -m sub -i -- ${tokens.map((t) => `"${escapeHAProxyString(t)}"`).join(' ')}`);
				aclConditionNames.push(aclName);
			} else {
				// Query or Body
				const aclName = `is_${sanitizedCat}_query`;
				aclLines.push(`acl ${aclName} query -m sub -i -- ${tokens.map((t) => `"${escapeHAProxyString(t)}"`).join(' ')}`);
				aclConditionNames.push(aclName);
			}

			if (aclConditionNames.length > 0) {
				const condition = aclConditionNames.join(' or ');
				const fullCond = urlPath ? `is_scoped_path_${sanitizedCat} { ${condition} }` : condition;

				if (isSimulate) {
					aclLines.push(`http-request set-header X-WAF-Simulation "blocked" if ${fullCond}`);
				} else {
					aclLines.push(`http-request deny deny_status 403 if ${fullCond}`);
				}
			}

			const nativeRule = aclLines.join('\n');
			patches.push({
				vendor: 'haproxy',
				name: `HAProxy: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule,
				description: `HAProxy ACL directive matching ${tokens.length} verified ${category} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const rawPattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);

			const aclLines: string[] = [
				`# --- WAF-Checker Virtual Patch: ${category} (Heuristic) ---`,
			];
			const aclName = `is_${sanitizedCat}_rx`;

			if (urlPath) {
				aclLines.push(`acl is_scoped_path_${sanitizedCat} path_beg ${urlPath}`);
			}

			if (location === 'uri') {
				aclLines.push(`acl ${aclName} path -m reg -i -- "${escapeHAProxyString(rawPattern)}"`);
			} else if (location === 'header') {
				const hdrName = category === 'User-Agent' ? 'User-Agent' : 'Authorization';
				aclLines.push(`acl ${aclName} req.hdr(${hdrName}) -m reg -i -- "${escapeHAProxyString(rawPattern)}"`);
			} else {
				aclLines.push(`acl ${aclName} query -m reg -i -- "${escapeHAProxyString(rawPattern)}"`);
			}

			const fullCond = urlPath ? `is_scoped_path_${sanitizedCat} ${aclName}` : aclName;
			if (isSimulate) {
				aclLines.push(`http-request set-header X-WAF-Simulation "blocked" if ${fullCond}`);
			} else {
				aclLines.push(`http-request deny deny_status 403 if ${fullCond}`);
			}

			const nativeRule = aclLines.join('\n');
			patches.push({
				vendor: 'haproxy',
				name: `HAProxy: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule,
				description: heuristic ? heuristic.description : `HAProxy regex ACL defense for ${category}`,
			});
		}
	}

	return patches;
}
