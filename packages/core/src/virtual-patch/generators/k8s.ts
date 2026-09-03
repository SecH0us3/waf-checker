import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import {
	CATEGORY_HEURISTICS,
	detectInspectionLocation,
	escapeRegex,
	sanitizeStrictToken,
} from '../heuristics';

function getHostname(targetUrl?: string): string {
	if (!targetUrl) return 'app.example.com';
	try {
		return new URL(targetUrl).hostname || 'app.example.com';
	} catch {
		return 'app.example.com';
	}
}

function escapeNginxRegex(str: string): string {
	return str.replace(/"/g, '\\"');
}

/**
 * Generates Kubernetes Ingress YAML manifests with Ingress-NGINX security server-snippets.
 */
export function generateK8sPatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const isSimulate = options.action === 'simulate';
	const actionSnippet = isSimulate
		? 'add_header X-WAF-Simulation-Triggered "1" always;'
		: 'return 403;';
	const host = getHostname(options.targetUrl);

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
		const sanitizedCat = category.toLowerCase().replace(/[^a-z0-9]/g, '-');

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = Array.from(new Set(items.map((i) => sanitizeStrictToken(i.payload, category)))).filter(
				Boolean
			);

			const snippetLines: string[] = [];
			if (location === 'uri') {
				const isVcs = (t: string) => t === '.git' || t === '.svn' || t === '.hg';
				const extTokens = tokens
					.filter((t) => t.startsWith('.') && !isVcs(t) && !t.includes('/'))
					.map((t) => t.slice(1));
				const vcsTokens = tokens.filter(isVcs).map((t) => t.slice(1));
				const fileTokens = tokens
					.filter((t) => !t.startsWith('.'))
					.map((t) => t.replace(/^\/+/, ''));

				if (extTokens.length > 0) {
					snippetLines.push(
						`location ~* \\.(${extTokens.join('|')})$ {`,
						`    ${actionSnippet}`,
						`}`
					);
				}
				if (vcsTokens.length > 0) {
					snippetLines.push(
						`location ~ /\\.(?:${vcsTokens.join('|')}) {`,
						`    ${actionSnippet}`,
						`}`
					);
				}
				if (fileTokens.length > 0) {
					const escapedFiles = fileTokens.map((f) => escapeNginxRegex(escapeRegex(f))).join('|');
					snippetLines.push(
						`location ~* /(${escapedFiles}) {`,
						`    ${actionSnippet}`,
						`}`
					);
				}
			} else if (location === 'header') {
				const nginxVar = category === 'User-Agent' ? '$http_user_agent' : '$http_authorization';
				const escapedAlternation = tokens.map((t) => escapeNginxRegex(escapeRegex(t))).join('|');
				snippetLines.push(
					`if (${nginxVar} ~* "(${escapedAlternation})") {`,
					`    ${actionSnippet}`,
					`}`
				);
			} else {
				const escapedAlternation = tokens.map((t) => escapeNginxRegex(escapeRegex(t))).join('|');
				snippetLines.push(
					`if ($query_string ~* "(${escapedAlternation})") {`,
					`    ${actionSnippet}`,
					`}`
				);
			}

			const indentedSnippet = snippetLines.map((l) => `      ${l}`).join('\n');
			const manifest = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: waf-patch-${sanitizedCat}-strict
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/server-snippet: |
${indentedSnippet}
spec:
  rules:
  - host: ${host}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-service
            port:
              number: 80`;

			patches.push({
				vendor: 'k8s',
				name: `Kubernetes Ingress: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule: manifest,
				description: `K8s Ingress YAML manifest matching ${tokens.length} verified ${category} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const rawPattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);
			const escapedPattern = escapeNginxRegex(rawPattern);

			let snippet = '';
			if (location === 'uri') {
				snippet = `location ~* "${escapedPattern}" {\n          ${actionSnippet}\n      }`;
			} else if (location === 'header') {
				const nginxVar = category === 'User-Agent' ? '$http_user_agent' : '$http_authorization';
				snippet = `if (${nginxVar} ~* "${escapedPattern}") {\n          ${actionSnippet}\n      }`;
			} else {
				snippet = `if ($query_string ~* "${escapedPattern}") {\n          ${actionSnippet}\n      }`;
			}

			const manifest = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: waf-patch-${sanitizedCat}-heuristic
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/server-snippet: |
      ${snippet}
spec:
  rules:
  - host: ${host}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-service
            port:
              number: 80`;

			patches.push({
				vendor: 'k8s',
				name: `Kubernetes Ingress: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule: manifest,
				description: heuristic ? heuristic.description : `K8s Ingress regex defense for ${category}`,
			});
		}
	}

	return patches;
}
