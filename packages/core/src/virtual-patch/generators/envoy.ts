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

/** Wrap a RE2 pattern for case-insensitive full-value substring matching. */
function re2Contains(pattern: string, pathPrefix?: string): string {
	const anchor = pathPrefix ? `^${escapeRegex(pathPrefix)}.*` : '.*';
	return `(?i)${anchor}(${pattern}).*`;
}

/**
 * RE2 program-size ceiling for the generated `safe_regex` matchers. Envoy's
 * default `re2.max_program_size.error_level` is only 100, which rejects any
 * non-trivial strict alternation (a ~20-token list compiles to ~400). We set a
 * generous per-regex ceiling so the emitted config loads out of the box; tune
 * it down if you prefer stricter limits.
 */
const MAX_PROGRAM_SIZE = 1000;

/** Embed a regex as a YAML single-quoted scalar (only single quotes need doubling). */
function yamlSingleQuote(str: string): string {
	return `'${str.replace(/'/g, "''")}'`;
}

/** Header name Envoy should inspect for a given category. */
function getEnvoyHeader(category: string): string {
	if (category === 'User-Agent') return 'user-agent';
	if (category.includes('JWT')) return 'authorization';
	return 'x-forwarded-for';
}

/**
 * Generates Envoy proxy route entries that block verified WAF bypasses with a
 * `direct_response: 403` (or, in simulate mode, tag matched requests with a
 * response header while still forwarding them). Drop the emitted entries into
 * a route_configuration virtual_host's `routes:` list, ahead of the catch-all
 * route. Envoy's route matcher cannot inspect request bodies, so body-borne
 * categories are matched on `:path` with a note (use ext_authz/Lua/Wasm for
 * true body inspection).
 */
export function generateEnvoyPatches(
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

	const buildAction = (category: string): string[] => {
		if (isSimulate) {
			return [
				`    route:`,
				`      cluster: "REPLACE_WITH_UPSTREAM_CLUSTER"`,
				`    response_headers_to_add:`,
				`      - header:`,
				`          key: "x-waf-simulation"`,
				`          value: "${category.replace(/"/g, '')}"`,
			];
		}
		return [
			`    direct_response:`,
			`      status: 403`,
			`      body:`,
			`        inline_string: "Request blocked by WAF-Checker virtual patch"`,
		];
	};

	// Build a route entry for a given RE2 pattern, dispatching on inspection location.
	//
	// Everything is matched via a `headers` string_match, never the route-level
	// `safe_regex` path matcher: the latter matches only the path and DROPS the
	// query string, so query-borne attacks would slip through. The `:path`
	// pseudo-header, by contrast, carries the full path + query string.
	const buildRoute = (category: string, location: string, pattern: string): string[] => {
		const headerName = location === 'header' ? getEnvoyHeader(category) : ':path';
		const prefix = location === 'header' ? urlPath || '/' : '/';
		const lines: string[] = [
			`  - match:`,
			`      prefix: "${prefix}"`,
			`      headers:`,
			`        - name: "${headerName}"`,
			`          string_match:`,
			`            safe_regex:`,
			`              google_re2: { max_program_size: ${MAX_PROGRAM_SIZE} }`,
			`              regex: ${yamlSingleQuote(pattern)}`,
		];
		lines.push(...buildAction(category));
		return lines;
	};

	for (const [category, items] of Object.entries(groups)) {
		const sampleItem = items[0];
		const location = detectInspectionLocation(category, sampleItem.method, sampleItem.payload);
		const bodyNote =
			location === 'body'
				? [`  # NOTE: Envoy route matching cannot read request bodies; matched on :path instead.`,
					`  # For body inspection use an ext_authz / Lua / Wasm HTTP filter.`]
				: [];

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = Array.from(new Set(items.map((i) => sanitizeStrictToken(i.payload, category)))).filter(Boolean);
			const alternation = tokens.map((t) => escapeRegex(t)).join('|');
			const pattern = re2Contains(alternation, location === 'header' ? undefined : urlPath || undefined);

			const lines = [
				`# --- WAF-Checker Virtual Patch: ${category} (Strict) ---`,
				`# Add to an Envoy route_configuration virtual_host's routes: list, before the catch-all route.`,
				...bodyNote,
				...buildRoute(category, location, pattern),
			];
			patches.push({
				vendor: 'envoy',
				name: `Envoy: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule: lines.join('\n'),
				description: `Envoy route matching ${tokens.length} verified ${category} bypass token(s) with direct_response 403`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const rawPattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);
			const pattern = re2Contains(rawPattern, location === 'header' ? undefined : urlPath || undefined);

			const lines = [
				`# --- WAF-Checker Heuristic Defense: ${category} ---`,
				...bodyNote,
				...buildRoute(category, location, pattern),
			];
			patches.push({
				vendor: 'envoy',
				name: `Envoy: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule: lines.join('\n'),
				description: heuristic ? heuristic.description : `Envoy heuristic regex defense for ${category}`,
			});
		}
	}

	return patches;
}
