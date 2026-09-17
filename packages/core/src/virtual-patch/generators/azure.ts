import { AuditResultItem } from '../../reports/types';
import { VirtualPatchOptions, GeneratedPatch } from '../types';
import {
	CATEGORY_HEURISTICS,
	detectInspectionLocation,
	escapeRegex,
	sanitizeStrictToken,
	escapeHclString,
	escapeDoubleQuotes,
} from '../heuristics';

function getAzureMatchVariable(location: 'query' | 'body' | 'header' | 'uri') {
	switch (location) {
		case 'header':
			return 'RequestHeader';
		case 'uri':
			return 'RequestUri';
		case 'body':
			return 'RequestBody';
		case 'query':
		default:
			return 'QueryString';
	}
}

/**
 * Generates Azure Front Door / Application Gateway WAF rules (JSON, Azure CLI, and Terraform).
 *
 * Note on the native JSON match-condition field name: the Azure Front Door ARM schema
 * (Microsoft.Network/FrontDoorWebApplicationFirewallPolicies) uses `negateCondition`.
 * The misspelling `negationConditon` that appears in some Azure REST reference docs is a
 * documented typo (see Azure/azure-cli#31807) and is rejected by the real API, so it must
 * not be emitted here.
 */
export function generateAzurePatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const isSimulate = options.action === 'simulate';
	const azureAction = isSimulate ? 'Log' : 'Block';
	let currentPriority = options.ruleIdPrefix ? Math.floor(options.ruleIdPrefix / 1000) : 100;

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
		const matchVariable = getAzureMatchVariable(location);
		const sanitizedCat = category.replace(/[^a-zA-Z0-9]/g, '');
		const selector = location === 'header' ? (category === 'User-Agent' ? 'User-Agent' : 'Authorization') : undefined;

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = Array.from(new Set(items.map((i) => sanitizeStrictToken(i.payload, category)))).filter(
				Boolean
			);

			const matchConditions: any[] = [];
			const tfMatchBlocks: string[] = [];
			const cliCommands: string[] = [
				`az network front-door waf-policy rule create \\`,
				`    --policy-name="waf-policy" \\`,
				`    --resource-group="myResourceGroup" \\`,
				`    --name="VirtualPatch${sanitizedCat}Strict" \\`,
				`    --priority=${currentPriority} \\`,
				`    --rule-type="MatchRule" \\`,
				`    --action="${azureAction}" \\`,
				`    --defer`,
			];

			if (location === 'uri') {
				const exts = tokens.filter((t) => t.startsWith('.') && t !== '.git' && t !== '.svn' && t !== '.hg');
				const vcs = tokens.filter((t) => t === '.git' || t === '.svn' || t === '.hg');
				const files = tokens.filter((t) => !t.startsWith('.'));

				if (exts.length > 0) {
					matchConditions.push({
						matchVariable: 'RequestUri',
						operator: 'EndsWith',
						negateCondition: false,
						matchValue: exts,
					});
					tfMatchBlocks.push(`    match_conditions {
      match_variable     = "RequestUri"
      operator           = "EndsWith"
      negation_condition = false
      match_values       = [${exts.map((e) => `"${escapeHclString(e)}"`).join(', ')}]
    }`);
					cliCommands.push(
						`az network front-door waf-policy rule match-condition add \\`,
						`    --policy-name="waf-policy" \\`,
						`    --resource-group="myResourceGroup" \\`,
						`    --rule-name="VirtualPatch${sanitizedCat}Strict" \\`,
						`    --match-variable="RequestUri" \\`,
						`    --operator="EndsWith" \\`,
						`    --values ${exts.map((e) => `"${e}"`).join(' ')}`
					);
				}

				if (vcs.length > 0) {
					const vcsRegex = `/\\.(?:${vcs.map((v) => v.slice(1)).join('|')})`;
					matchConditions.push({
						matchVariable: 'RequestUri',
						operator: 'RegEx',
						negateCondition: false,
						matchValue: [vcsRegex],
					});
					tfMatchBlocks.push(`    match_conditions {
      match_variable     = "RequestUri"
      operator           = "RegEx"
      negation_condition = false
      match_values       = ["${escapeHclString(vcsRegex)}"]
    }`);
					cliCommands.push(
						`az network front-door waf-policy rule match-condition add \\`,
						`    --policy-name="waf-policy" \\`,
						`    --resource-group="myResourceGroup" \\`,
						`    --rule-name="VirtualPatch${sanitizedCat}Strict" \\`,
						`    --match-variable="RequestUri" \\`,
						`    --operator="RegEx" \\`,
						`    --values "${vcsRegex}"`
					);
				}

				if (files.length > 0) {
					matchConditions.push({
						matchVariable: 'RequestUri',
						operator: 'EndsWith',
						negateCondition: false,
						matchValue: files,
					});
					tfMatchBlocks.push(`    match_conditions {
      match_variable     = "RequestUri"
      operator           = "EndsWith"
      negation_condition = false
      match_values       = [${files.map((f) => `"${escapeHclString(f)}"`).join(', ')}]
    }`);
					cliCommands.push(
						`az network front-door waf-policy rule match-condition add \\`,
						`    --policy-name="waf-policy" \\`,
						`    --resource-group="myResourceGroup" \\`,
						`    --rule-name="VirtualPatch${sanitizedCat}Strict" \\`,
						`    --match-variable="RequestUri" \\`,
						`    --operator="EndsWith" \\`,
						`    --values ${files.map((f) => `"${escapeDoubleQuotes(f)}"`).join(' ')}`
					);
				}
			} else if (tokens.length > 0) {
				matchConditions.push({
					matchVariable,
					selector,
					operator: 'Contains',
					negateCondition: false,
					matchValue: tokens,
				});
				tfMatchBlocks.push(`    match_conditions {
      match_variable     = "${matchVariable}"
      ${selector ? `selector           = "${selector}"\n      ` : ''}operator           = "Contains"
      negation_condition = false
      match_values       = [${tokens.map((t) => `"${escapeHclString(t)}"`).join(', ')}]
    }`);
				cliCommands.push(
					`az network front-door waf-policy rule match-condition add \\`,
					`    --policy-name="waf-policy" \\`,
					`    --resource-group="myResourceGroup" \\`,
					`    --rule-name="VirtualPatch${sanitizedCat}Strict" \\`,
					`    --match-variable="${matchVariable}" \\`,
					selector ? `    --selector="${selector}" \\\n` : '',
					`    --operator="Contains" \\`,
					`    --values ${tokens.map((t) => `"${escapeDoubleQuotes(t)}"`).join(' ')}`
				);
			}

			// Only emit a rule when at least one match condition survived (a
			// blank/whitespace-only payload leaves matchConditions empty, and Azure
			// rejects a custom rule with no conditions or an empty matchValue set).
			if (matchConditions.length > 0) {
				const ruleObj = {
					name: `VirtualPatch_${sanitizedCat}_Strict`,
					priority: currentPriority,
					ruleType: 'MatchRule',
					action: azureAction,
					matchConditions,
				};

				const tfHcl = `custom_rules {
  name      = "VirtualPatch_${sanitizedCat}_Strict"
  priority  = ${currentPriority}
  rule_type = "MatchRule"
  action    = "${azureAction}"

${tfMatchBlocks.join('\n\n')}
}`;

				patches.push({
					vendor: 'azure',
					name: `Azure WAF: ${category} (Strict Hotfix)`,
					category,
					tier: 'strict',
					nativeRule: JSON.stringify(ruleObj, null, 2),
					terraformHcl: tfHcl,
					azureCliCommand: cliCommands.join('\n'),
					description: `Azure WAF custom rule matching ${tokens.length} verified ${category} bypass token(s)`,
				});
				currentPriority += 10;
			}
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const rawPattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);

			const ruleObj = {
				name: `VirtualPatch_${sanitizedCat}_Heuristic`,
				priority: currentPriority,
				ruleType: 'MatchRule',
				action: azureAction,
				matchConditions: [
					{
						matchVariable,
						selector,
						operator: 'RegEx',
						negateCondition: false,
						matchValue: [rawPattern],
					},
				],
			};

			const tfHcl = `custom_rules {
  name      = "VirtualPatch_${sanitizedCat}_Heuristic"
  priority  = ${currentPriority}
  rule_type = "MatchRule"
  action    = "${azureAction}"

  match_conditions {
    match_variable     = "${matchVariable}"
    ${selector ? `selector           = "${selector}"\n    ` : ''}operator           = "RegEx"
    negation_condition = false
    match_values       = ["${escapeHclString(rawPattern)}"]
  }
}`;

			const cliCommands = [
				`az network front-door waf-policy rule create \\`,
				`    --policy-name="waf-policy" \\`,
				`    --resource-group="myResourceGroup" \\`,
				`    --name="VirtualPatch${sanitizedCat}Heuristic" \\`,
				`    --priority=${currentPriority} \\`,
				`    --rule-type="MatchRule" \\`,
				`    --action="${azureAction}" \\`,
				`    --defer`,
				`az network front-door waf-policy rule match-condition add \\`,
				`    --policy-name="waf-policy" \\`,
				`    --resource-group="myResourceGroup" \\`,
				`    --rule-name="VirtualPatch${sanitizedCat}Heuristic" \\`,
				`    --match-variable="${matchVariable}" \\`,
				selector ? `    --selector="${selector}" \\\n` : '',
				`    --operator="RegEx" \\`,
				`    --values "${escapeDoubleQuotes(rawPattern)}"`,
			];

			patches.push({
				vendor: 'azure',
				name: `Azure WAF: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule: JSON.stringify(ruleObj, null, 2),
				terraformHcl: tfHcl,
				azureCliCommand: cliCommands.join('\n'),
				description: heuristic ? heuristic.description : `Azure WAF heuristic regex defense for ${category}`,
			});
			currentPriority += 10;
		}
	}

	return patches;
}
