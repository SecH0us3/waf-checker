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

function getAwsFieldToMatch(location: 'query' | 'body' | 'header' | 'uri', category: string): Record<string, any> {
	switch (location) {
		case 'header':
			if (category === 'User-Agent') return { SingleHeader: { Name: 'user-agent' } };
			if (category.includes('JWT')) return { SingleHeader: { Name: 'authorization' } };
			return { SingleHeader: { Name: 'x-forwarded-for' } };
		case 'uri':
			return { UriPath: {} };
		case 'body':
			return { Body: {} };
		case 'query':
		default:
			return { AllQueryArguments: {} };
	}
}

export function generateAwsPatches(
	bypasses: AuditResultItem[],
	options: VirtualPatchOptions = {}
): GeneratedPatch[] {
	const patches: GeneratedPatch[] = [];
	const actionKey = options.action === 'simulate' ? 'Count' : 'Block';
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

	let priority = 10;
	for (const [groupKey, items] of Object.entries(groups)) {
		const category = items[0].category;
		const location = detectInspectionLocation(category, items[0].method, items[0].payload);
		const fieldToMatch = getAwsFieldToMatch(location, category);
		const sanitizedCat = category.replace(/[^a-zA-Z0-9]/g, '');

		// 1. Strict Hotfix Tier
		if (options.tier !== 'heuristic') {
			const tokens = [...new Set(items.map((it) => sanitizeStrictToken(it.payload)))];
			const byteStatements = tokens.map((tok) => ({
				ByteMatchStatement: {
					SearchString: tok,
					FieldToMatch: fieldToMatch,
					TextTransformations: [
						{ Priority: 0, Type: 'URL_DECODE' },
						{ Priority: 1, Type: 'LOWERCASE' },
					],
					PositionalConstraint: 'CONTAINS',
				},
			}));

			let mainStatement: any;
			if (byteStatements.length === 1) {
				mainStatement = byteStatements[0];
			} else {
				mainStatement = { OrStatement: { Statements: byteStatements } };
			}

			if (urlPath) {
				mainStatement = {
					AndStatement: {
						Statements: [
							{
								ByteMatchStatement: {
									SearchString: urlPath,
									FieldToMatch: { UriPath: {} },
									TextTransformations: [{ Priority: 0, Type: 'NONE' }],
									PositionalConstraint: 'EXACTLY',
								},
							},
							mainStatement,
						],
					},
				};
			}

			const ruleName = `WafChecker_Patch_${sanitizedCat}_Strict`;
			const nativeRuleObj = {
				Name: ruleName,
				Priority: priority,
				Action: { [actionKey]: {} },
				VisibilityConfig: {
					SampledRequestsEnabled: true,
					CloudWatchMetricsEnabled: true,
					MetricName: ruleName,
				},
				Statement: mainStatement,
			};

			const nativeRuleJson = JSON.stringify(nativeRuleObj, null, 2);

			const terraformSnippet = `resource "aws_wafv2_rule_group" "virtual_patch_${sanitizedCat.toLowerCase()}_strict" {
  name     = "${ruleName}"
  scope    = "REGIONAL"
  capacity = 25

  rule {
    name     = "${ruleName}"
    priority = ${priority}

    action {
      ${actionKey.toLowerCase()} {}
    }

    statement {
      byte_match_statement {
        positional_constraint = "CONTAINS"
        search_string         = "${tokens[0].replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"

        field_to_match {
          ${location === 'uri' ? 'uri_path {}' : location === 'body' ? 'body {}' : 'all_query_arguments {}'}
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 1
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${ruleName}"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${ruleName}_group"
    sampled_requests_enabled   = true
  }
}`;

			patches.push({
				vendor: 'aws',
				name: `AWS WAF: ${category} (Strict Hotfix)`,
				category,
				tier: 'strict',
				nativeRule: nativeRuleJson,
				terraformHcl: terraformSnippet,
				description: `AWS WAF v2 ByteMatch rule matching ${tokens.length} verified ${category} bypass token(s)`,
			});
		}

		// 2. Heuristic Pattern Tier
		if (options.tier !== 'strict') {
			const heuristic = CATEGORY_HEURISTICS[category];
			const pattern = heuristic ? heuristic.pattern : escapeRegex(items[0].payload);
			const ruleName = `WafChecker_Patch_${sanitizedCat}_Heuristic`;

			const nativeRuleObj = {
				Name: ruleName,
				Priority: priority + 1,
				Action: { [actionKey]: {} },
				VisibilityConfig: {
					SampledRequestsEnabled: true,
					CloudWatchMetricsEnabled: true,
					MetricName: ruleName,
				},
				Statement: {
					RegexPatternSetReferenceStatement: {
						ARN: `arn:aws:wafv2:region:account:regional/regexpatternset/${ruleName}/id`,
						FieldToMatch: fieldToMatch,
						TextTransformations: [
							{ Priority: 0, Type: 'URL_DECODE' },
							{ Priority: 1, Type: 'LOWERCASE' },
						],
					},
				},
			};

			const nativeRuleJson = JSON.stringify(nativeRuleObj, null, 2);

			const terraformSnippet = `resource "aws_wafv2_regex_pattern_set" "pattern_${sanitizedCat.toLowerCase()}" {
  name  = "${ruleName}_Patterns"
  scope = "REGIONAL"

  regular_expression {
    regex_string = "${pattern.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"
  }
}

resource "aws_wafv2_rule_group" "virtual_patch_${sanitizedCat.toLowerCase()}_heuristic" {
  name     = "${ruleName}"
  scope    = "REGIONAL"
  capacity = 35

  rule {
    name     = "${ruleName}"
    priority = ${priority + 1}

    action {
      ${actionKey.toLowerCase()} {}
    }

    statement {
      regex_pattern_set_reference_statement {
        arn = aws_wafv2_regex_pattern_set.pattern_${sanitizedCat.toLowerCase()}.arn

        field_to_match {
          ${location === 'uri' ? 'uri_path {}' : location === 'body' ? 'body {}' : 'all_query_arguments {}'}
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 1
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${ruleName}"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${ruleName}_group"
    sampled_requests_enabled   = true
  }
}`;

			patches.push({
				vendor: 'aws',
				name: `AWS WAF: ${category} (Heuristic Pattern)`,
				category,
				tier: 'heuristic',
				nativeRule: nativeRuleJson,
				terraformHcl: terraformSnippet,
				description: heuristic ? heuristic.description : `AWS WAF RegexPatternSet defense for ${category}`,
			});
		}

		priority += 2;
	}

	return patches;
}
