#!/usr/bin/env node
/**
 * Validate the AWS WAFv2 rules produced by the virtual-patch generator with the
 * official AWS linter (cfn-lint), fully offline and without AWS credentials.
 *
 * The generator emits rules in the `aws wafv2` CLI/API dialect. CloudFormation
 * uses the same Statement shapes with one casing difference: the regex-pattern-set
 * reference is `ARN` in the API but `Arn` in CloudFormation. This script wraps the
 * generated rules in an `AWS::WAFv2::RuleGroup` template and applies that single
 * dialect adjustment so cfn-lint can validate the structure.
 *
 * Usage:
 *   npx vite-node scripts/validate-aws-cfn.mjs            # emit template, run cfn-lint if present
 *   npx vite-node scripts/validate-aws-cfn.mjs --print    # only print the template to stdout
 *
 * Install cfn-lint (in a venv to avoid clobbering system PyYAML):
 *   python3 -m venv .cfnenv && ./.cfnenv/bin/pip install cfn-lint
 *   PATH="$PWD/.cfnenv/bin:$PATH" npx vite-node scripts/validate-aws-cfn.mjs
 */
import { writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateVirtualPatches } from '../packages/core/src/virtual-patch/index.ts';

// Broad fixture: one representative, deliberately mixed-case bypass per
// inspection location (query / body / header / uri).
const fixture = [
	{ category: 'SQL Injection', method: 'GET', payload: "1' UNION SELECT NULL-- -" },
	{ category: 'XSS', method: 'GET', payload: '<IMG SRC=x onerror=alert(1)>' },
	{ category: 'XXE', method: 'POST', payload: '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>' },
	{ category: 'GraphQL Injection', method: 'POST', payload: '{__schema{types{name}}}' },
	{ category: 'Command Injection', method: 'POST', payload: '; CAT /etc/passwd' },
	{ category: 'Path Traversal', method: 'GET', payload: '../../../../etc/passwd' },
	{ category: 'Sensitive Files', method: 'GET', payload: '/backup/db.SQL' },
	{ category: 'User-Agent', method: 'GET', payload: 'SQLMap/1.7' },
].map((b) => ({ ...b, status: 200, responseTime: 10 }));

const report = generateVirtualPatches(fixture, { vendor: 'aws' });

const resources = {};
report.patches.forEach((patch, i) => {
	// API dialect -> CloudFormation dialect: the only difference is ARN -> Arn.
	const rule = JSON.parse(patch.nativeRule.replaceAll('"ARN"', '"Arn"'));
	resources[`RuleGroup${i}`] = {
		Type: 'AWS::WAFv2::RuleGroup',
		Properties: {
			Name: `wafchecker-${i}`,
			Scope: 'REGIONAL',
			Capacity: 50,
			Rules: [rule],
			VisibilityConfig: {
				SampledRequestsEnabled: true,
				CloudWatchMetricsEnabled: true,
				MetricName: `wafchecker-group-${i}`,
			},
		},
	};
});

const template = JSON.stringify(
	{ AWSTemplateFormatVersion: '2010-09-09', Resources: resources },
	null,
	2
);

if (process.argv.includes('--print')) {
	console.log(template);
	process.exit(0);
}

const templatePath = join(tmpdir(), `wafchecker-aws-cfn-${process.pid}.json`);
writeFileSync(templatePath, template);
console.log(`Wrote ${report.patches.length} AWS rule group(s) to ${templatePath}`);

const cfn = spawnSync('cfn-lint', [templatePath], { encoding: 'utf8' });
if (cfn.error && cfn.error.code === 'ENOENT') {
	console.log('\ncfn-lint not found on PATH. Install it and re-run, or lint manually:');
	console.log(`  cfn-lint ${templatePath}`);
	process.exit(0);
}
if (cfn.stdout) process.stdout.write(cfn.stdout);
if (cfn.stderr) process.stderr.write(cfn.stderr);
if (cfn.status === 0) {
	console.log('\ncfn-lint: OK — all generated AWS WAFv2 rules are structurally valid.');
}
process.exit(cfn.status ?? 0);
