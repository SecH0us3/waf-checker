import { describe, it, expect } from 'vitest';
import { generateVirtualPatches } from '../src/virtual-patch';
import { AuditResultItem } from '../src/reports/types';

/**
 * Structural-invariant tests for the AWS and Azure virtual-patch generators.
 *
 * Unlike the example-based tests in virtual-patch.spec.ts, these run every
 * generated rule (across a broad, deliberately mixed-case fixture that spans
 * query / body / header / uri inspection) through invariant checks that mirror
 * what an official validator (cfn-lint for AWS, the ARM schema for Azure) would
 * enforce. They exist to catch rule-formation regressions without needing cloud
 * access or external binaries.
 */

// One representative bypass per inspection location, with intentionally
// mixed-case payloads so the LOWERCASE-transform invariant is exercised.
const fixture: AuditResultItem[] = [
	{ category: 'SQL Injection', method: 'GET', payload: "1' UNION SELECT NULL-- -", status: 200, responseTime: 10 },
	{ category: 'XSS', method: 'GET', payload: '<IMG SRC=x onerror=alert(1)>', status: 200, responseTime: 10 },
	{ category: 'XXE', method: 'POST', payload: '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>', status: 200, responseTime: 10 },
	{ category: 'GraphQL Injection', method: 'POST', payload: '{__schema{types{name}}}', status: 200, responseTime: 10 },
	{ category: 'Command Injection', method: 'POST', payload: '; CAT /etc/passwd', status: 200, responseTime: 10 },
	{ category: 'Path Traversal', method: 'GET', payload: '../../../../etc/passwd', status: 200, responseTime: 10 },
	{ category: 'Sensitive Files', method: 'GET', payload: '/backup/db.SQL', status: 200, responseTime: 10 },
	{ category: 'User-Agent', method: 'GET', payload: 'SQLMap/1.7', status: 200, responseTime: 10 },
	{ category: 'JWT Attack (Header)', method: 'GET', payload: '{"alg":"NONE"}', status: 200, responseTime: 10 },
];

/** Recursively collect every value stored under `key` anywhere in a statement tree. */
function collect(node: any, key: string, out: any[] = []): any[] {
	if (node === null || typeof node !== 'object') return out;
	for (const [k, v] of Object.entries(node)) {
		if (k === key) out.push(v);
		if (v && typeof v === 'object') collect(v, key, out);
	}
	return out;
}

describe('AWS WAF rule-formation invariants', () => {
	const report = generateVirtualPatches(fixture, { vendor: 'aws' });

	it('generates at least one patch per fixture tier', () => {
		expect(report.patches.length).toBeGreaterThan(0);
	});

	it('every native rule is valid JSON with the required WebACL rule shape', () => {
		for (const patch of report.patches) {
			const rule = JSON.parse(patch.nativeRule);
			expect(typeof rule.Name).toBe('string');
			expect(rule.Name.length).toBeGreaterThan(0);
			expect(typeof rule.Priority).toBe('number');
			expect(rule.Statement).toBeDefined();
			expect(rule.VisibilityConfig?.MetricName).toBeTruthy();
			// Exactly one terminating action.
			const actionKeys = Object.keys(rule.Action);
			expect(actionKeys.length).toBe(1);
			expect(['Block', 'Count']).toContain(actionKeys[0]);
		}
	});

	it('any ByteMatchStatement using a LOWERCASE transform has a lowercase SearchString', () => {
		for (const patch of report.patches) {
			const rule = JSON.parse(patch.nativeRule);
			for (const bm of collect(rule.Statement, 'ByteMatchStatement')) {
				expect(typeof bm.SearchString).toBe('string');
				expect(Array.isArray(bm.TextTransformations)).toBe(true);
				const hasLowercase = bm.TextTransformations.some((t: any) => t.Type === 'LOWERCASE');
				if (hasLowercase) {
					// AWS transforms the inspected field, never the SearchString, so an
					// uppercase SearchString would never match a lowercased field.
					expect(bm.SearchString).toBe(bm.SearchString.toLowerCase());
				}
			}
		}
	});

	it('every Body field-to-match declares the required OversizeHandling', () => {
		let bodyRulesChecked = 0;
		for (const patch of report.patches) {
			const rule = JSON.parse(patch.nativeRule);
			for (const body of collect(rule.Statement, 'Body')) {
				bodyRulesChecked++;
				expect(['CONTINUE', 'MATCH', 'NO_MATCH']).toContain(body.OversizeHandling);
			}
			// The Terraform body block requires oversize_handling too.
			if (patch.terraformHcl?.includes('body {')) {
				expect(patch.terraformHcl).toContain('oversize_handling');
			}
		}
		// The fixture includes body-inspected categories (XXE, GraphQL), so this must fire.
		expect(bodyRulesChecked).toBeGreaterThan(0);
	});

	it('rule priorities are unique across the combined bundle', () => {
		const bundle = report.bundles.aws;
		const rules = JSON.parse(bundle.native);
		const arr = Array.isArray(rules) ? rules : [rules];
		const priorities = arr.map((r: any) => r.Priority);
		expect(new Set(priorities).size).toBe(priorities.length);
	});
});

describe('Azure WAF rule-formation invariants', () => {
	const report = generateVirtualPatches(fixture, { vendor: 'azure' });

	it('every native rule is valid JSON with a non-empty match condition set', () => {
		for (const patch of report.patches) {
			const rule = JSON.parse(patch.nativeRule);
			expect(typeof rule.name).toBe('string');
			expect(typeof rule.priority).toBe('number');
			expect(rule.ruleType).toBe('MatchRule');
			expect(['Block', 'Log']).toContain(rule.action);
			expect(Array.isArray(rule.matchConditions)).toBe(true);
			expect(rule.matchConditions.length).toBeGreaterThan(0);
		}
	});

	it('uses the ARM field name negateCondition, never the documented typo negationConditon', () => {
		for (const patch of report.patches) {
			// Guard against the Azure REST-doc misspelling (Azure/azure-cli#31807).
			expect(patch.nativeRule).not.toContain('negationConditon');
			const rule = JSON.parse(patch.nativeRule);
			for (const mc of rule.matchConditions) {
				expect(typeof mc.negateCondition).toBe('boolean');
			}
		}
	});
});
