import { describe, it, expect } from 'vitest';
import {
	generateVirtualPatches,
	filterBypasses,
	sanitizeStrictToken,
	escapeRegex,
	detectInspectionLocation,
	CATEGORY_HEURISTICS,
} from '../src/virtual-patch';
import { AuditResultItem } from '../src/reports/types';

describe('Virtual Patching & Rule Generator', () => {
	const mockBypasses: AuditResultItem[] = [
		{
			category: 'SQL Injection',
			payload: "' UNION SELECT 1, @@version-- -",
			method: 'GET',
			status: 200,
			responseTime: 45,
		},
		{
			category: 'SQL Injection',
			payload: "' OR '1'='1",
			method: 'GET',
			status: '200',
			responseTime: 30,
		},
		{
			category: 'XSS',
			payload: '<script>alert(1)</script>',
			method: 'GET',
			status: 200,
			responseTime: 50,
		},
		{
			category: 'Command Injection',
			payload: '; cat /etc/passwd',
			method: 'POST',
			status: 200,
			responseTime: 60,
		},
	];

	const mockBlocked: AuditResultItem[] = [
		{
			category: 'SQL Injection',
			payload: "' UNION SELECT null",
			method: 'GET',
			status: 403,
			responseTime: 20,
		},
		{
			category: 'XSS',
			payload: '<svg/onload=alert(1)>',
			method: 'GET',
			status: 'BLOCKED',
			responseTime: 25,
		},
	];

	describe('filterBypasses', () => {
		it('should only return items with status 200 or "200"', () => {
			const mixed = [...mockBypasses, ...mockBlocked];
			const filtered = filterBypasses(mixed);
			expect(filtered.length).toBe(4);
			expect(filtered.every((i) => i.status === 200 || i.status === '200')).toBe(true);
		});

		it('should return empty array if no bypasses exist', () => {
			expect(filterBypasses(mockBlocked)).toEqual([]);
		});
	});

	describe('Heuristics & Token Sanitization', () => {
		it('should escape regex special characters correctly', () => {
			expect(escapeRegex('test.com?id=1&name=a')).toBe('test\\.com\\?id=1&name=a');
			expect(escapeRegex('127.0.0.1')).toBe('127\\.0\\.0\\.1');
		});

		it('should sanitize strict tokens properly and consolidate sensitive extensions', () => {
			expect(sanitizeStrictToken("  ' OR '1'='1 \n")).toBe("' OR '1'='1");
			expect(sanitizeStrictToken('/dump.sql', 'Sensitive Files')).toBe('.sql');
			expect(sanitizeStrictToken('database.sql', 'Sensitive Files')).toBe('.sql');
			expect(sanitizeStrictToken('db.sql', 'Sensitive Files')).toBe('.sql');
			expect(sanitizeStrictToken('backup.tar.gz', 'Sensitive Files')).toBe('.tar.gz');
			expect(sanitizeStrictToken('backup.zip', 'Sensitive Files')).toBe('.zip');
			expect(sanitizeStrictToken('server.key', 'Sensitive Files')).toBe('.key');
			expect(sanitizeStrictToken('server.pem', 'Sensitive Files')).toBe('.pem');
			expect(sanitizeStrictToken('.git/config', 'Sensitive Files')).toBe('.git');
			expect(sanitizeStrictToken('.env', 'Sensitive Files')).toBe('.env');
			expect(sanitizeStrictToken('wp-config.php', 'Sensitive Files')).toBe('wp-config.php');
		});

		it('should detect inspection location correctly', () => {
			expect(detectInspectionLocation('User-Agent', 'GET', 'sqlmap')).toBe('header');
			expect(detectInspectionLocation('Path Traversal', 'GET', '../../etc/passwd')).toBe('uri');
			expect(detectInspectionLocation('SQL Injection', 'POST', "' or 1=1")).toBe('body');
			expect(detectInspectionLocation('SQL Injection', 'GET', "' or 1=1")).toBe('query');
		});

		it('should have heuristic definitions for core categories', () => {
			expect(CATEGORY_HEURISTICS['SQL Injection']).toBeDefined();
			expect(CATEGORY_HEURISTICS['XSS']).toBeDefined();
			expect(CATEGORY_HEURISTICS['Path Traversal']).toBeDefined();
			expect(CATEGORY_HEURISTICS['SSRF']).toBeDefined();
		});
	});

	describe('generateVirtualPatches (Orchestrator)', () => {
		it('should return empty report when no bypasses are provided', () => {
			const report = generateVirtualPatches(mockBlocked);
			expect(report.totalBypasses).toBe(0);
			expect(report.patches.length).toBe(0);
			expect(report.bundles.cloudflare.ruleCount).toBe(0);
		});

		it('should generate patches for all vendors by default', () => {
			const report = generateVirtualPatches(mockBypasses, { targetUrl: 'https://example.com/api/v1/search' });
			expect(report.totalBypasses).toBe(4);
			expect(report.patches.length).toBeGreaterThan(0);

			expect(report.bundles.cloudflare).toBeDefined();
			expect(report.bundles.aws).toBeDefined();
			expect(report.bundles.modsecurity).toBeDefined();
			expect(report.bundles.nginx).toBeDefined();

			expect(report.bundles.cloudflare.ruleCount).toBeGreaterThan(0);
			expect(report.bundles.aws.ruleCount).toBeGreaterThan(0);
			expect(report.bundles.modsecurity.ruleCount).toBeGreaterThan(0);
			expect(report.bundles.nginx.ruleCount).toBeGreaterThan(0);
		});

		it('should filter by specific vendor when requested', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'cloudflare' });
			expect(report.patches.every((p) => p.vendor === 'cloudflare')).toBe(true);
			expect(report.bundles.cloudflare).toBeDefined();
			expect(report.bundles.aws).toBeUndefined();
		});

		it('should support strict tier only', () => {
			const report = generateVirtualPatches(mockBypasses, { tier: 'strict', vendor: 'cloudflare' });
			expect(report.patches.every((p) => p.tier === 'strict')).toBe(true);
		});

		it('should support heuristic tier only', () => {
			const report = generateVirtualPatches(mockBypasses, { tier: 'heuristic', vendor: 'cloudflare' });
			expect(report.patches.every((p) => p.tier === 'heuristic')).toBe(true);
		});
	});

	describe('Cloudflare Ruleset Generator', () => {
		it('should generate valid Wirefilter expressions and Terraform HCL', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'cloudflare' });
			const strictSqli = report.patches.find((p) => p.category === 'SQL Injection' && p.tier === 'strict');
			expect(strictSqli).toBeDefined();
			expect(strictSqli?.nativeRule).toContain('lower(http.request.uri.query) contains');
			expect(strictSqli?.terraformHcl).toContain('resource "cloudflare_ruleset"');
			expect(strictSqli?.terraformHcl).toContain('phase       = "http_request_firewall_custom"');
			expect(strictSqli?.terraformHcl).toContain('action      = "block"');
		});

		it('should apply scopeToPath when enabled', () => {
			const report = generateVirtualPatches(mockBypasses, {
				vendor: 'cloudflare',
				scopeToPath: true,
				targetUrl: 'https://example.com/api/v1/search',
			});
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('(http.request.uri.path eq "/api/v1/search") and');
		});

		it('should support simulation / log mode', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'cloudflare', action: 'simulate' });
			const patch = report.patches[0];
			expect(patch.terraformHcl).toContain('action      = "log"');
		});
	});

	describe('AWS WAF v2 Generator', () => {
		it('should generate valid AWS WAF JSON Statements and Terraform HCL', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'aws' });
			const strictSqli = report.patches.find((p) => p.category === 'SQL Injection' && p.tier === 'strict');
			expect(strictSqli).toBeDefined();

			const parsedJson = JSON.parse(strictSqli!.nativeRule);
			expect(parsedJson.Name).toBe('WafChecker_Patch_SQLInjection_Strict');
			expect(parsedJson.Action).toEqual({ Block: {} });
			expect(parsedJson.Statement.OrStatement.Statements.length).toBe(2);

			expect(strictSqli?.terraformHcl).toContain('resource "aws_wafv2_rule_group"');
			expect(strictSqli?.terraformHcl).toContain('byte_match_statement');
		});

		it('should support simulation / Count mode in AWS WAF', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'aws', action: 'simulate' });
			const patch = report.patches[0];
			const parsedJson = JSON.parse(patch.nativeRule);
			expect(parsedJson.Action).toEqual({ Count: {} });
			expect(patch.terraformHcl).toContain('count {}');
		});
	});

	describe('ModSecurity Generator', () => {
		it('should generate valid SecRule directives with unique IDs', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'modsecurity', ruleIdPrefix: 950000 });
			const strictPatch = report.patches.find((p) => p.tier === 'strict');
			expect(strictPatch).toBeDefined();
			expect(strictPatch?.nativeRule).toContain('SecRule ARGS|REQUEST_URI "@contains');
			expect(strictPatch?.nativeRule).toContain('id:950000');
			expect(strictPatch?.nativeRule).toContain('deny,status:403');
		});

		it('should support simulation mode in ModSecurity', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'modsecurity', action: 'simulate' });
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('pass,log,auditlog');
			expect(patch.nativeRule).toContain('[SIMULATION]');
		});

		it('should generate chained rules when scopeToPath is enabled', () => {
			const report = generateVirtualPatches(mockBypasses, {
				vendor: 'modsecurity',
				scopeToPath: true,
				targetUrl: 'https://example.com/api/login',
			});
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('SecRule REQUEST_URI "@beginsWith /api/login"');
			expect(patch.nativeRule).toContain('chain');
		});
	});

	describe('NGINX Generator', () => {
		it('should generate valid nginx configuration blocks and map snippets', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'nginx' });
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('if ($query_string ~*');
			expect(patch.nativeRule).toContain('return 403;');
			expect(patch.nativeRule).toContain('High-Performance Alternative');
			expect(patch.nativeRule).toContain('map $query_string');
		});

		it('should support simulation mode in NGINX', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'nginx', action: 'simulate' });
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('add_header X-WAF-Simulation-Triggered "1"');
		});

		it('should wrap in location block when scopeToPath is enabled', () => {
			const report = generateVirtualPatches(mockBypasses, {
				vendor: 'nginx',
				scopeToPath: true,
				targetUrl: 'https://example.com/v1/auth',
			});
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('location /v1/auth {');
		});

		it('should escape double quotes in NGINX payloads and regexes', () => {
			const bypassWithQuotes: AuditResultItem[] = [
				{
					category: 'SQL Injection',
					method: 'GET',
					payload: 'admin" OR "1"="1',
					status: 200,
					responseTime: 45,
				},
			];
			const report = generateVirtualPatches(bypassWithQuotes, { vendor: 'nginx', tier: 'strict' });
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('\\"1\\"');
			expect(patch.nativeRule).not.toMatch(/~[*] ".*[^\\]".*"/);
		});
	});

	describe('Engine Safety & Escaping', () => {
		it('should escape HCL interpolation syntax for SSTI in Terraform', () => {
			const sstiBypasses: AuditResultItem[] = [
				{
					category: 'SSTI',
					method: 'GET',
					payload: '${7*7}',
					status: 200,
					responseTime: 30,
				},
			];
			const report = generateVirtualPatches(sstiBypasses, { vendor: 'aws', tier: 'heuristic' });
			const patch = report.patches[0];
			expect(patch.terraformHcl).toContain('$${');
			expect(patch.terraformHcl).not.toContain('"${.*?}"');
		});

		it('should generate or_statement in AWS Terraform for multiple strict tokens', () => {
			const multiBypasses: AuditResultItem[] = [
				{ category: 'XSS', method: 'GET', payload: '<script>1</script>', status: 200, responseTime: 20 },
				{ category: 'XSS', method: 'GET', payload: '<script>2</script>', status: 200, responseTime: 22 },
			];
			const report = generateVirtualPatches(multiBypasses, { vendor: 'aws', tier: 'strict' });
			const patch = report.patches[0];
			expect(patch.terraformHcl).toContain('or_statement');
			expect(patch.terraformHcl).toContain('<script>1</script>');
			expect(patch.terraformHcl).toContain('<script>2</script>');
		});

		it('should generate single_header in AWS Terraform for header bypasses', () => {
			const headerBypasses: AuditResultItem[] = [
				{ category: 'User-Agent', method: 'GET', payload: 'sqlmap/1.0', status: 200, responseTime: 20 },
			];
			const report = generateVirtualPatches(headerBypasses, { vendor: 'aws', tier: 'strict' });
			const patch = report.patches[0];
			expect(patch.terraformHcl).toContain('single_header');
			expect(patch.terraformHcl).toContain('name = "user-agent"');
		});

		it('should start ModSecurity rule IDs at 1000000 by default to avoid CRS conflicts', () => {
			const report = generateVirtualPatches(mockBypasses, { vendor: 'modsecurity' });
			const patch = report.patches[0];
			expect(patch.nativeRule).toContain('id:1000000');
		});
	});

	describe('WAF Misses & 404 Remediation', () => {
		const mixedResults: AuditResultItem[] = [
			{ category: 'SQL Injection', method: 'GET', payload: "' OR 1=1--", status: 200, responseTime: 20 },
			{ category: 'Sensitive Files', method: 'GET', payload: '/.git/config', status: 404, responseTime: 25 },
			{ category: 'Path Traversal', method: 'GET', payload: '/../../etc/passwd', status: 404, responseTime: 28 },
			{ category: 'XXE', method: 'POST', payload: '<!ENTITY xxe ...>', status: 500, responseTime: 40 },
			{ category: 'XSS', method: 'GET', payload: '<script>alert(1)</script>', status: 403, responseTime: 15 },
		];

		it('filterBypasses should return only 200 OK by default', () => {
			const filtered = filterBypasses(mixedResults);
			expect(filtered.length).toBe(1);
			expect(filtered[0].status).toBe(200);
		});

		it('filterBypasses should return 200, 404, and 500 when includeMisses is true', () => {
			const filtered = filterBypasses(mixedResults, { includeMisses: true });
			expect(filtered.length).toBe(4);
			const statuses = filtered.map((f) => f.status);
			expect(statuses).toContain(200);
			expect(statuses).toContain(404);
			expect(statuses).toContain(500);
			expect(statuses).not.toContain(403);
		});

		it('filterBypasses should filter by explicit statusCodes', () => {
			const filtered = filterBypasses(mixedResults, { statusCodes: [404] });
			expect(filtered.length).toBe(2);
			expect(filtered.every((f) => f.status === 404)).toBe(true);
		});

		it('generateVirtualPatches should generate perimeter rules for /.git/config when includeMisses is true', () => {
			const report = generateVirtualPatches(mixedResults, {
				vendor: 'cloudflare',
				includeMisses: true,
			});
			expect(report.totalBypasses).toBe(4);
			const gitPatch = report.patches.find((p) => p.category === 'Sensitive Files');
			expect(gitPatch).toBeDefined();
			expect(gitPatch?.nativeRule).toContain('.git');
		});
	});

	describe('Cloudflare Wirefilter & Extension Consolidation', () => {
		it('should consolidate dump.sql and db.sql into a single .sql match in Cloudflare rules', () => {
			const sqlFiles: AuditResultItem[] = [
				{ category: 'Sensitive Files', method: 'GET', payload: '/dump.sql', status: 200, responseTime: 20 },
				{ category: 'Sensitive Files', method: 'GET', payload: '/db.sql', status: 200, responseTime: 20 },
				{ category: 'Sensitive Files', method: 'GET', payload: '/database.sql', status: 200, responseTime: 20 },
			];

			const report = generateVirtualPatches(sqlFiles, { vendor: 'cloudflare', tier: 'strict' });
			const cfBundle = report.bundles.cloudflare;
			expect(cfBundle.native).toContain('contains ".sql"');
			expect(cfBundle.native).not.toContain('contains "dump.sql"');
			expect(cfBundle.native).not.toContain('contains "db.sql"');
		});

		it('should join multiple Cloudflare rules with boolean "or" in native bundle for valid Wirefilter syntax', () => {
			const mixed: AuditResultItem[] = [
				{ category: 'Sensitive Files', method: 'GET', payload: '/dump.sql', status: 200, responseTime: 20 },
			];

			const report = generateVirtualPatches(mixed, { vendor: 'cloudflare', tier: 'both' });
			const cfBundle = report.bundles.cloudflare;
			expect(cfBundle.ruleCount).toBe(2);
			expect(cfBundle.native).toContain(' or\n\n');
			expect(cfBundle.native).toMatch(/\)\s+or\s+\(/);
		});
	});
});
