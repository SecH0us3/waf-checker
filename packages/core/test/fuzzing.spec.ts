import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { isValidTargetUrl } from '../src/utils/security';
import { PayloadEncoder, WAFBypasses } from '../src/encoding';
import { substitutePayload, processCustomHeaders, randomUppercase } from '../src/utils/payload-utils';
import { generateSARIFReport } from '../src/reports/sarif';
import { calculateAuditStats, generateJSONReport } from '../src/reports';

describe('Property-Based & Fuzz Testing (fast-check)', () => {
	describe('SSRF Protection (isValidTargetUrl)', () => {
		it('should never throw an unhandled exception for any arbitrary string', () => {
			fc.assert(
				fc.property(fc.string(), (input) => {
					expect(() => isValidTargetUrl(input)).not.toThrow();
					const result = isValidTargetUrl(input);
					expect(typeof result).toBe('boolean');
				}),
				{ numRuns: 500 }
			);
		});

		it('should always reject private IPv4 ranges regardless of path, port, or params', () => {
			const privateIps = fc.oneof(
				fc.tuple(fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 255 })).map(([b, c, d]) => `10.${b}.${c}.${d}`),
				fc.tuple(fc.integer({ min: 16, max: 31 }), fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 255 })).map(([b, c, d]) => `172.${b}.${c}.${d}`),
				fc.tuple(fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 255 })).map(([c, d]) => `192.168.${c}.${d}`),
				fc.tuple(fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 255 })).map(([c, d]) => `127.${c}.${d}.1`),
				fc.tuple(fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 255 })).map(([c, d]) => `169.254.${c}.${d}`)
			);

			const paths = fc.stringMatching(/^[a-z0-9/_-]*$/);
			const ports = fc.option(fc.integer({ min: 1, max: 65535 }));
			const schemes = fc.constantFrom('http', 'https');

			fc.assert(
				fc.property(schemes, privateIps, ports, paths, (scheme, ip, port, path) => {
					const portPart = port ? `:${port}` : '';
					const url = `${scheme}://${ip}${portPart}/${path}`;
					expect(isValidTargetUrl(url)).toBe(false);
				}),
				{ numRuns: 300 }
			);
		});

		it('should always accept valid public HTTPS URLs', () => {
			const validDomains = fc.constantFrom('example.com', 'google.com', 'github.com', 'cloudflare.com', 'mozilla.org');
			const paths = fc.stringMatching(/^[a-z0-9/_-]*$/);
			const schemes = fc.constantFrom('http', 'https');

			fc.assert(
				fc.property(schemes, validDomains, paths, (scheme, domain, path) => {
					const url = `${scheme}://${domain}/${path}`;
					expect(isValidTargetUrl(url)).toBe(true);
				}),
				{ numRuns: 200 }
			);
		});
	});

	describe('Payload Encoders & WAF Bypasses', () => {
		it('should never throw when generating bypass variations for arbitrary payload strings', () => {
			fc.assert(
				fc.property(fc.string(), (payload) => {
					expect(() => PayloadEncoder.generateBypassVariations(payload)).not.toThrow();
					const res = PayloadEncoder.generateBypassVariations(payload);
					expect(Array.isArray(res)).toBe(true);
					expect(res.length).toBeGreaterThan(0);
					expect(res.every((v) => typeof v === 'string')).toBe(true);
				}),
				{ numRuns: 300 }
			);
		});

		it('should never crash any WAF-specific bypass generator on arbitrary payload inputs', () => {
			const wafBypassFns = [
				WAFBypasses.cloudflareBypass,
				WAFBypasses.awsWafBypass,
				WAFBypasses.impervaBypass,
				WAFBypasses.modSecurityBypass,
				WAFBypasses.akamaiBypass,
				WAFBypasses.azureBypass,
				WAFBypasses.f5BigIpBypass,
				WAFBypasses.googleCloudArmorBypass,
				WAFBypasses.panosBypass,
				WAFBypasses.sophosBypass,
				WAFBypasses.signalSciencesBypass,
				WAFBypasses.nginxAppProtectBypass,
				WAFBypasses.haproxyBypass,
				WAFBypasses.ibmDataPowerBypass,
				WAFBypasses.reblazeBypass,
				WAFBypasses.dotDefenderBypass,
			];

			fc.assert(
				fc.property(fc.string(), (payload) => {
					for (const bypassFn of wafBypassFns) {
						expect(() => bypassFn(payload)).not.toThrow();
						const variations = bypassFn(payload);
						expect(Array.isArray(variations)).toBe(true);
						expect(variations.length).toBeGreaterThan(0);
					}
				}),
				{ numRuns: 100 }
			);
		});

		it('should safely uppercase random characters in randomUppercase without length mutation', () => {
			fc.assert(
				fc.property(fc.string(), (str) => {
					const result = randomUppercase(str);
					expect(result.length).toBe(str.length);
					expect(result.toLowerCase()).toBe(str.toLowerCase());
				}),
				{ numRuns: 200 }
			);
		});
	});

	describe('Payload Utilities & Templates', () => {
		it('should recursively substitute payloads in arbitrary nested JSON structures without crashing', () => {
			const jsonArbitrary = fc.jsonValue();

			fc.assert(
				fc.property(jsonArbitrary, fc.string(), (jsonObj, payload) => {
					expect(() => substitutePayload(jsonObj, payload)).not.toThrow();
				}),
				{ numRuns: 200 }
			);
		});

		it('should parse arbitrary custom header strings safely', () => {
			fc.assert(
				fc.property(fc.string(), fc.string(), (rawHeaders, payload) => {
					expect(() => processCustomHeaders(rawHeaders, payload)).not.toThrow();
					const headers = processCustomHeaders(rawHeaders, payload);
					expect(typeof headers).toBe('object');
				}),
				{ numRuns: 200 }
			);
		});
	});

	describe('Reports & Statistics Invariants', () => {
		it('should calculate stats without NaN or infinite values for any combination of results', () => {
			const checkResultArbitrary = fc.array(
				fc.record({
					category: fc.string(),
					payload: fc.string(),
					method: fc.constantFrom('GET', 'POST', 'PUT', 'DELETE'),
					status: fc.oneof(fc.integer({ min: 100, max: 599 }), fc.constant('ERR')),
					responseTime: fc.integer({ min: 0, max: 10000 }),
					is_redirect: fc.boolean(),
				}),
				{ minLength: 0, maxLength: 50 }
			);

			fc.assert(
				fc.property(checkResultArbitrary, (results) => {
					const stats = calculateAuditStats(results as any);
					expect(Number.isNaN(stats.protectionScore)).toBe(false);
					expect(Number.isFinite(stats.protectionScore)).toBe(true);
					expect(stats.protectionScore).toBeGreaterThanOrEqual(0);
					expect(stats.protectionScore).toBeLessThanOrEqual(100);
					expect(stats.total).toBe(results.length);
					expect(stats.blocked + stats.bypassed + stats.errors + stats.other).toBe(results.length);
				}),
				{ numRuns: 300 }
			);
		});

		it('should generate valid SARIF and JSON reports for arbitrary check results', () => {
			const checkResultArbitrary = fc.array(
				fc.record({
					category: fc.string(),
					payload: fc.string(),
					method: fc.constantFrom('GET', 'POST'),
					status: fc.oneof(fc.integer({ min: 200, max: 500 }), fc.constant('ERR')),
					responseTime: fc.integer({ min: 0, max: 5000 }),
					is_redirect: fc.boolean(),
				}),
				{ minLength: 1, maxLength: 20 }
			);

			fc.assert(
				fc.property(checkResultArbitrary, (results) => {
					const sarifJson = generateSARIFReport(results as any, 'https://example.com');
					expect(() => JSON.parse(sarifJson)).not.toThrow();
					const parsedSarif = JSON.parse(sarifJson);
					expect(parsedSarif.version).toBe('2.1.0');
					expect(Array.isArray(parsedSarif.runs)).toBe(true);
					expect(parsedSarif.runs[0].tool.driver.name).toBe('WAF-Checker');

					const jsonReport = generateJSONReport(results as any, 'https://example.com');
					expect(() => JSON.parse(jsonReport)).not.toThrow();
				}),
				{ numRuns: 100 }
			);
		});
	});
});
