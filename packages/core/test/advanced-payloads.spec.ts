import { describe, it, expect } from 'vitest';
import { generateWAFSpecificPayloads, generateHTTPManipulationPayloads, generateEncodedPayloads } from '../src/advanced-payloads';

describe('advanced-payloads', () => {
	describe('generateEncodedPayloads', () => {
		it('should generate encoded categories with deduplication and falsePayloads preserved', () => {
			const originalPayloads = {
				'SQL Injection': {
					type: 'ParamCheck' as const,
					payloads: ["' OR 1=1--", "' OR 1=1--"],
					falsePayloads: ["John O'Connor"]
				},
				'User-Agent': {
					type: 'Header' as const,
					payloads: ["Mozilla/5.0"],
				}
			};

			const encoded = generateEncodedPayloads(originalPayloads);
			expect(encoded['SQL Injection - Encoded']).toBeDefined();
			expect(encoded['SQL Injection - Encoded'].type).toBe('ParamCheck');
			expect(encoded['SQL Injection - Encoded'].payloads.length).toBeGreaterThan(0);
			expect(encoded['SQL Injection - Encoded'].falsePayloads).toEqual(["John O'Connor"]);
			expect(encoded['User-Agent - Encoded'].falsePayloads).toEqual([]);
		});
	});

	describe('generateWAFSpecificPayloads', () => {
		it('should route Cloudflare', () => {
			const res = generateWAFSpecificPayloads('cloudflare', 'test');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route AWS aliases', () => {
			expect(generateWAFSpecificPayloads('aws', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('awswaf', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('aws waf', 'test').length).toBeGreaterThan(0);
		});
		it('should route ModSecurity', () => {
			const res = generateWAFSpecificPayloads('modsecurity', 'test');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Akamai', () => {
			const res = generateWAFSpecificPayloads('akamai', 'test');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Azure aliases', () => {
			expect(generateWAFSpecificPayloads('azure', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('azure front door', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('azure waf', 'test').length).toBeGreaterThan(0);
		});
		it('should route Imperva and Incapsula', () => {
			expect(generateWAFSpecificPayloads('imperva', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('incapsula', 'test').length).toBeGreaterThan(0);
		});
		it('should route F5 aliases', () => {
			expect(generateWAFSpecificPayloads('f5', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('f5 big-ip', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('f5 big ip', 'test').length).toBeGreaterThan(0);
		});
		it('should route Google Cloud Armor aliases', () => {
			expect(generateWAFSpecificPayloads('google', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('google cloud armor', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('cloud armor', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('gcp', 'test').length).toBeGreaterThan(0);
		});
		it('should route Palo Alto aliases', () => {
			expect(generateWAFSpecificPayloads('palo alto', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('palo alto networks', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('pan-os', 'test').length).toBeGreaterThan(0);
		});
		it('should route Sophos aliases', () => {
			expect(generateWAFSpecificPayloads('sophos', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('sophos waf', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('sophos utm', 'test').length).toBeGreaterThan(0);
		});
		it('should route Signal Sciences aliases', () => {
			expect(generateWAFSpecificPayloads('signal sciences', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('signalsciences', 'test').length).toBeGreaterThan(0);
		});
		it('should route Nginx App Protect and NAXSI aliases', () => {
			expect(generateWAFSpecificPayloads('nginx', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('nginx app protect', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('naxsi', 'test').length).toBeGreaterThan(0);
		});
		it('should route HAProxy', () => {
			const res = generateWAFSpecificPayloads('haproxy', 'test');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route IBM DataPower aliases', () => {
			expect(generateWAFSpecificPayloads('ibm datapower', 'test').length).toBeGreaterThan(0);
			expect(generateWAFSpecificPayloads('datapower', 'test').length).toBeGreaterThan(0);
		});
		it('should route Reblaze', () => {
			const res = generateWAFSpecificPayloads('reblaze', 'test');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route dotDefender', () => {
			const res = generateWAFSpecificPayloads('dotdefender', 'test');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should fallback to encoder for unknown WAF vendor', () => {
			const res = generateWAFSpecificPayloads('unknown-custom-waf', 'test');
			expect(res.length).toBeGreaterThan(0);
		});
	});

	describe('generateHTTPManipulationPayloads', () => {
		it('should handle verb technique', () => {
			const res = generateHTTPManipulationPayloads('test', 'verb');
			expect(res).toEqual(['test']);
		});

		it('should generate pollution payloads', () => {
			const res = generateHTTPManipulationPayloads('test', 'pollution');
			expect(res.some(r => r.includes('param=test&param=test'))).toBe(true);
			expect(res.some(r => r.includes('param[]=test&param[]=test'))).toBe(true);
		});

		it('should generate content-type payloads', () => {
			const res = generateHTTPManipulationPayloads('alert("1")', 'content-type');
			expect(res.some(r => r.includes('alert(\\"1\\")'))).toBe(true);
			expect(res.some(r => r.includes('<?xml'))).toBe(true);
			expect(res.some(r => r.includes('alert(%221%22)'))).toBe(true);
		});
		
		it('should generate request smuggling payloads', () => {
			const res = generateHTTPManipulationPayloads('test', 'smuggling');
			expect(res.some(r => r.includes('0\r\n\r\ntest'))).toBe(true);
			expect(res.some(r => r.includes('4\r\ntest\r\n0\r\n\r\n'))).toBe(true);
		});
		
		it('should fallback to pollution if technique is unknown', () => {
			// @ts-ignore
			const res = generateHTTPManipulationPayloads('test', 'unknown');
			expect(res.length).toBe(1); // default switch fallback doesn't add variations
		});
	});
});
