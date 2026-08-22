import { describe, it, expect } from 'vitest';
import { generateWAFSpecificPayloads, generateHTTPManipulationPayloads } from '../src/advanced-payloads';

describe('advanced-payloads', () => {
	describe('generateWAFSpecificPayloads', () => {
		it('should route Cloudflare', () => {
			const res = generateWAFSpecificPayloads('test', 'cloudflare');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route AWS', () => {
			const res = generateWAFSpecificPayloads('test', 'aws');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route ModSecurity', () => {
			const res = generateWAFSpecificPayloads('test', 'modsecurity');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Akamai', () => {
			const res = generateWAFSpecificPayloads('test', 'akamai');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Azure', () => {
			const res = generateWAFSpecificPayloads('test', 'azure');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Imperva', () => {
			const res = generateWAFSpecificPayloads('test', 'imperva');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route F5', () => {
			const res = generateWAFSpecificPayloads('test', 'f5');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Google Cloud Armor', () => {
			const res = generateWAFSpecificPayloads('test', 'google');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Palo Alto', () => {
			const res = generateWAFSpecificPayloads('test', 'palo alto');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Sophos', () => {
			const res = generateWAFSpecificPayloads('test', 'sophos');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Signal Sciences', () => {
			const res = generateWAFSpecificPayloads('test', 'signal sciences');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Nginx App Protect', () => {
			const res = generateWAFSpecificPayloads('test', 'nginx');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route HAProxy', () => {
			const res = generateWAFSpecificPayloads('test', 'haproxy');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route IBM DataPower', () => {
			const res = generateWAFSpecificPayloads('test', 'ibm datapower');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route Reblaze', () => {
			const res = generateWAFSpecificPayloads('test', 'reblaze');
			expect(res.length).toBeGreaterThan(0);
		});
		it('should route dotDefender', () => {
			const res = generateWAFSpecificPayloads('test', 'dotdefender');
			expect(res.length).toBeGreaterThan(0);
		});
	});

	describe('generateHTTPManipulationPayloads', () => {
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
