import { describe, it, expect } from 'vitest';
import { PayloadEncoder, WAFBypasses } from '../src/encoding';

describe('encoding.ts', () => {
	describe('PayloadEncoder', () => {
		it('should encode double url', () => {
			expect(PayloadEncoder.doubleUrlEncode('test < >')).toBe('test%2520%253C%2520%253E');
		});
		
		it('should unicode encode', () => {
			expect(PayloadEncoder.unicodeEncode('test <')).toContain('\\u003c');
		});
		
		it('should html entity encode', () => {
			expect(PayloadEncoder.htmlEntityEncode('test <')).toContain('&#60;');
			expect(PayloadEncoder.htmlEntityEncode('test <', true)).toContain('&#x3C;');
		});
		
		it('should hex encode', () => {
			expect(PayloadEncoder.hexEncode('test <')).toContain('0x3c');
		});
		
		it('should octal encode', () => {
			expect(PayloadEncoder.octalEncode('test <')).toContain('\\074');
		});
		
		it('should base64 encode', () => {
			expect(PayloadEncoder.base64Encode('test')).toBe('dGVzdA==');
		});
		
		it('should apply multiple encodings', () => {
			const res = PayloadEncoder.applyEncodings('test <', { 
				doubleUrlEncode: true, 
				unicodeEncode: true,
				htmlEntityEncode: true,
				hexEncode: true,
				octalEncode: true,
				base64Encode: true,
				urlEncode: true
			});
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should apply sql obfuscation', () => {
			const res = PayloadEncoder.sqlObfuscation('SELECT * FROM users');
			expect(res.some(r => r.includes('SELECT/**/*/**/FROM/**/users'))).toBe(true);
		});
		
		it('should apply xss obfuscation', () => {
			const res = PayloadEncoder.xssObfuscation('<script>alert(1) ONLOAD=x</script>');
			expect(res.some(r => r.includes('<SCRIPT>ALERT(1) ONLOAD=X</SCRIPT>'))).toBe(true);
			// Should also do uppercase ONLOAD substitution
			expect(res.some(r => r.includes('oNlOaD')) || res.some(r => r.includes('OnLoAd'))).toBe(true);
		});
	});
	
	describe('WAFBypasses', () => {
		it('should bypass Palo Alto PAN-OS', () => {
			const res = WAFBypasses.panosBypass('test payload 1=1');
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should bypass Sophos', () => {
			const res = WAFBypasses.sophosBypass('<script>alert(1)</script>');
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should bypass Signal Sciences', () => {
			const res = WAFBypasses.signalSciencesBypass('test');
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should bypass Nginx App Protect', () => {
			const res = WAFBypasses.nginxAppProtectBypass('test');
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should bypass HAProxy', () => {
			const res = WAFBypasses.haproxyBypass('test');
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should bypass IBM DataPower', () => {
			const res = WAFBypasses.ibmDataPowerBypass('test');
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should bypass Reblaze', () => {
			const res = WAFBypasses.reblazeBypass('test');
			expect(res.length).toBeGreaterThan(0);
		});
		
		it('should bypass dotDefender', () => {
			const res = WAFBypasses.dotDefenderBypass('test');
			expect(res.length).toBeGreaterThan(0);
		});
	});
});
