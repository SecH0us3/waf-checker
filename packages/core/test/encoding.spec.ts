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

		it('should overlong UTF-8 encode traversal characters', () => {
			// '/' (0x2F) -> %C0%AF, '.' (0x2E) -> %C0%AE
			expect(PayloadEncoder.overlongUtf8Encode('../')).toBe('%C0%AE%C0%AE%C0%AF');
			expect(PayloadEncoder.overlongUtf8Encode('/etc/passwd')).toContain('%C0%AF');
		});

		it('should leave alphanumerics untouched when overlong encoding', () => {
			expect(PayloadEncoder.overlongUtf8Encode('abc123')).toBe('abc123');
		});

		it('should include overlong UTF-8 variant in applyEncodings', () => {
			const res = PayloadEncoder.applyEncodings('../etc', { overlongUtf8: true });
			expect(res.some((r) => r.includes('%C0%AF'))).toBe(true);
		});

		it('should full-width encode ASCII and NFKC-normalize back to the original', () => {
			const encoded = PayloadEncoder.fullWidthEncode('<script>');
			expect(encoded).toBe('＜ｓｃｒｉｐｔ＞');
			// The whole point: an NFKC-normalizing backend recovers the attack.
			expect(encoded.normalize('NFKC')).toBe('<script>');
		});

		it('should full-width encode spaces to ideographic space (NFKC -> space)', () => {
			const encoded = PayloadEncoder.fullWidthEncode('a b');
			expect(encoded).toContain('　');
			expect(encoded.normalize('NFKC')).toBe('a b');
		});

		it('should include full-width variant in applyEncodings', () => {
			const res = PayloadEncoder.applyEncodings('SELECT', { fullWidth: true });
			expect(res.some((r) => r.normalize('NFKC') === 'SELECT' && r !== 'SELECT')).toBe(true);
		});

		it('should produce parenthesis-wrapped tautology SQL obfuscation', () => {
			const res = PayloadEncoder.sqlObfuscation("' OR 1=1--");
			expect(res.some((r) => r.includes('OR(1)=(1)'))).toBe(true);
		});

		it('should not recase OR/AND inside unrelated case-sensitive tokens', () => {
			// Regression: \b anchoring keeps 'constructor' and 'command' intact.
			const out = PayloadEncoder.mixedCaseEncode('x[constructor][prototype]=1&command=2');
			expect(out).toContain('constructor');
			expect(out).toContain('command');
		});

		it('should produce MySQL inline-comment keyword obfuscation', () => {
			const res = PayloadEncoder.sqlObfuscation('UNION SELECT 1');
			expect(res.some((r) => r.includes('/*!50000SELECT*/'))).toBe(true);
		});

		it('should obfuscate tag/attribute separators in xss', () => {
			const res = PayloadEncoder.xssObfuscation('<svg onload=alert(1)>');
			expect(res.some((r) => r.includes('<svg/onload='))).toBe(true);
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
