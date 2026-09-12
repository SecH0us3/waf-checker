import { describe, it, expect } from 'vitest';
import { PAYLOADS } from '../src/payloads';

const VALID_TYPES = ['ParamCheck', 'FileCheck', 'Header'];

describe('Payload registry integrity', () => {
	it('every category is well-formed', () => {
		for (const [name, cat] of Object.entries(PAYLOADS)) {
			expect(VALID_TYPES, `${name} has valid type`).toContain(cat.type);
			expect(Array.isArray(cat.payloads), `${name}.payloads is array`).toBe(true);
			expect(Array.isArray(cat.falsePayloads), `${name}.falsePayloads is array`).toBe(true);
			expect(cat.payloads.length, `${name} has at least one payload`).toBeGreaterThan(0);
			for (const p of cat.payloads) {
				expect(typeof p, `${name} payload is string`).toBe('string');
			}
			for (const p of cat.falsePayloads) {
				expect(typeof p, `${name} falsePayload is string`).toBe('string');
			}
		}
	});

	describe('XPath Injection', () => {
		const cat = PAYLOADS['XPath Injection'];
		it('is registered as a ParamCheck', () => {
			expect(cat).toBeDefined();
			expect(cat.type).toBe('ParamCheck');
		});
		it('includes authentication-bypass and blind XPath vectors', () => {
			expect(cat.payloads.some((p) => p.includes("or '1'='1"))).toBe(true);
			expect(cat.payloads.some((p) => /position\(\)|name\(\)|count\(/.test(p))).toBe(true);
		});
	});

	describe('Spreadsheet Formula Injection', () => {
		const cat = PAYLOADS['Spreadsheet Formula Injection'];
		it('is registered as a ParamCheck', () => {
			expect(cat).toBeDefined();
			expect(cat.type).toBe('ParamCheck');
		});
		it('every payload starts with a formula-trigger character', () => {
			// Spreadsheet engines evaluate cells beginning with = + - @ or a tab.
			const triggers = ['=', '+', '-', '@', '\t'];
			for (const p of cat.payloads) {
				expect(triggers, `"${p}" begins with a formula trigger`).toContain(p[0]);
			}
		});
		it('benign values do not begin with a formula-trigger character', () => {
			const triggers = ['=', '+', '-', '@', '\t'];
			for (const p of cat.falsePayloads) {
				expect(triggers).not.toContain(p[0]);
			}
		});
	});

	describe('Log4Shell (JNDI)', () => {
		const cat = PAYLOADS['Log4Shell (JNDI)'];
		it('is registered as a ParamCheck', () => {
			expect(cat).toBeDefined();
			expect(cat.type).toBe('ParamCheck');
		});
		it('covers multiple JNDI protocols', () => {
			const joined = cat.payloads.join(' ');
			for (const proto of ['ldap:', 'rmi:', 'dns:']) {
				expect(joined).toContain(proto);
			}
		});
		it('includes lookup-based obfuscation variants for filter evasion', () => {
			expect(cat.payloads.some((p) => p.includes('${lower:') || p.includes('${::-') || p.includes('${upper:'))).toBe(true);
		});
		it('benign templating strings are not literal JNDI lookups', () => {
			for (const p of cat.falsePayloads) {
				expect(p.toLowerCase()).not.toContain('jndi:');
			}
		});
	});
});
