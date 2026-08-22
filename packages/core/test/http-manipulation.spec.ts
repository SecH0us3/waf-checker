import { describe, it, expect } from 'vitest';
import { HTTPManipulator } from '../src/http-manipulation';

describe('HTTPManipulator', () => {
	it('should return uncommon methods', () => {
		const methods = HTTPManipulator.getUncommonMethods();
		expect(methods).toContain('TRACE');
		expect(methods).toContain('OPTIONS');
		expect(methods).toContain('PROPFIND');
		expect(methods.length).toBeGreaterThan(5);
	});

	it('should generate method overrides', () => {
		const overrides = HTTPManipulator.generateMethodOverrides('GET', 'POST');
		expect(overrides).toBeInstanceOf(Array);
		expect(overrides.length).toBeGreaterThan(0);
		
		const hasXHttpOverride = overrides.some(o => o['X-HTTP-Method-Override'] === 'POST');
		expect(hasXHttpOverride).toBe(true);
	});

	it('should generate parameter pollution variations', () => {
		const variations = HTTPManipulator.generateParameterPollution('id', '1=1');
		expect(variations).toBeInstanceOf(Array);
		expect(variations.some(v => v.includes('id=1%3D1&id=safe'))).toBe(true);
		expect(variations.some(v => v.includes('id[]=1%3D1'))).toBe(true);
	});

	it('should get content type variations', () => {
		const variations = HTTPManipulator.getContentTypeVariations();
		expect(variations).toBeInstanceOf(Array);
		expect(variations.some(v => v['Content-Type']?.includes('application/x-www-form-urlencoded'))).toBe(true);
		expect(variations.some(v => v['Content-Type']?.includes('application/json'))).toBe(true);
	});

	it('should generate request smuggling headers', () => {
		const headers = HTTPManipulator.generateRequestSmugglingHeaders();
		expect(headers).toBeInstanceOf(Array);
		expect(headers.some(h => Object.keys(h).includes('Transfer-Encoding') || Object.keys(h).includes('Content-Length'))).toBe(true);
	});

	it('should generate host header variations', () => {
		const variations = HTTPManipulator.generateHostHeaderVariations('target.com', 'evil.com');
		expect(variations).toBeInstanceOf(Array);
		expect(variations.some(v => v['Host'] === 'target.com' && v['X-Forwarded-Host'] === 'evil.com')).toBe(true);
		expect(variations.some(v => v['Host'] === 'evil.com')).toBe(true);
	});

	it('should generate manipulated requests based on options', () => {
		const requests = HTTPManipulator.generateManipulatedRequests('http://example.com/api', 'GET', '1=1', {
			enableVerbTampering: true,
			enableParameterPollution: true,
			enableContentTypeConfusion: true,
		});
		
		expect(requests).toBeInstanceOf(Array);
		expect(requests.length).toBeGreaterThan(0);
		
		// Should contain some method overrides (which happens if enableVerbTampering is true)
		const overrides = requests.filter(r => Object.keys(r.headers || {}).some(k => k.toLowerCase().includes('override')));
		expect(overrides.length).toBeGreaterThan(0);
		
		// Should contain parameter pollution
		const pollution = requests.filter(r => r.url.includes('safe') && r.url.includes('test'));
		expect(pollution.length).toBeGreaterThan(0);
	});
});
