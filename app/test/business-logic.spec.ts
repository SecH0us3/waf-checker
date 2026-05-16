import { describe, it, expect, vi } from 'vitest';
import { handleApiCheckFiltered } from '../src/handlers/check';
import { WAFDetector } from '../src/waf-detection';
import { PayloadEncoder } from '../src/encoding';
import { generateWAFSpecificPayloads } from '../src/advanced-payloads';
import { HTTPManipulator } from '../src/http-manipulation';

describe('Business Logic Tests for Visual Controls', () => {
    describe('Control: "Run WAF Detection" Button', () => {
        // Bug #6 Fix Verification
        it('should detect Generic WAF from response body keywords', async () => {
            const mockResponse = {
                status: 403,
                headers: new Map(),
                ok: false
            } as unknown as Response;
            mockResponse.headers.get = (name: string) => null;

            const responseBody = 'Error: Request blocked by Web Application Firewall. Ray ID: ...';

            const result = await WAFDetector.detectFromResponse(mockResponse, responseBody);

            expect(result.detected).toBe(true);
            expect(result.wafType).toBe('Generic WAF');
        });
    });

    describe('Control: "WAF Type" Dropdown & "Use Encoding Variations" Checkbox', () => {
        // Bug #1 Fix Verification
        it('should generate Cloudflare-specific payloads when "Cloudflare" is selected', () => {
            const basePayload = '<script>alert(1)</script>';
            const payloads = generateWAFSpecificPayloads('Cloudflare', basePayload);

            expect(payloads.length).toBeGreaterThan(0);
            // Cloudflare specific bypass often involves different event handlers or spacing
            // e.g. <svg/onload=...>
            expect(payloads.some(p => p !== basePayload)).toBe(true);
        });

        it('should generate encoded variations separately from WAF-specific ones', () => {
            const basePayload = '<script>alert(1)</script>';
            const encoded = PayloadEncoder.generateBypassVariations(basePayload, 'XSS');

            expect(encoded.length).toBeGreaterThan(0);
            expect(encoded.some(p => p.includes('%3Cscript%3E'))).toBe(true); // URL encoded
        });
    });

    describe('Control: "Run HTTP Manipulation Tests" Button', () => {
        // Bug #7 Fix Verification
        it('should include HEAD method in uncommon methods list', () => {
            const methods = HTTPManipulator.getUncommonMethods();
            expect(methods).toContain('HEAD');
        });
    });

    describe('Control: "Enable Case-Sensitive Test" Checkbox', () => {
        // Bug #4 Fix Verification - Logic Test
        it('should allow preserving mixed-case hostnames (logic verification)', () => {
            const originalUrl = 'http://example.com/path';
            const originalHostname = 'example.com';
            const modifiedHostname = 'ExAmPlE.cOm';

            const u = new URL(originalUrl);
            u.hostname = modifiedHostname;
            expect(u.hostname).toBe('example.com'); // Confirms URL class behavior causing the bug

            const fixedUrl = originalUrl.replace(originalHostname, modifiedHostname);
            expect(fixedUrl).toBe('http://ExAmPlE.cOm/path');
            expect(fixedUrl).toContain(modifiedHostname);
        });
    });

    describe('Integration: Hostname Case Sensitivity', () => {
        it('should send requests with mixed-case hostname when enabled', async () => {
            // Mock global fetch
            const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('OK'));

            // Mock Math.random to return > 0.5, ensuring characters are uppercased
            const randomSpy = vi.spyOn(Math, 'random').mockReturnValue(0.9);

            const url = 'http://example.com/path';
            const page = 0;
            const methods = ['GET'];
            const categories = ['SQL Injection']; // Minimal set

            await handleApiCheckFiltered(
                url,
                page,
                methods,
                categories,
                undefined, // payloadTemplate
                false, // followRedirect
                undefined, // customHeaders
                false, // falsePositiveTest
                true, // caseSensitiveTest <--- ENABLED
                false, // enhancedPayloads
                false, // advancedPayloads
                false, // autoDetectWAF
                false, // encodingVariations
                undefined, // detectedWAF
                undefined // httpManipulation
            );

            const calls = fetchSpy.mock.calls;
            const requestedUrls = calls.map(call => (call[0] as string | Request).toString());

            const hasMixedCase = requestedUrls.some(u => u.includes('EXAMPLE.COM'));

            expect(hasMixedCase).toBe(true);

            // Cleanup
            fetchSpy.mockRestore();
            randomSpy.mockRestore();
        });
    });

    describe('Expanded WAF Detection Tests', () => {
        it('should detect AWS WAF based on Server header', async () => {
            const mockResponse = {
                status: 403,
                headers: new Map([['server', 'awselb/2.0']]),
                ok: false
            } as unknown as Response;
            const headersMap = new Map([['server', 'awselb/2.0']]);
            mockResponse.headers.get = (name: string) => headersMap.get(name.toLowerCase()) || null;

            const result = await WAFDetector.detectFromResponse(mockResponse, '');
            expect(result.detected).toBe(true);
            expect(result.wafType).toBe('AWS WAF');
        });

        it('should detect ModSecurity based on body pattern', async () => {
            const mockResponse = {
                status: 406,
                headers: new Map(),
                ok: false
            } as unknown as Response;
            mockResponse.headers.get = (name: string) => null;

            const body = 'mod_security: Access denied with code 406 (Phase 2). Pattern match...';
            const result = await WAFDetector.detectFromResponse(mockResponse, body);
            expect(result.detected).toBe(true);
            expect(result.wafType).toBe('ModSecurity');
        });

        it('should detect Azure Front Door based on headers and body', async () => {
            const mockResponse = {
                status: 403,
                headers: new Map([['x-azure-ref', '123456']]),
                ok: false
            } as unknown as Response;
            const headersMap = new Map([['x-azure-ref', '123456']]);
            mockResponse.headers.get = (name: string) => headersMap.get(name.toLowerCase()) || null;

            const body = 'Your request has been blocked. This could be due to several reasons...';
            const result = await WAFDetector.detectFromResponse(mockResponse, body);
            expect(result.detected).toBe(true);
            expect(result.wafType).toBe('Azure Front Door');
        });

        it('should detect Google Cloud Armor based on Server header', async () => {
            const mockResponse = {
                status: 403,
                headers: new Map([['server', 'GSE']]),
                ok: false
            } as unknown as Response;
            const headersMap = new Map([['server', 'GSE']]);
            mockResponse.headers.get = (name: string) => headersMap.get(name.toLowerCase()) || null;

            const result = await WAFDetector.detectFromResponse(mockResponse, '');
            expect(result.detected).toBe(true);
            expect(result.wafType).toBe('Google Cloud Armor');
        });
    });

    describe('Comprehensive Payload Generation Tests', () => {
        it('should generate AWS-specific payloads', () => {
            const base = "1 OR 1=1";
            const payloads = generateWAFSpecificPayloads('AWS WAF', base);
            expect(payloads.length).toBeGreaterThan(0);
        });

        it('should generate ModSecurity-specific payloads', () => {
            const base = "UNION SELECT";
            const payloads = generateWAFSpecificPayloads('ModSecurity', base);
            expect(payloads.some(p => p.includes('/**/'))).toBe(true);
        });

        it('should generate Akamai-specific payloads', () => {
            const base = "<script>";
            const payloads = generateWAFSpecificPayloads('Akamai', base);
            expect(payloads.some(p => p.includes('%253C'))).toBe(true); // Double encoded <
        });

        it('should generate Azure-specific payloads', () => {
            const base = "UNION SELECT";
            const payloads = generateWAFSpecificPayloads('Azure Front Door', base);
            expect(payloads.some(p => p.includes('/**/'))).toBe(true);
            expect(payloads.some(p => p.toLowerCase().includes('union'))).toBe(true);
        });
    });

    describe('Advanced Encoding Tests (PayloadEncoder)', () => {
        const payload = "<"; // Use a char that encodeURIComponent actually encodes

        it('should support Double URL Encoding', () => {
            const encoded = PayloadEncoder.doubleUrlEncode(payload);
            expect(encoded).toBe('%253C');
        });

        it('should support Unicode Encoding', () => {
            const P = "'";
            const encoded = PayloadEncoder.unicodeEncode(P);
            // In JS string literals, \\u0027 is the literal string \u0027
            expect(encoded).toBe('\\u0027');
        });

        it('should support Hex Encoding', () => {
            const P = "'";
            const encoded = PayloadEncoder.hexEncode(P);
            expect(encoded).toBe('0x27');
        });

        it('should generate all variations when multiple options enabled', () => {
            const variations = PayloadEncoder.generateBypassVariations(payload, 'SQL Injection');
            expect(variations).toContain('%253C'); // Double URL <
            expect(variations).toContain('\\u003c'); // Unicode <
            expect(variations).toContain('0x3c'); // Hex <
        });
    });
});
