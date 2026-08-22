import { describe, it, expect } from 'vitest';
import { isValidTargetUrl } from '../src/utils/security';

describe('isValidTargetUrl', () => {
    describe('Valid URLs', () => {
        it('should allow valid public https URLs', () => {
            expect(isValidTargetUrl('https://www.google.com')).toBe(true);
            expect(isValidTargetUrl('https://github.com/test')).toBe(true);
        });

        it('should allow valid public http URLs', () => {
            expect(isValidTargetUrl('http://example.com')).toBe(true);
        });

        it('should allow valid public IP addresses', () => {
            expect(isValidTargetUrl('http://8.8.8.8')).toBe(true);
            expect(isValidTargetUrl('http://1.1.1.1')).toBe(true);
        });

        it('should allow valid public IPv6 addresses', () => {
            expect(isValidTargetUrl('http://[2001:4860:4860::8888]')).toBe(true);
        });

        it('should allow domains that happen to start with IPv6 private range hex characters', () => {
            expect(isValidTargetUrl('http://fc00.com')).toBe(true);
            expect(isValidTargetUrl('http://fe80.org')).toBe(true);
        });
    });

    describe('Invalid Protocols', () => {
        it('should reject non-http/https protocols', () => {
            expect(isValidTargetUrl('ftp://example.com')).toBe(false);
            expect(isValidTargetUrl('file:///etc/passwd')).toBe(false);
            expect(isValidTargetUrl('gopher://example.com')).toBe(false);
            expect(isValidTargetUrl('javascript:alert(1)')).toBe(false);
        });
    });

    describe('IPv4 Internal Ranges', () => {
        it('should reject localhost', () => {
            expect(isValidTargetUrl('http://localhost')).toBe(false);
            expect(isValidTargetUrl('http://127.0.0.1')).toBe(false);
            expect(isValidTargetUrl('http://127.0.0.2')).toBe(false);
        });

        it('should reject 10.0.0.0/8', () => {
            expect(isValidTargetUrl('http://10.0.0.1')).toBe(false);
            expect(isValidTargetUrl('http://10.255.255.255')).toBe(false);
        });

        it('should reject 172.16.0.0/12', () => {
            expect(isValidTargetUrl('http://172.16.0.1')).toBe(false);
            expect(isValidTargetUrl('http://172.31.255.255')).toBe(false);
        });

        it('should reject 192.168.0.0/16', () => {
            expect(isValidTargetUrl('http://192.168.0.1')).toBe(false);
            expect(isValidTargetUrl('http://192.168.255.255')).toBe(false);
        });

        it('should reject 169.254.0.0/16 (link-local)', () => {
            expect(isValidTargetUrl('http://169.254.0.1')).toBe(false);
        });

        it('should reject 0.0.0.0/8', () => {
            expect(isValidTargetUrl('http://0.0.0.0')).toBe(false);
            expect(isValidTargetUrl('http://0.255.255.255')).toBe(false);
        });
    });

    describe('IPv6 Internal Ranges (Current Gap)', () => {
        it('should reject unspecified IPv6 address (::)', () => {
            expect(isValidTargetUrl('http://[::]')).toBe(false);
            expect(isValidTargetUrl('http://[0000:0000:0000:0000:0000:0000:0000:0000]')).toBe(false);
        });

        it('should reject IPv4-compatible IPv6 addresses for internal IPs', () => {
            expect(isValidTargetUrl('http://[::127.0.0.1]')).toBe(false);
            expect(isValidTargetUrl('http://[::10.0.0.1]')).toBe(false);
            expect(isValidTargetUrl('http://[::192.168.0.1]')).toBe(false);
        });

        it('should reject uncompressed IPv6 loopback', () => {
            expect(isValidTargetUrl('http://[0:0:0:0:0:0:0:1]')).toBe(false);
            expect(isValidTargetUrl('http://[0000:0000:0000:0000:0000:0000:0000:0001]')).toBe(false);
        });

        it('should reject IPv6 loopback', () => {
            expect(isValidTargetUrl('http://[::1]')).toBe(false);
        });

        it('should reject IPv6 Unique Local Address (fc00::/7)', () => {
            expect(isValidTargetUrl('http://[fc00::1]')).toBe(false);
            expect(isValidTargetUrl('http://[fd00::1]')).toBe(false);
        });

        it('should reject IPv6 Link-Local Address (fe80::/10)', () => {
            expect(isValidTargetUrl('http://[fe80::1]')).toBe(false);
        });

        it('should reject IPv4-mapped IPv6 internal addresses', () => {
            expect(isValidTargetUrl('http://[::ffff:127.0.0.1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:10.0.0.1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:192.168.0.1]')).toBe(false);
        });

        it('should reject hex-encoded IPv4-mapped IPv6 internal addresses', () => {
            expect(isValidTargetUrl('http://[::ffff:7f00:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:0a00:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:a00:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:ac10:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:c0a8:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:a9fe:1]')).toBe(false);
        });
    });

    describe('Additional IPv4 Internal Ranges', () => {
        it('should reject CGNAT (100.64.0.0/10)', () => {
            expect(isValidTargetUrl('http://100.64.0.1')).toBe(false);
            expect(isValidTargetUrl('http://100.127.255.255')).toBe(false);
        });
        it('should reject IETF Protocol Assignments (192.0.0.0/24)', () => {
            expect(isValidTargetUrl('http://192.0.0.1')).toBe(false);
        });
        it('should reject TEST-NET-1 (192.0.2.0/24)', () => {
            expect(isValidTargetUrl('http://192.0.2.1')).toBe(false);
        });
        it('should reject Benchmarking (198.18.0.0/15)', () => {
            expect(isValidTargetUrl('http://198.18.0.1')).toBe(false);
            expect(isValidTargetUrl('http://198.19.255.255')).toBe(false);
        });
        it('should reject TEST-NET-2 (198.51.100.0/24)', () => {
            expect(isValidTargetUrl('http://198.51.100.1')).toBe(false);
        });
        it('should reject TEST-NET-3 (203.0.113.0/24)', () => {
            expect(isValidTargetUrl('http://203.0.113.1')).toBe(false);
        });
        it('should reject Multicast (224.0.0.0/4)', () => {
            expect(isValidTargetUrl('http://224.0.0.1')).toBe(false);
            expect(isValidTargetUrl('http://239.255.255.255')).toBe(false);
        });
        it('should reject Reserved (240.0.0.0/4)', () => {
            expect(isValidTargetUrl('http://240.0.0.1')).toBe(false);
            expect(isValidTargetUrl('http://255.255.255.255')).toBe(false);
        });
    });

    describe('Additional IPv6 Internal Ranges', () => {
        it('should reject hex-encoded IPv4-compatible IPv6 internal addresses', () => {
            expect(isValidTargetUrl('http://[::7f00:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::0a00:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::a00:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ac10:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::c0a8:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::a9fe:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::6440:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::c000:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::c000]')).toBe(false);
            expect(isValidTargetUrl('http://[::c612:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::c633:6401]')).toBe(false);
            expect(isValidTargetUrl('http://[::cb00:7101]')).toBe(false);
        });
        
        it('should reject additional hex-encoded IPv4-mapped IPv6 internal addresses', () => {
            expect(isValidTargetUrl('http://[::ffff:6440:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:c000:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:c000]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:c612:1]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:c633:6401]')).toBe(false);
            expect(isValidTargetUrl('http://[::ffff:cb00:7101]')).toBe(false);
        });
    });

    describe('Invalid URL formats', () => {
        it('should reject malformed URLs', () => {
            expect(isValidTargetUrl('not-a-url')).toBe(false);
            expect(isValidTargetUrl('')).toBe(false);
        });

        it('should handle URLs that throw during parsing', () => {
            expect(isValidTargetUrl('http://[::1')).toBe(false);
        });
    });
});
