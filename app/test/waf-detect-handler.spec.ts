import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleWAFDetection } from '../src/handlers/waf-detect';
import { WAFDetector } from '../src/waf-detection';

describe('handleWAFDetection handler', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('returns 200 and detection results on success', async () => {
        const mockDetection = {
            detected: true,
            wafType: 'Cloudflare',
            confidence: 90,
            evidence: ['Header: server: cloudflare'],
            suggestedBypassTechniques: ['Unicode encoding']
        };
        const mockBypass = {
            httpMethodsBypass: false,
            headerBypass: true,
            encodingBypass: false,
            parameterPollution: false
        };

        const activeDetectionSpy = vi.spyOn(WAFDetector, 'activeDetection').mockResolvedValue(mockDetection);
        const detectBypassSpy = vi.spyOn(WAFDetector, 'detectBypassOpportunities').mockResolvedValue(mockBypass);

        const request = new Request('https://example.com/api/waf-detect?url=https://target.com');
        const response = await handleWAFDetection(request);

        expect(response.status).toBe(200);
        expect(response.headers.get('content-type')).toBe('application/json; charset=UTF-8');

        const data = await response.json() as any;
        expect(data.detection).toEqual(mockDetection);
        expect(data.bypassOpportunities).toEqual(mockBypass);
        expect(data.timestamp).toBeDefined();

        expect(activeDetectionSpy).toHaveBeenCalledWith('https://target.com');
        expect(detectBypassSpy).toHaveBeenCalledWith('https://target.com');
    });

    it('strips {PAYLOAD} from the target url before passing to WAFDetector', async () => {
        const activeDetectionSpy = vi.spyOn(WAFDetector, 'activeDetection').mockResolvedValue({} as any);
        const detectBypassSpy = vi.spyOn(WAFDetector, 'detectBypassOpportunities').mockResolvedValue({} as any);

        const request = new Request('https://example.com/api/waf-detect?url=https://target.com/api/login?user={PAYLOAD}');
        await handleWAFDetection(request);

        expect(activeDetectionSpy).toHaveBeenCalledWith('https://target.com/api/login?user=');
        expect(detectBypassSpy).toHaveBeenCalledWith('https://target.com/api/login?user=');
    });

    it('returns 500 when WAFDetector.activeDetection throws an Error object', async () => {
        const errorMessage = 'Network timeout';
        vi.spyOn(WAFDetector, 'activeDetection').mockRejectedValue(new Error(errorMessage));

        const request = new Request('https://example.com/api/waf-detect?url=https://target.com');
        const response = await handleWAFDetection(request);

        expect(response.status).toBe(500);
        expect(response.headers.get('content-type')).toBe('application/json; charset=UTF-8');

        const data = await response.json() as any;
        expect(data.error).toBe('WAF detection failed');
        expect(data.message).toBe(errorMessage);
    });

    it('returns 500 when WAFDetector.activeDetection throws a non-Error object', async () => {
        vi.spyOn(WAFDetector, 'activeDetection').mockRejectedValue('Something went wrong');

        const request = new Request('https://example.com/api/waf-detect?url=https://target.com');
        const response = await handleWAFDetection(request);

        expect(response.status).toBe(500);
        expect(response.headers.get('content-type')).toBe('application/json; charset=UTF-8');

        const data = await response.json() as any;
        expect(data.error).toBe('WAF detection failed');
        expect(data.message).toBe('Unknown error');
    });

    it('returns 500 when WAFDetector.detectBypassOpportunities throws', async () => {
        vi.spyOn(WAFDetector, 'activeDetection').mockResolvedValue({
            detected: false,
            wafType: 'Unknown',
            confidence: 0,
            evidence: [],
            suggestedBypassTechniques: []
        });
        vi.spyOn(WAFDetector, 'detectBypassOpportunities').mockRejectedValue(new Error('Bypass detection failed'));

        const request = new Request('https://example.com/api/waf-detect?url=https://target.com');
        const response = await handleWAFDetection(request);

        expect(response.status).toBe(500);
        expect(response.headers.get('content-type')).toBe('application/json; charset=UTF-8');

        const data = await response.json() as any;
        expect(data.error).toBe('WAF detection failed');
        expect(data.message).toBe('Bypass detection failed');
    });

    it('returns 400 when url parameter is missing', async () => {
        const request = new Request('https://example.com/api/waf-detect');
        const response = await handleWAFDetection(request);

        expect(response.status).toBe(400);
        expect(response.headers.get('content-type')).toBe('application/json; charset=UTF-8');

        const data = await response.json() as any;
        expect(data.error).toBe('Missing url parameter');
    });
});
