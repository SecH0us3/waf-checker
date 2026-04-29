import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleBatchStart, handleBatchStatus } from '../src/handlers/batch';
import * as checkModule from '../src/handlers/check';

describe('handleBatchStart handler', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Mock handleApiCheckFiltered to avoid actual API calls in the background job
        vi.spyOn(checkModule, 'handleApiCheckFiltered').mockResolvedValue([]);
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('returns 400 for invalid request body (non-JSON)', async () => {
        const request = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: 'invalid-json'
        });
        const response = await handleBatchStart(request);

        expect(response.status).toBe(400);
        const data = await response.json() as any;
        expect(data.error).toBe('Invalid request body');
    });

    it('returns 400 for missing urls', async () => {
        const request = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ config: {} })
        });
        const response = await handleBatchStart(request);

        expect(response.status).toBe(400);
        const data = await response.json() as any;
        expect(data.error).toBe('No URLs provided');
    });

    it('returns 400 for empty urls array', async () => {
        const request = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ urls: [], config: {} })
        });
        const response = await handleBatchStart(request);

        expect(response.status).toBe(400);
        const data = await response.json() as any;
        expect(data.error).toBe('No URLs provided');
    });

    it('returns 400 for exceeding max URLs (> 100)', async () => {
        const urls = Array.from({ length: 101 }, (_, i) => `https://example.com/${i}`);
        const request = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ urls, config: {} })
        });
        const response = await handleBatchStart(request);

        expect(response.status).toBe(400);
        const data = await response.json() as any;
        expect(data.error).toBe('Maximum 100 URLs allowed');
    });

    it('returns 400 for all invalid URLs', async () => {
        const request = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ urls: ['not-a-url', 'http://127.0.0.1'], config: {} })
        });
        const response = await handleBatchStart(request);

        expect(response.status).toBe(400);
        const data = await response.json() as any;
        expect(data.error).toMatch(/Invalid URLs found/);
        expect(data.validUrls).toBe(0);
        expect(data.invalidUrls).toBe(2);
    });

    it('returns 400 for mixed valid and invalid URLs', async () => {
        const request = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ urls: ['https://example.com', 'not-a-url'], config: {} })
        });
        const response = await handleBatchStart(request);

        expect(response.status).toBe(400);
        const data = await response.json() as any;
        expect(data.error).toMatch(/Invalid URLs found/);
        expect(data.validUrls).toBe(1);
        expect(data.invalidUrls).toBe(1);
    });

    it('returns 200 and starts a batch job for valid URLs', async () => {
        const request = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ urls: ['https://example.com', 'https://test.com'], config: {} })
        });
        const response = await handleBatchStart(request);

        expect(response.status).toBe(200);
        const data = await response.json() as any;
        expect(data.jobId).toBeDefined();
        expect(data.status).toBe('started');
        expect(data.totalUrls).toBe(2);
        expect(data.filteredUrls).toBe(0);

        // Verify the job exists using handleBatchStatus
        const statusReq = new Request(`https://example.com/api/batch/status?jobId=${data.jobId}`);
        const statusRes = await handleBatchStatus(statusReq);
        expect(statusRes.status).toBe(200);
        const statusData = await statusRes.json() as any;
        expect(statusData.id).toBe(data.jobId);
        expect(statusData.totalUrls).toBe(2);
        // The status can be 'running' or 'completed' depending on how fast the microtask queue processed it
    });
});
