import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleBatchStart, handleBatchStop } from '../src/handlers/batch';
import * as checkModule from '../src/handlers/check';

describe('Batch memory leak fix verification', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.spyOn(checkModule, 'handleApiCheckFiltered').mockResolvedValue([]);
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.restoreAllMocks();
        vi.useRealTimers();
    });

    it('enforces MAX_BATCH_JOBS limit when all jobs are running', async () => {
        // MAX_BATCH_JOBS is 50.
        // Start 50 running jobs.
        for (let i = 0; i < 50; i++) {
            const request = new Request('https://example.com/api/batch/start', {
                method: 'POST',
                body: JSON.stringify({ urls: ['https://example.com'] })
            });
            const response = await handleBatchStart(request);
            expect(response.status).toBe(200);
        }

        // The 51st job should fail with 429 because all 50 are 'running' and cannot be evicted
        const request51 = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ urls: ['https://example.com'] })
        });
        const response51 = await handleBatchStart(request51);
        expect(response51.status).toBe(429);
    });

    it('evicts completed jobs to make room for new ones', async () => {
        // Start 50 jobs
        const jobIds = [];
        for (let i = 0; i < 50; i++) {
            const request = new Request('https://example.com/api/batch/start', {
                method: 'POST',
                body: JSON.stringify({ urls: ['https://example.com'] })
            });
            const response = await handleBatchStart(request);
            const data = await response.json() as any;
            jobIds.push(data.jobId);
        }

        // Stop one job so it's not 'running'
        await handleBatchStop(new Request(`https://example.com/api/batch/stop?jobId=${jobIds[0]}`));

        // Now we should be able to start a new job because the stopped one will be evicted
        const request51 = new Request('https://example.com/api/batch/start', {
            method: 'POST',
            body: JSON.stringify({ urls: ['https://example.com'] })
        });
        const response51 = await handleBatchStart(request51);
        expect(response51.status).toBe(200);
    });
});
