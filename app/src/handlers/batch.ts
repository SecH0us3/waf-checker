import { handleApiCheckFiltered } from './check';

// Global batch state storage (in production, use a database or KV store)
const batchJobs = new Map<
    string,
    {
        id: string;
        status: 'running' | 'completed' | 'stopped' | 'error';
        progress: number;
        currentUrl: string;
        startTime: string;
        results: any[];
        error?: string;
        totalUrls: number;
        completedUrls: number;
    }
>();

// Cleanup old batch jobs periodically to prevent memory leaks
function cleanupOldBatchJobs() {
    const cutoffTime = Date.now() - 24 * 60 * 60 * 1000; // 24 hours ago

    for (const [jobId, job] of batchJobs.entries()) {
        const jobStartTime = new Date(job.startTime).getTime();
        if (jobStartTime < cutoffTime && job.status !== 'running') {
            batchJobs.delete(jobId);
            console.log(`Cleaned up old batch job: ${jobId}`);
        }
    }
}

export async function handleBatchStart(request: Request): Promise<Response> {
    // Run cleanup on each batch start request
    cleanupOldBatchJobs();

    try {
        const body: any = await request.json();
        const { urls, config } = body;

        // Remove delay from config as it's handled client-side
        if (config && config.delayBetweenRequests) {
            delete config.delayBetweenRequests;
        }

        if (!urls || !Array.isArray(urls) || urls.length === 0) {
            return new Response(JSON.stringify({ error: 'No URLs provided' }), {
                status: 400,
                headers: { 'content-type': 'application/json' },
            });
        }

        if (urls.length > 100) {
            return new Response(JSON.stringify({ error: 'Maximum 100 URLs allowed' }), {
                status: 400,
                headers: { 'content-type': 'application/json' },
            });
        }

        // Validate URLs
        const validUrls: string[] = [];
        const invalidUrls: string[] = [];

        for (const url of urls) {
            try {
                const urlObj = new URL(url);
                // Check if protocol is HTTP or HTTPS
                if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
                    invalidUrls.push(`${url} (unsupported protocol: ${urlObj.protocol})`);
                } else {
                    validUrls.push(url);
                }
            } catch {
                invalidUrls.push(`${url} (invalid URL format)`);
            }
        }

        if (invalidUrls.length > 0) {
            return new Response(
                JSON.stringify({
                    error: `Invalid URLs found: ${invalidUrls.join(', ')}`,
                    validUrls: validUrls.length,
                    invalidUrls: invalidUrls.length,
                }),
                {
                    status: 400,
                    headers: { 'content-type': 'application/json' },
                },
            );
        }

        if (validUrls.length === 0) {
            return new Response(JSON.stringify({ error: 'No valid URLs provided' }), {
                status: 400,
                headers: { 'content-type': 'application/json' },
            });
        }

        const jobId = `batch_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
        const startTime = new Date().toISOString();

        // Initialize batch job
        batchJobs.set(jobId, {
            id: jobId,
            status: 'running',
            progress: 0,
            currentUrl: '',
            startTime,
            results: [],
            totalUrls: validUrls.length,
            completedUrls: 0,
        });

        console.log(`Batch job ${jobId} initialized with ${validUrls.length} valid URLs (${invalidUrls.length} invalid URLs filtered out)`);

        // Start batch processing asynchronously
        processBatchAsync(jobId, validUrls, config || {});

        return new Response(
            JSON.stringify({
                jobId,
                status: 'started',
                totalUrls: validUrls.length,
                filteredUrls: invalidUrls.length,
            }),
            {
                headers: { 'content-type': 'application/json' },
            },
        );
    } catch (error) {
        return new Response(JSON.stringify({ error: 'Invalid request body' }), {
            status: 400,
            headers: { 'content-type': 'application/json' },
        });
    }
}

export async function handleBatchStatus(request: Request): Promise<Response> {
    // Occasionally run cleanup on status requests (every ~20th request)
    if (Math.random() < 0.05) {
        cleanupOldBatchJobs();
    }

    const urlObj = new URL(request.url);
    const jobId = urlObj.searchParams.get('jobId');

    if (!jobId) {
        return new Response(JSON.stringify({ error: 'Missing jobId parameter' }), {
            status: 400,
            headers: { 'content-type': 'application/json' },
        });
    }

    const job = batchJobs.get(jobId);
    if (!job) {
        console.log(`Job ${jobId} not found. Available jobs:`, Array.from(batchJobs.keys()));
        return new Response(JSON.stringify({ error: 'Job not found' }), {
            status: 404,
            headers: { 'content-type': 'application/json' },
        });
    }

    console.log(`Status request for job ${jobId}:`, {
        progress: job.progress,
        completedUrls: job.completedUrls,
        totalUrls: job.totalUrls,
        currentUrl: job.currentUrl,
        status: job.status,
    });

    return new Response(JSON.stringify(job), {
        headers: { 'content-type': 'application/json' },
    });
}

export async function handleBatchStop(request: Request): Promise<Response> {
    const urlObj = new URL(request.url);
    const jobId = urlObj.searchParams.get('jobId');

    if (!jobId) {
        return new Response(JSON.stringify({ error: 'Missing jobId parameter' }), {
            status: 400,
            headers: { 'content-type': 'application/json' },
        });
    }

    const job = batchJobs.get(jobId);
    if (!job) {
        return new Response(JSON.stringify({ error: 'Job not found' }), {
            status: 404,
            headers: { 'content-type': 'application/json' },
        });
    }

    if (job.status === 'running') {
        job.status = 'stopped';
        job.error = 'Stopped by user';
    }

    return new Response(JSON.stringify({ status: 'stopped' }), {
        headers: { 'content-type': 'application/json' },
    });
}

async function processBatchAsync(jobId: string, urls: string[], config: any) {
    const job = batchJobs.get(jobId);
    if (!job) return;

    const maxConcurrent = Math.min(config.maxConcurrent || 3, 5);
    let completedCount = 0;

    const semaphore = { permits: maxConcurrent, queue: [] as Array<() => void> };

    async function acquireSemaphore(): Promise<void> {
        if (semaphore.permits > 0) {
            semaphore.permits--;
            return Promise.resolve();
        }
        return new Promise<void>((resolve) => {
            semaphore.queue.push(resolve);
        });
    }

    function releaseSemaphore(): void {
        semaphore.permits++;
        if (semaphore.queue.length > 0) {
            const resolve = semaphore.queue.shift();
            if (resolve) {
                semaphore.permits--;
                resolve();
            }
        }
    }

    function updateProgress(currentUrl: string = '') {
        const currentJob = batchJobs.get(jobId);
        if (currentJob && currentJob.status === 'running') {
            currentJob.completedUrls = completedCount;
            currentJob.progress = Math.round((completedCount / urls.length) * 100);
            currentJob.currentUrl = currentUrl;
            console.log(`Batch ${jobId} progress: ${currentJob.progress}% (${completedCount}/${urls.length}) - ${currentUrl}`);
        }
    }

    const processUrl = async (url: string, index: number): Promise<string | null> => {
        const currentJob = batchJobs.get(jobId);
        if (!currentJob || currentJob.status !== 'running') return null;

        await acquireSemaphore();

        try {
            // Update current URL being processed
            updateProgress(url);

            // Delay is now handled on client-side

            const currentJobCheck = batchJobs.get(jobId);
            if (!currentJobCheck || currentJobCheck.status !== 'running') return null;

            // Run tests for this URL with timeout
            const urlResults = await Promise.race([
                testSingleUrlForBatch(url, config),
                new Promise<never>(
                    (_, reject) => setTimeout(() => reject(new Error('URL test timeout')), 300000), // 5 minute timeout
                ),
            ]);

            const finalJob = batchJobs.get(jobId);
            if (finalJob && finalJob.status === 'running') {
                const resultEntry = {
                    url,
                    success: true,
                    results: urlResults,
                    timestamp: new Date().toISOString(),
                    totalTests: urlResults.length,
                    bypassedTests: urlResults.filter((r) => r.status === 200 || r.status === '200').length,
                    bypassRate:
                        urlResults.length > 0
                            ? Math.round((urlResults.filter((r) => r.status === 200 || r.status === '200').length / urlResults.length) * 100)
                            : 0,
                };

                finalJob.results.push(resultEntry);
                completedCount++;
                updateProgress(url);
            }

            return url;
        } catch (error) {
            console.error(`Error processing URL ${url}:`, error);
            const errorJob = batchJobs.get(jobId);
            if (errorJob && errorJob.status === 'running') {
                errorJob.results.push({
                    url,
                    success: false,
                    error: error instanceof Error ? error.message : 'Unknown error',
                    timestamp: new Date().toISOString(),
                    totalTests: 0,
                    bypassedTests: 0,
                    bypassRate: 0,
                });

                completedCount++;
                updateProgress(url);
            }
            return null;
        } finally {
            releaseSemaphore();
        }
    };

    try {
        const promises = urls.map((url, index) => processUrl(url, index));
        await Promise.allSettled(promises);

        const finalJob = batchJobs.get(jobId);
        if (finalJob) {
            finalJob.status = finalJob.status === 'running' ? 'completed' : finalJob.status;
            finalJob.progress = 100;
            finalJob.completedUrls = completedCount;
            finalJob.currentUrl = '';
            console.log(`Batch ${jobId} finished with status: ${finalJob.status}`);
        }
    } catch (error) {
        console.error(`Batch ${jobId} failed:`, error);
        const errorJob = batchJobs.get(jobId);
        if (errorJob) {
            errorJob.status = 'error';
            errorJob.error = error instanceof Error ? error.message : 'Unknown error';
        }
    }
}

async function testSingleUrlForBatch(url: string, config: any): Promise<any[]> {
    console.log(`Starting batch test for URL: ${url}`);
    const methods = config.methods || ['GET'];
    const categories = config.categories || ['SQL Injection', 'XSS'];

    let allResults: any[] = [];
    let page = 0;
    let maxPages = 10; // Limit to prevent infinite loops

    while (page < maxPages) {
        try {
            const results = await handleApiCheckFiltered(
                url,
                page,
                methods,
                categories,
                config.payloadTemplate,
                config.followRedirect || false,
                config.customHeaders,
                config.falsePositiveTest || false,
                config.caseSensitiveTest || false,
                config.enhancedPayloads || false,
                config.useAdvancedPayloads || false,
                config.autoDetectWAF || false,
                config.useEncodingVariations || false,
                undefined,
                config.httpManipulation
                    ? {
                        enableParameterPollution: true,
                        enableVerbTampering: true,
                        enableContentTypeConfusion: true,
                    }
                    : undefined,
            );

            if (!results || !results.length) {
                console.log(`No more results for ${url} at page ${page}`);
                break;
            }

            allResults = allResults.concat(results);
            console.log(`Batch test ${url}: page ${page} completed, ${results.length} results, total: ${allResults.length}`);
            page++;

            // Limit results to prevent memory issues
            if (allResults.length > 1000) {
                console.log(`Result limit reached for ${url}`);
                break;
            }
        } catch (error) {
            console.error(`Error testing ${url} at page ${page}:`, error);
            break;
        }
    }

    console.log(`Batch test completed for ${url}: ${allResults.length} total results`);
    return allResults;
}
