/**
 * Batch testing module for WAF Checker - handles bulk URL testing with progress tracking
 * Supports concurrent testing, progress reporting, and result aggregation
 */

export interface BatchTestConfig {
  urls: string[];
  methods: string[];
  categories: string[];
  followRedirect: boolean;
  falsePositiveTest: boolean;
  caseSensitiveTest: boolean;
  enhancedPayloads: boolean;
  useAdvancedPayloads: boolean;
  autoDetectWAF: boolean;
  useEncodingVariations: boolean;
  httpManipulation: boolean;
  payloadTemplate?: string;
  customHeaders?: string;
  maxConcurrent: number;
  delayBetweenRequests: number; // milliseconds
}

export interface BatchTestResult {
  url: string;
  success: boolean;
  results: any[];
  wafDetection?: any;
  error?: string;
  startTime: string;
  endTime: string;
  duration: number;
  totalTests: number;
  bypassedTests: number;
  bypassRate: number;
}

export interface BatchProgress {
  totalUrls: number;
  completedUrls: number;
  currentUrl: string;
  progress: number; // 0-100
  estimatedTimeRemaining: number; // milliseconds
  startTime: string;
  errors: string[];
}

export type ProgressCallback = (progress: BatchProgress) => void;
export type ResultCallback = (result: BatchTestResult) => void;

/**
 * Batch tester class for managing bulk URL testing
 */
export class BatchTester {
  private config: BatchTestConfig;
  private progressCallback?: ProgressCallback;
  private resultCallback?: ResultCallback;
  private isRunning = false;
  private shouldStop = false;
  private startTime = '';
  private completedCount = 0;
  private errors: string[] = [];

  constructor(config: BatchTestConfig) {
    this.config = config;
  }

  /**
   * Set progress callback
   */
  onProgress(callback: ProgressCallback): void {
    this.progressCallback = callback;
  }

  /**
   * Set result callback (called for each completed URL)
   */
  onResult(callback: ResultCallback): void {
    this.resultCallback = callback;
  }

  /**
   * Start batch testing
   */
  async start(): Promise<BatchTestResult[]> {
    if (this.isRunning) {
      throw new Error('Batch test is already running');
    }

    this.isRunning = true;
    this.shouldStop = false;
    this.startTime = new Date().toISOString();
    this.completedCount = 0;
    this.errors = [];

    const results: BatchTestResult[] = [];
    const semaphore = new Semaphore(this.config.maxConcurrent);

    try {
      const promises = this.config.urls.map(async (url, index) => {
        if (this.shouldStop) return null;

        await semaphore.acquire();

        try {
          if (this.shouldStop) return null;

          // Add delay between requests if configured
          if (this.config.delayBetweenRequests > 0 && index > 0) {
            await this.delay(this.config.delayBetweenRequests);
          }

          const result = await this.testSingleUrl(url);
          results.push(result);

          if (this.resultCallback) {
            this.resultCallback(result);
          }

          this.completedCount++;
          this.updateProgress(url);

          return result;
        } catch (error) {
          const errorMsg = `Failed to test ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`;
          this.errors.push(errorMsg);
          console.error(errorMsg);

          const failedResult: BatchTestResult = {
            url,
            success: false,
            results: [],
            error: errorMsg,
            startTime: new Date().toISOString(),
            endTime: new Date().toISOString(),
            duration: 0,
            totalTests: 0,
            bypassedTests: 0,
            bypassRate: 0
          };

          results.push(failedResult);

          if (this.resultCallback) {
            this.resultCallback(failedResult);
          }

          this.completedCount++;
          this.updateProgress(url);

          return failedResult;
        } finally {
          semaphore.release();
        }
      });

      await Promise.all(promises);
      return results.filter(r => r !== null) as BatchTestResult[];

    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Stop batch testing
   */
  stop(): void {
    this.shouldStop = true;
  }

  /**
   * Check if batch test is running
   */
  isTestRunning(): boolean {
    return this.isRunning;
  }

  /**
   * Test a single URL
   */
  private async testSingleUrl(url: string): Promise<BatchTestResult> {
    const startTime = new Date().toISOString();
    const testStart = Date.now();

    try {
      // Auto-detect WAF if enabled
      let wafDetection = null;
      if (this.config.autoDetectWAF) {
        try {
          const wafResponse = await fetch(`/api/waf-detect?url=${encodeURIComponent(url)}`);
          if (wafResponse.ok) {
            wafDetection = await wafResponse.json();
          }
        } catch (error) {
          console.warn(`WAF detection failed for ${url}:`, error);
        }
      }

      // Run main tests
      let allResults: any[] = [];
      let page = 0;

      while (true) {
        if (this.shouldStop) break;

        const params = new URLSearchParams({
          url,
          methods: this.config.methods.join(','),
          categories: this.config.categories.join(','),
          page: page.toString(),
          followRedirect: this.config.followRedirect ? '1' : '0',
          falsePositiveTest: this.config.falsePositiveTest ? '1' : '0',
          caseSensitiveTest: this.config.caseSensitiveTest ? '1' : '0',
          enhancedPayloads: this.config.enhancedPayloads ? '1' : '0',
          useAdvancedPayloads: this.config.useAdvancedPayloads ? '1' : '0',
          autoDetectWAF: this.config.autoDetectWAF ? '1' : '0',
          useEncodingVariations: this.config.useEncodingVariations ? '1' : '0',
          httpManipulation: this.config.httpManipulation ? '1' : '0',
          detectedWAF: wafDetection?.detection?.wafType || '',
        });

        const response = await fetch(`/api/check?${params.toString()}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            payloadTemplate: this.config.payloadTemplate || '',
            customHeaders: this.config.customHeaders || '',
            detectedWAF: wafDetection?.detection?.wafType || null,
          }),
        });

        if (!response.ok) break;

        const results = await response.json();
        if (!results || !results.length) break;

        allResults = allResults.concat(results);
        page++;
      }

      const endTime = new Date().toISOString();
      const duration = Date.now() - testStart;

      // Calculate bypass statistics
      const totalTests = allResults.length;
      const bypassedTests = allResults.filter(r =>
        this.config.falsePositiveTest
          ? (r.status === 403 || r.status === '403')
          : (r.status === 200 || r.status === '200' || r.status === 500 || r.status === '500')
      ).length;
      const bypassRate = totalTests > 0 ? (bypassedTests / totalTests) * 100 : 0;

      return {
        url,
        success: true,
        results: allResults,
        wafDetection: wafDetection?.detection,
        startTime,
        endTime,
        duration,
        totalTests,
        bypassedTests,
        bypassRate: Math.round(bypassRate * 100) / 100
      };

    } catch (error) {
      const endTime = new Date().toISOString();
      const duration = Date.now() - testStart;

      throw new Error(`Testing failed for ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Update progress and notify callback
   */
  private updateProgress(currentUrl: string): void {
    if (!this.progressCallback) return;

    const progress = (this.completedCount / this.config.urls.length) * 100;
    const elapsed = Date.now() - new Date(this.startTime).getTime();
    const estimatedTotal = elapsed / (this.completedCount / this.config.urls.length);
    const estimatedTimeRemaining = Math.max(0, estimatedTotal - elapsed);

    const progressData: BatchProgress = {
      totalUrls: this.config.urls.length,
      completedUrls: this.completedCount,
      currentUrl,
      progress: Math.round(progress * 100) / 100,
      estimatedTimeRemaining,
      startTime: this.startTime,
      errors: [...this.errors]
    };

    this.progressCallback(progressData);
  }

  /**
   * Utility method to add delay
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Semaphore for controlling concurrent operations
 */
class Semaphore {
  private permits: number;
  private waitQueue: Array<() => void> = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      this.waitQueue.push(resolve);
    });
  }

  release(): void {
    this.permits++;
    if (this.waitQueue.length > 0) {
      const resolve = this.waitQueue.shift();
      if (resolve) {
        this.permits--;
        resolve();
      }
    }
  }
}

/**
 * Utility functions for batch operations
 */
export class BatchUtils {
  /**
   * Parse URLs from text input (one URL per line)
   */
  static parseUrlList(text: string): string[] {
    return text
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && line.startsWith('http'))
      .map(line => {
        try {
          new URL(line); // Validate URL
          return line;
        } catch {
          return null;
        }
      })
      .filter(url => url !== null) as string[];
  }

  /**
   * Validate batch configuration
   */
  static validateConfig(config: BatchTestConfig): string[] {
    const errors: string[] = [];

    if (!config.urls || config.urls.length === 0) {
      errors.push('No URLs provided for batch testing');
    }

    if (config.urls.length > 100) {
      errors.push('Maximum 100 URLs allowed for batch testing');
    }

    if (config.maxConcurrent < 1 || config.maxConcurrent > 10) {
      errors.push('Max concurrent requests must be between 1 and 10');
    }

    if (config.delayBetweenRequests < 0 || config.delayBetweenRequests > 10000) {
      errors.push('Delay between requests must be between 0 and 10000ms');
    }

    if (!config.methods || config.methods.length === 0) {
      errors.push('No HTTP methods selected');
    }

    if (!config.categories || config.categories.length === 0) {
      errors.push('No test categories selected');
    }

    // Validate URLs
    config.urls.forEach((url, index) => {
      try {
        new URL(url);
      } catch {
        errors.push(`Invalid URL at line ${index + 1}: ${url}`);
      }
    });

    return errors;
  }

  /**
   * Generate summary statistics from batch results
   */
  static generateSummary(results: BatchTestResult[]): {
    totalUrls: number;
    successfulTests: number;
    failedTests: number;
    totalTestCases: number;
    totalBypassedTests: number;
    averageBypassRate: number;
    averageDuration: number;
    wafTypes: { [key: string]: number };
    topVulnerableUrls: Array<{ url: string; bypassRate: number }>;
  } {
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);

    const totalTestCases = successful.reduce((sum, r) => sum + r.totalTests, 0);
    const totalBypassedTests = successful.reduce((sum, r) => sum + r.bypassedTests, 0);
    const averageBypassRate = successful.length > 0
      ? successful.reduce((sum, r) => sum + r.bypassRate, 0) / successful.length
      : 0;
    const averageDuration = successful.length > 0
      ? successful.reduce((sum, r) => sum + r.duration, 0) / successful.length
      : 0;

    // Count WAF types
    const wafTypes: { [key: string]: number } = {};
    successful.forEach(r => {
      if (r.wafDetection?.wafType) {
        wafTypes[r.wafDetection.wafType] = (wafTypes[r.wafDetection.wafType] || 0) + 1;
      }
    });

    // Find most vulnerable URLs
    const topVulnerableUrls = successful
      .filter(r => r.bypassRate > 0)
      .sort((a, b) => b.bypassRate - a.bypassRate)
      .slice(0, 10)
      .map(r => ({ url: r.url, bypassRate: r.bypassRate }));

    return {
      totalUrls: results.length,
      successfulTests: successful.length,
      failedTests: failed.length,
      totalTestCases,
      totalBypassedTests,
      averageBypassRate: Math.round(averageBypassRate * 100) / 100,
      averageDuration: Math.round(averageDuration),
      wafTypes,
      topVulnerableUrls
    };
  }

  /**
   * Format duration in human readable format
   */
  static formatDuration(milliseconds: number): string {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Estimate batch test duration
   */
  static estimateDuration(
    urlCount: number,
    categoriesCount: number,
    methodsCount: number,
    maxConcurrent: number,
    delay: number
  ): number {
    // Rough estimation: ~100ms per test + network overhead
    const testsPerUrl = categoriesCount * 10 * methodsCount; // Assume ~10 payloads per category
    const timePerTest = 100; // milliseconds
    const networkOverhead = 50; // milliseconds per test

    const totalTests = urlCount * testsPerUrl;
    const timeWithConcurrency = (totalTests * (timePerTest + networkOverhead)) / maxConcurrent;
    const totalDelay = (urlCount - 1) * delay;

    return timeWithConcurrency + totalDelay;
  }
}

/**
 * Export batch results to various formats
 */
export class BatchResultExporter {
  constructor(private results: BatchTestResult[]) {}

  /**
   * Export as JSON
   */
  exportJSON(): string {
    const summary = BatchUtils.generateSummary(this.results);

    return JSON.stringify({
      summary,
      results: this.results,
      exportedAt: new Date().toISOString(),
      version: '1.0.0'
    }, null, 2);
  }

  /**
   * Export as CSV summary
   */
  exportCSV(): string {
    const headers = [
      'URL',
      'Success',
      'Total Tests',
      'Bypassed Tests',
      'Bypass Rate (%)',
      'Duration (ms)',
      'WAF Detected',
      'WAF Type',
      'Error'
    ];

    const csvRows = [
      headers.join(','),
      ...this.results.map(result => [
        `"${result.url}"`,
        result.success,
        result.totalTests,
        result.bypassedTests,
        result.bypassRate,
        result.duration,
        result.wafDetection?.detected || false,
        `"${result.wafDetection?.wafType || ''}"`,
        `"${result.error || ''}"`
      ].join(','))
    ];

    return csvRows.join('\n');
  }

  /**
   * Generate HTML summary report
   */
  generateHTMLSummary(): string {
    const summary = BatchUtils.generateSummary(this.results);

    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Batch WAF Testing Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 20px; text-align: center; }
        .metric-value { font-size: 1.5em; font-weight: bold; color: #007bff; }
        .metric-label { font-size: 0.9em; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .success { color: #198754; }
        .failed { color: #dc3545; }
        .warning { color: #fd7e14; }
    </style>
</head>
<body>
    <h1>Batch WAF Testing Summary</h1>

    <div class="summary-card">
        <h2>Overview</h2>
        <div class="metric">
            <div class="metric-value">${summary.totalUrls}</div>
            <div class="metric-label">Total URLs</div>
        </div>
        <div class="metric">
            <div class="metric-value">${summary.successfulTests}</div>
            <div class="metric-label">Successful</div>
        </div>
        <div class="metric">
            <div class="metric-value">${summary.failedTests}</div>
            <div class="metric-label">Failed</div>
        </div>
        <div class="metric">
            <div class="metric-value">${summary.totalTestCases}</div>
            <div class="metric-label">Total Tests</div>
        </div>
        <div class="metric">
            <div class="metric-value">${summary.averageBypassRate}%</div>
            <div class="metric-label">Avg Bypass Rate</div>
        </div>
    </div>

    ${summary.topVulnerableUrls.length > 0 ? `
    <div class="summary-card">
        <h3>Most Vulnerable URLs</h3>
        <table>
            <thead>
                <tr><th>URL</th><th>Bypass Rate</th></tr>
            </thead>
            <tbody>
                ${summary.topVulnerableUrls.map(url => `
                <tr>
                    <td>${url.url}</td>
                    <td class="${url.bypassRate > 50 ? 'failed' : url.bypassRate > 25 ? 'warning' : 'success'}">${url.bypassRate}%</td>
                </tr>
                `).join('')}
            </tbody>
        </table>
    </div>
    ` : ''}

    <p><em>Generated on ${new Date().toLocaleString()}</em></p>
</body>
</html>
    `;
  }
}
