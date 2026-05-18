#!/usr/bin/env node
import { Command } from 'commander';
import { fetch as undiciFetch, ProxyAgent } from 'undici';
import { WAFDetector } from '@waf-checker/core';

const program = new Command();

program
  .name('waf-checker')
  .description('WAF Efficiency Auditing CLI')
  .version('1.0.0');

function createFetchFn(proxyUrl?: string) {
  if (proxyUrl) {
    const proxyAgent = new ProxyAgent(proxyUrl);
    return function customFetch(url: string | URL | globalThis.Request, init?: globalThis.RequestInit): Promise<globalThis.Response> {
      return undiciFetch(url as any, { ...init, dispatcher: proxyAgent } as any) as any;
    };
  }
  return undiciFetch as any;
}

program
  .command('detect')
  .description('Detect WAF and bypass opportunities for a given URL')
  .argument('<url>', 'URL to analyze')
  .option('--proxy <proxy>', 'Proxy URL (e.g. http://127.0.0.1:8080)')
  .action(async (url, options) => {
    try {
      console.log(`Analyzing ${url}...`);
      if (options.proxy) console.log(`Using proxy: ${options.proxy}`);

      const fetchFn = createFetchFn(options.proxy);

      const detectionResult = await WAFDetector.activeDetection(url, { fetch: fetchFn as any });
      console.log('\n--- Detection Result ---');
      console.log(JSON.stringify(detectionResult, null, 2));

      console.log('\n--- Bypass Opportunities ---');
      const bypassOpportunities = await WAFDetector.detectBypassOpportunities(url, { fetch: fetchFn as any });
      console.log(JSON.stringify(bypassOpportunities, null, 2));

    } catch (error: any) {
      console.error(`Error: ${error.message}`);
    }
  });

program.parse(process.argv);
