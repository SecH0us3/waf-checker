import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: resolve(__dirname, 'wrangler.toml') },
		})
	],
	test: {
		// Runtime tests only. Static front-end asset checks run in a Node project
		// (vitest.ui.config.mts) because they need node:fs, which the workers pool lacks.
		include: ['test/**/*.{test,spec}.{ts,mts,js,mjs}'],
	},
});
