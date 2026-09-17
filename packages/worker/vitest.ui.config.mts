import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Node-environment project for static front-end asset checks (index.html / main.js /
// style.css). These read files from disk with node:fs, which the Cloudflare workers
// pool used by vitest.config.mts does not provide.
export default defineConfig({
	root: __dirname,
	test: {
		name: 'worker-ui',
		environment: 'node',
		include: ['test-ui/**/*.{test,spec}.{ts,mts,js,mjs}'],
	},
});
