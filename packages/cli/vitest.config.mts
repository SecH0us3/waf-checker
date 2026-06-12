import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
	test: {
		environment: 'node',
		alias: {
			'@waf-checker/core': resolve(__dirname, '../core/src/index.ts'),
		},
	},
});
