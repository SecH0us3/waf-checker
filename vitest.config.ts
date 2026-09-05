import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		projects: [
			'packages/core/vitest.config.mts',
			'packages/worker/vitest.config.mts',
			'packages/cli/vitest.config.mts'
		]
	}
});
