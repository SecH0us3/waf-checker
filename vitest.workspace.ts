import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
	'packages/core/vitest.config.mts',
	'packages/worker/vitest.config.mts',
	'packages/cli/vitest.config.mts'
]);
