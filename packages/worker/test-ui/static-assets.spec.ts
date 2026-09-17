import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

/**
 * Regression guards for the results-area UI. These assert the structural
 * decisions made while cleaning up the results header, so future edits don't
 * silently reintroduce the bugs we fixed:
 *   - the remediation banner reappearing (empty) on first load,
 *   - orphaned mode blocks/buttons instead of the inline legend,
 *   - the results filters/search blending into the edge,
 *   - dead CSS/JS left behind.
 *
 * They are plain string/structure checks (no DOM engine) so they stay fast and
 * dependency-free, and run in a Node vitest project (see vitest.ui.config.mts).
 */

const staticDir = resolve(dirname(fileURLToPath(import.meta.url)), '../src/static');
const html = readFileSync(resolve(staticDir, 'index.html'), 'utf8');
const js = readFileSync(resolve(staticDir, 'main.js'), 'utf8');
const css = readFileSync(resolve(staticDir, 'style.css'), 'utf8');

/** Return the opening tag of the element carrying id="<id>". */
function openTag(source: string, id: string): string {
	const idx = source.indexOf(`id="${id}"`);
	expect(idx, `#${id} should exist in index.html`).toBeGreaterThan(-1);
	const start = source.lastIndexOf('<', idx);
	const end = source.indexOf('>', idx);
	return source.slice(start, end + 1);
}

/** Class tokens of an opening tag. */
function classes(tag: string): string[] {
	const m = /class="([^"]*)"/.exec(tag);
	return m ? m[1].split(/\s+/).filter(Boolean) : [];
}

describe('remediation banner visibility', () => {
	const banner = openTag(html, 'virtualPatchBanner');

	it('is hidden by default via inline display:none', () => {
		expect(banner).toMatch(/style="[^"]*display:\s*none/);
	});

	it('does NOT use the d-flex class (which is display:flex !important and overrode the inline none)', () => {
		// This was the root cause of the banner showing empty on first load.
		expect(classes(banner)).not.toContain('d-flex');
		expect(classes(banner)).not.toContain('d-inline-flex');
	});

	it('ships no hardcoded "0 … Detected" text — the scan handler fills it', () => {
		expect(html).toContain('id="virtualPatchBypassCount"></span>');
		expect(html).toContain('id="virtualPatchBannerTitle"></span>');
		// The static markup must not carry the pre-scan bypass copy.
		expect(html).not.toMatch(/WAF Bypass\(es\) Detected!<\/span>/);
	});

	it('is force-hidden on load in initApp', () => {
		expect(js).toMatch(/getElementById\('virtualPatchBanner'\)[\s\S]{0,120}display\s*=\s*'none'/);
	});
});

describe('no JS-toggled element mixes d-flex with inline display:none', () => {
	// General guard for the whole class of bug the banner hit.
	const hiddenTags = [...html.matchAll(/<[^>]*style="[^"]*display:\s*none[^"]*"[^>]*>/gi)].map((m) => m[0]);

	it('finds hidden elements to check', () => {
		expect(hiddenTags.length).toBeGreaterThan(0);
	});

	it.each(hiddenTags)('%s has no flex display utility', (tag) => {
		const cls = classes(tag);
		expect(cls).not.toContain('d-flex');
		expect(cls).not.toContain('d-inline-flex');
	});
});

describe('results container layout', () => {
	it('results area is flush (no p-4 padding) so content aligns under the header line', () => {
		expect(classes(openTag(html, 'resultsContainer'))).not.toContain('p-4');
	});

	it('the sticky header keeps its 1px divider line', () => {
		expect(css).toMatch(/\.middle-header\b[\s\S]*?border-bottom:\s*1px solid var\(--section-border\)/);
	});
});

describe('results header renders the inline mode legend, not orphan blocks', () => {
	it('renderSummary emits the compact legend that opens the security modal', () => {
		expect(js).toContain('results-legend');
		expect(js).toContain("data-bs-target='#securityTestModal'");
		expect(html).toContain('id="securityTestModal"');
	});

	it('the removed standalone Security Test / False Positive blocks are gone', () => {
		expect(js).not.toContain('normal-test-indicator');
		expect(js).not.toContain('false-positive-indicator');
		expect(js).not.toContain('toggleHelp');
	});

	it('dead CSS for the old blocks/help toggle is removed', () => {
		expect(css).not.toContain('.false-positive-indicator');
		expect(css).not.toContain('.normal-test-indicator');
		expect(css).not.toContain('.help-icon');
		expect(css).not.toContain('.help-content');
	});
});

describe('filters/search inset while the table stays full-width', () => {
	it('the summary block (legend + status checkboxes) is inset with px-3', () => {
		expect(js).toContain("<div class='mb-3 px-3'>");
	});

	it('the search toolbar is inset with px-3', () => {
		expect(js).toContain('results-toolbar mb-2 px-3');
	});

	it('the results table itself is full-width (w-100) and not wrapped in horizontal padding', () => {
		expect(js).toContain("class='w-100 results-table-modern'");
	});
});
