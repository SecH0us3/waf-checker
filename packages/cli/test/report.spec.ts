import { describe, it, expect, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { deduceFormat, writeReport } from '../src/report';

vi.mock('fs', async () => {
	const actual = await vi.importActual<typeof import('fs')>('fs');
	return {
		...actual,
		writeFileSync: vi.fn(),
		mkdirSync: vi.fn(),
		existsSync: vi.fn((p) => {
			if (p === 'existing-dir') return true;
			return false;
		})
	};
});

describe('Report Module', () => {
	describe('deduceFormat', () => {
		it('should deduce json format from extension', () => {
			expect(deduceFormat('test.json')).toBe('json');
			expect(deduceFormat('path/to/test.JSON')).toBe('json');
		});

		it('should deduce csv format from extension', () => {
			expect(deduceFormat('test.csv')).toBe('csv');
			expect(deduceFormat('test.CSV')).toBe('csv');
		});

		it('should deduce html format from extension', () => {
			expect(deduceFormat('test.html')).toBe('html');
			expect(deduceFormat('test.htm')).toBe('html');
		});

		it('should default to html for unknown extensions', () => {
			expect(deduceFormat('test.txt')).toBe('html');
			expect(deduceFormat('test')).toBe('html');
		});
	});

	describe('writeReport', () => {
		const checkResults = [
			{ status: 403, method: 'GET', payload: 'test-sql', responseTime: 100, category: 'SQL Injection' },
			{ status: 200, method: 'POST', payload: 'test-xss', responseTime: 120, category: 'XSS', is_redirect: false }
		];

		const batchResults = [
			{ url: 'https://example.com', success: true, total: 10, blocked: 9, bypassed: 1, bypassRate: 10 },
			{ url: 'https://google.com', success: false, total: 0, blocked: 0, bypassed: 0, bypassRate: 0, error: 'Connection failure' }
		];

		it('should write JSON check reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.json', 'json', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.json', expect.stringContaining('"status": 403'), 'utf8');
		});

		it('should write CSV check reports with headers', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.csv', 'csv', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.csv', expect.stringContaining('Category,Method,Status'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.csv', expect.stringContaining('SQL Injection,GET,403'), 'utf8');
		});

		it('should write HTML check reports with styling and content', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('report.html', 'html', 'check', 'https://example.com', checkResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.html', expect.stringContaining('<!DOCTYPE html>'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.html', expect.stringContaining('WAF Audit Report'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('report.html', expect.stringContaining('test-sql'), 'utf8');
		});

		it('should write CSV batch reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('batch.csv', 'csv', 'batch', 'targets.txt', batchResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.csv', expect.stringContaining('Target URL,Success,Total Tests'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.csv', expect.stringContaining('https://example.com,Yes,10'), 'utf8');
		});

		it('should write HTML batch reports', () => {
			vi.mocked(fs.writeFileSync).mockClear();
			writeReport('batch.html', 'html', 'batch', 'targets.txt', batchResults);
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.html', expect.stringContaining('WAF Batch Audit Report'), 'utf8');
			expect(fs.writeFileSync).toHaveBeenCalledWith('batch.html', expect.stringContaining('Connection failure'), 'utf8');
		});

		it('should create directories if they do not exist', () => {
			vi.mocked(fs.existsSync).mockReturnValue(false);
			vi.mocked(fs.mkdirSync).mockClear();

			writeReport('new-dir/report.json', 'json', 'check', 'https://example.com', checkResults);

			expect(fs.mkdirSync).toHaveBeenCalledWith('new-dir', { recursive: true });
		});
	});
});
