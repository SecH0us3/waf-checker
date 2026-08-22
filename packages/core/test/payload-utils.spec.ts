import { describe, it, expect, vi } from 'vitest';
import { processCustomHeaders, substitutePayload, randomUppercase, redactUrl, redactHeaders } from '../src/utils/payload-utils';

describe('payload-utils', () => {
	describe('processCustomHeaders', () => {
		it('should return empty object for empty or null input', () => {
			expect(processCustomHeaders('')).toEqual({});
			expect(processCustomHeaders('   ')).toEqual({});
			// @ts-ignore
			expect(processCustomHeaders(null)).toEqual({});
		});

		it('should parse single header correctly', () => {
			expect(processCustomHeaders('Content-Type: application/json')).toEqual({
				'Content-Type': 'application/json',
			});
		});

		it('should parse multiple headers with different line endings', () => {
			const input = 'X-Header-1: value1\r\nX-Header-2: value2\nX-Header-3: value3';
			expect(processCustomHeaders(input)).toEqual({
				'X-Header-1': 'value1',
				'X-Header-2': 'value2',
				'X-Header-3': 'value3',
			});
		});

		it('should trim whitespace from names and values', () => {
			expect(processCustomHeaders('  X-Header  :   value   ')).toEqual({
				'X-Header': 'value',
			});
		});

		it('should replace {PAYLOAD} placeholder', () => {
			const input = 'X-Payload: {PAYLOAD}';
			const payload = 'alert(1)';
			expect(processCustomHeaders(input, payload)).toEqual({
				'X-Payload': 'alert(1)',
			});
		});

		it('should replace multiple {PAYLOAD} placeholders in the same value', () => {
			const input = 'X-Double: {PAYLOAD} and {PAYLOAD}';
			const payload = 'test';
			expect(processCustomHeaders(input, payload)).toEqual({
				'X-Double': 'test and test',
			});
		});

		it('should ignore lines without a colon', () => {
			expect(processCustomHeaders('InvalidHeaderLine')).toEqual({});
			expect(processCustomHeaders('Valid: Header\nInvalidLine\nAnother: Valid')).toEqual({
				'Valid': 'Header',
				'Another': 'Valid',
			});
		});

		it('should ignore lines starting with a colon', () => {
			expect(processCustomHeaders(':Value')).toEqual({});
		});
	});

	describe('substitutePayload', () => {
		it('should substitute payload in a string', () => {
			expect(substitutePayload('Hello {PAYLOAD}', 'World')).toBe('Hello World');
		});

		it('should substitute multiple payloads in a string', () => {
			expect(substitutePayload('{PAYLOAD} {PAYLOAD}', 'X')).toBe('X X');
		});

		it('should substitute payload in an array', () => {
			const input = ['{PAYLOAD}', 'normal', '{PAYLOAD}2'];
			expect(substitutePayload(input, 'test')).toEqual(['test', 'normal', 'test2']);
		});

		it('should substitute payload in a nested object', () => {
			const input = {
				key1: '{PAYLOAD}',
				key2: {
					nested: 'prefix-{PAYLOAD}',
				},
				key3: 123,
			};
			const expected = {
				key1: 'val',
				key2: {
					nested: 'prefix-val',
				},
				key3: 123,
			};
			expect(substitutePayload(input, 'val')).toEqual(expected);
		});

		it('should return original value for non-string/object/array', () => {
			expect(substitutePayload(123, 'test')).toBe(123);
			expect(substitutePayload(true, 'test')).toBe(true);
			expect(substitutePayload(null, 'test')).toBe(null);
		});

		it('should prevent prototype pollution', () => {
			const obj = JSON.parse('{"__proto__": {"polluted": "yes"}, "constructor": {"prototype": {"polluted": "yes"}}, "normal": "{PAYLOAD}"}');
			const result = substitutePayload(obj, 'test');

			expect(result.normal).toBe('test');
			expect(Object.prototype.hasOwnProperty.call(result, '__proto__')).toBe(false);
			expect(Object.prototype.hasOwnProperty.call(result, 'constructor')).toBe(false);
			expect(Object.prototype.hasOwnProperty.call(result, 'prototype')).toBe(false);
			// @ts-ignore
			expect({}.polluted).toBeUndefined();
		});
	});

	describe('randomUppercase', () => {
		it('should toggle case for alphabetic characters when Math.random > 0.5', () => {
			const spy = vi.spyOn(Math, 'random');
			// First call > 0.5, second call <= 0.5
			spy.mockReturnValueOnce(0.6).mockReturnValueOnce(0.4);

			// 'a' (index 0) matches [a-zA-Z] and random > 0.5 -> should uppercase
			// 'b' (index 1) matches [a-zA-Z] and random <= 0.5 -> should stay same
			expect(randomUppercase('ab')).toBe('Ab');

			spy.mockRestore();
		});

		it('should handle already uppercased characters', () => {
			const spy = vi.spyOn(Math, 'random').mockReturnValue(0.6);
			// 'A' matches [a-zA-Z] and random > 0.5. Toggles to 'a'.
			expect(randomUppercase('A')).toBe('a');
			spy.mockRestore();
		});

		it('should ignore non-alphabetic characters', () => {
			const spy = vi.spyOn(Math, 'random').mockReturnValue(0.6);
			expect(randomUppercase('123!@#')).toBe('123!@#');
			spy.mockRestore();
		});
	});

	describe('redactUrl', () => {
		it('should redact sensitive query parameters', () => {
			expect(redactUrl('http://example.com/?token=abc&normal=123')).toBe('http://example.com/?token=%5BREDACTED%5D&normal=123');
			expect(redactUrl('http://example.com/?key=123')).toBe('http://example.com/?key=%5BREDACTED%5D');
		});
		it('should redact basic auth password', () => {
			expect(redactUrl('http://user:pass123@example.com/')).toBe('http://user:%5BREDACTED%5D@example.com/');
		});
		it('should handle URLs without sensitive params', () => {
			expect(redactUrl('http://example.com/?id=1')).toBe('http://example.com/?id=1');
		});
		it('should return invalid URLs unchanged', () => {
			expect(redactUrl('not-a-url')).toBe('not-a-url');
		});
	});

	describe('redactHeaders', () => {
		it('should redact sensitive headers', () => {
			const headers = {
				'Authorization': 'Bearer 123',
				'Cookie': 'session=abc',
				'X-Custom': 'val'
			};
			const redacted = redactHeaders(headers);
			expect(redacted['Authorization']).toBe('[REDACTED]');
			expect(redacted['Cookie']).toBe('[REDACTED]');
			expect(redacted['X-Custom']).toBe('val');
		});
		it('should not mutate original headers', () => {
			const headers = { 'Cookie': 'abc' };
			redactHeaders(headers);
			expect(headers['Cookie']).toBe('abc');
		});
	});
});
