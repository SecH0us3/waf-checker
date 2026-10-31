/**
 * Helper function to substitute payload in JSON template
 */
export function substitutePayload(obj: any, payload: string): any {
	if (typeof obj === 'string') {
		return obj.replace(/\{PAYLOAD\}/g, payload);
	} else if (Array.isArray(obj)) {
		return obj.map((item) => substitutePayload(item, payload));
	} else if (obj && typeof obj === 'object') {
		const result: any = {};
		for (const [key, value] of Object.entries(obj)) {
			if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
			result[key] = substitutePayload(value, payload);
		}
		return result;
	}
	return obj;
}

/**
 * Helper function to parse and process custom headers
 */
export function processCustomHeaders(customHeadersStr: string, payload?: string): Record<string, string> {
	const headersObj: Record<string, string> = {};
	if (!customHeadersStr || !customHeadersStr.trim()) return headersObj;

	for (const line of customHeadersStr.split(/\r?\n/)) {
		const idx = line.indexOf(':');
		if (idx > 0) {
			const name = line.slice(0, idx).trim();
			let value = line.slice(idx + 1).trim();
			// Replace {PAYLOAD} placeholder with actual payload
			if (payload && value.includes('{PAYLOAD}')) {
				value = value.replace(/\{PAYLOAD\}/g, payload);
			}
			headersObj[name] = value;
		}
	}
	return headersObj;
}

/**
 * Deterministic pseudo-random generator seeded from a string (FNV-1a hash
 * feeding mulberry32). The same seed always yields the same sequence, which
 * lets a paged scan randomize a payload identically on every page.
 */
export function seededRandom(seed: string): () => number {
	let state = 0x811c9dc5;
	for (let i = 0; i < seed.length; i++) {
		state = Math.imul(state ^ seed.charCodeAt(i), 0x01000193);
	}
	return () => {
		state = (state + 0x6d2b79f5) | 0;
		let t = Math.imul(state ^ (state >>> 15), 1 | state);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

/**
 * Helper function to randomly uppercase characters in a string
 */
export function randomUppercase(str: string, random: () => number = Math.random): string {
	// Flip the case of each ASCII letter with probability 1/2. `random` is called
	// once per ASCII letter and for nothing else, in order, so a seeded generator
	// yields the same casing as before. Works on code units in a typed array
	// rather than matching a regex and appending per character.
	const n = str.length;
	const units = new Uint16Array(n);
	for (let i = 0; i < n; i++) {
		const code = str.charCodeAt(i);
		const isLetter = (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
		// Randomly uppercase 50% of alphabetic characters
		units[i] = isLetter && random() > 0.5 ? code ^ 0x20 : code;
	}
	let out = '';
	for (let i = 0; i < n; i += 4096) {
		out += String.fromCharCode.apply(null, units.subarray(i, i + 4096) as unknown as number[]);
	}
	return out;
}

/**
 * Redacts sensitive headers from a headers object
 */
export function redactHeaders(headers?: Record<string, string>): Record<string, string> {
	if (!headers) return {};
	const sensitiveHeaders = ['authorization', 'cookie', 'set-cookie'];
	const redacted: Record<string, string> = {};
	for (const [key, value] of Object.entries(headers)) {
		if (sensitiveHeaders.includes(key.toLowerCase())) {
			redacted[key] = '[REDACTED]';
		} else {
			redacted[key] = value;
		}
	}
	return redacted;
}

/**
 * Redacts sensitive query parameters from a URL
 */
export function redactUrl(urlStr: string): string {
	if (!urlStr) return urlStr;
	try {
		// Handle potential {PAYLOAD} placeholders by temporarily replacing them
		const hasPayloadPlaceholder = urlStr.includes('{PAYLOAD}');
		const tempUrlStr = hasPayloadPlaceholder ? urlStr.replace(/\{PAYLOAD\}/g, 'TEMP_PAYLOAD') : urlStr;

		const url = new URL(tempUrlStr);
		const sensitiveParams = ['token', 'key', 'auth', 'api_key', 'apikey', 'secret'];
		let changed = false;

		// Redact Basic Auth credentials
		if (url.password) {
			url.password = '[REDACTED]';
			changed = true;
		}

		const params = new URLSearchParams(url.search);
		params.forEach((value, key) => {
			if (sensitiveParams.some((param) => key.toLowerCase().includes(param))) {
				params.set(key, '[REDACTED]');
				changed = true;
			}
		});

		if (changed) {
			url.search = params.toString();
		}

		let result = url.toString();
		if (hasPayloadPlaceholder) {
			result = result.replace(/TEMP_PAYLOAD/g, '{PAYLOAD}');
		}
		return result;
	} catch {
		return urlStr;
	}
}
