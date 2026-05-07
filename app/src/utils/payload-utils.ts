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
 * Helper function to randomly uppercase characters in a string
 */
export function randomUppercase(str: string): string {
	let result = '';
	for (let i = 0; i < str.length; i++) {
		const char = str[i];
		// Randomly uppercase 50% of alphabetic characters
		if (char.match(/[a-zA-Z]/) && Math.random() > 0.5) {
			if (char === char.toLowerCase()) {
				result += char.toUpperCase();
			} else {
				result += char.toLowerCase();
			}
		} else {
			result += char;
		}
	}
	return result;
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
