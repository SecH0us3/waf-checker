/**
 * Heuristic pattern definitions and inspection field detectors for WAF virtual patching.
 */

export interface CategoryHeuristic {
	pattern: string;
	description: string;
	defaultLocation: 'query' | 'body' | 'header' | 'uri';
}

export const CATEGORY_HEURISTICS: Record<string, CategoryHeuristic> = {
	'SQL Injection': {
		pattern: `(?i)(?:\\b(?:union\\s+(?:all\\s+)?select|select\\s+.*\\bfrom|insert\\s+into|delete\\s+from|drop\\s+table|update\\s+.*\\bset)\\b|\\bexec(?:ute)?\\s*\\(|'\\s*(?:or|and)\\s+['\\d]=['\\d]|--\\s*$|;\\s*--)`,
		description: 'Detects SQL statement keywords, Boolean-based OR/AND injections, and SQL comment terminations',
		defaultLocation: 'query',
	},
	'XSS': {
		pattern: `(?i)(?:<script[^>]*>|javascript\\s*:|\\bon(?:error|load|click|mouseover|focus|blur)\\s*=|alert\\s*\\(|document\\.(?:cookie|location|domain)|eval\\s*\\()`,
		description: 'Detects script tags, inline event handlers, javascript: pseudo-protocol, and DOM sinks',
		defaultLocation: 'query',
	},
	'Command Injection': {
		pattern: `(?:;|\\||&&|\\n|\\x60|\\$\\()\\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|powershell|cmd|nc|python|perl|echo)\\b`,
		description: 'Detects OS command separators followed by system execution binaries and interpreters',
		defaultLocation: 'query',
	},
	'Path Traversal': {
		pattern: `(?:\\.\\.[\\/\\\\]){2,}|(?:%2e%2e[%2f%5c]){2,}|[\\/\\\\]etc[\\/\\\\](?:passwd|shadow|hosts)|[\\/\\\\](?:boot\\.ini|win\\.ini|windows[\\/\\\\]system32)`,
		description: 'Detects recursive directory traversal sequences and references to critical OS configuration files',
		defaultLocation: 'uri',
	},
	'Local File Inclusion': {
		pattern: `(?:(?:file|gopher|php|data|zip):\\/\\/|php:\\/\\/(?:filter|input)|\\.\\.[\\/\\\\]|\\/etc\\/passwd)`,
		description: 'Detects PHP wrappers and file inclusion schemes',
		defaultLocation: 'query',
	},
	'SSRF': {
		pattern: `(?i)(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1|0\\.0\\.0\\.0|localhost|\\[::1\\]|instance-data|fd00:)`,
		description: 'Detects loopback IPs, IPv6 addresses, and cloud metadata service endpoints (AWS, GCP, Azure)',
		defaultLocation: 'query',
	},
	'SSTI': {
		pattern: '(?:\\{\\{.*?\\}\\}|\\${.*?\\}|<%.*?%>|\\[\\[.*?\\]\\]|T\\(java\\.lang\\.Runtime\\)|#\\{.*?\\})',
		description: 'Detects template expression brackets (Jinja2, Twig, SpEL, FreeMarker, Ruby ERB)',
		defaultLocation: 'query',
	},
	'XXE': {
		pattern: `(?i)(?:<!ENTITY|SYSTEM\\s+["'](?:file|http|https):|<!DOCTYPE[^>]*\\[|PUBLIC\\s+["'])`,
		description: 'Detects XML DTD external entity declarations and system file references',
		defaultLocation: 'body',
	},
	'NoSQL Injection': {
		pattern: `(?:\\$where|\\$regex|\\$gt|\\$ne|\\$in|\\$nin|\\$or|\\$and|\\$exists|tojson|mongodb)`,
		description: 'Detects MongoDB query operators and JavaScript injection sequences in JSON/BSON',
		defaultLocation: 'query',
	},
	'GraphQL Injection': {
		pattern: `(?i)(?:__schema|__type|__typename|introspectionquery|mutation.*?\\{.*?\\})`,
		description: 'Detects GraphQL introspection probes and unauthorized nested mutations',
		defaultLocation: 'body',
	},
	'JWT Attack (Header)': {
		pattern: `(?i)(?:"alg"\\s*:\\s*"none"|"jwk"\\s*:|"jku"\\s*:|"kid"\\s*:\\s*".*?\\.\\.")`,
		description: 'Detects JWT header tampering (alg: none, rogue JWK/JKU URL, and kid path traversal)',
		defaultLocation: 'header',
	},
	'JWT Attack (Param)': {
		pattern: `(?i)(?:eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.(?:|none|AA)|"alg"\\s*:\\s*"none")`,
		description: 'Detects unsecured JWT tokens with missing signatures or alg=none passed as parameters',
		defaultLocation: 'query',
	},
	'Prototype Pollution (JSON Body)': {
		pattern: `(?i)(?:["']?__proto__["']?\\s*:|["']?constructor["']?\\s*:\\s*\\{\\s*["']?prototype["']?)`,
		description: 'Detects JavaScript prototype pollution keys (__proto__, constructor.prototype) in JSON bodies',
		defaultLocation: 'body',
	},
	'Prototype Pollution (URL/Param)': {
		pattern: `(?i)(?:__proto__\\[|\\[__proto__\\]|constructor\\[prototype\\]|prototype\\[)`,
		description: 'Detects prototype pollution attempts inside URL query parameters and form fields',
		defaultLocation: 'query',
	},
	'LDAP Injection': {
		pattern: `(?:\\*\\)\\(|\\(\\&|\\(\\||\\(\\!)`,
		description: 'Detects LDAP filter boolean manipulation and parentheses breakout sequences',
		defaultLocation: 'query',
	},
	'CRLF Injection': {
		pattern: `(?i)(?:%0d%0a|\\r\\n)(?:set-cookie|location|content-type):`,
		description: 'Detects HTTP response splitting and header injection via Carriage Return / Line Feed',
		defaultLocation: 'query',
	},
	'HTTP Parameter Pollution': {
		pattern: `(?i)(?:(?:id|user|username|uid|admin|role|token|redirect|url|file|page|search|query|email|callback)=[^&]*&(?:[^&]*&)*(?:id|user|username|uid|admin|role|token|redirect|url|file|page|search|query|email|callback)=)`,
		description: 'Detects duplicate parameter names in query string designed to cause HTTP parameter pollution (HPP)',
		defaultLocation: 'query',
	},
	'User-Agent': {
		pattern: `(?i)(?:sqlmap|nikto|nmap|acunetix|gobuster|dirbuster|masscan|zgrab)`,
		description: 'Detects well-known automated offensive scanner signatures in the User-Agent header',
		defaultLocation: 'header',
	},
	'IP Bypass': {
		pattern: `(?i)(?:127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|::1)`,
		description: 'Detects spoofed client IP headers attempting to bypass internal IP allowlists',
		defaultLocation: 'header',
	},
	'HTTP Request Smuggling': {
		pattern: `(?i)(?:Transfer-Encoding\\s*:\\s*chunked.*?Content-Length|0\\r\\n\\r\\nGET)`,
		description: 'Detects conflicting Transfer-Encoding and Content-Length headers or chunked desync patterns',
		defaultLocation: 'header',
	},
	'Web Cache Poisoning': {
		pattern: `(?i)(?:x-forwarded-host|x-host|x-forwarded-scheme|x-original-url):`,
		description: 'Detects unkeyed cache poison headers containing untrusted origin overrides',
		defaultLocation: 'header',
	},
	'UTF8/Unicode Bypass': {
		pattern: `(?:%u[0-9a-fA-F]{4}|%c0%[a-zA-Z0-9]{2}|%e0%[a-zA-Z0-9]{2}%[a-zA-Z0-9]{2})`,
		description: 'Detects overlong UTF-8 encodings and IIS %u Unicode bypass sequences',
		defaultLocation: 'query',
	},
	'Sensitive Files': {
		pattern: `(?i)(?:\\.(?:env|git|svn|hg|ds_store|bak|old|swp|config|yml|yaml|sql|tar\\.gz|zip)(?:$|[/?#])|/\\.(?:git|env|svn|hg)(?:/|$|\\w))`,
		description: 'Detects path requests probing for exposed source repositories, environment files, and backups',
		defaultLocation: 'uri',
	},
	'Open Redirect': {
		pattern: `(?i)(?:(?:url|next|redirect|return|dest|target)=)(?:https?:|\\/\\/|\\\\\\\\)[^\\s&]+`,
		description: 'Detects unvalidated external redirection destinations in query parameters',
		defaultLocation: 'query',
	},
	'WAF Inspection Limit Bypass (Padding)': {
		pattern: `(?:junk=[a-zA-Z0-9]{1000,}|[a-zA-Z0-9]{8192,})`,
		description: 'Detects oversized padding blocks designed to overflow WAF body inspection buffers',
		defaultLocation: 'body',
	},
};

/**
 * Escapes regex special characters for strict literal matching.
 */
export function escapeRegex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Escapes strings for embedding inside Terraform HCL double-quoted strings.
 * Escapes backslashes, double quotes, and '${' (HCL interpolation syntax).
 */
export function escapeHclString(str: string): string {
	return str
		.replace(/\\/g, '\\\\')
		.replace(/"/g, '\\"')
		.replaceAll('${', () => '$${');
}

/**
 * Escapes strings for embedding inside NGINX configuration double-quoted regexes.
 */
export function escapeNginxString(str: string): string {
	return str.replace(/"/g, '\\"');
}

/**
 * Common sensitive file extensions and paths that should never be exposed or publicly served on web servers.
 * When generating virtual patches, specific filenames (e.g. 'dump.sql', 'db.sql', 'database.sql') are
 * consolidated into generic extension rules (e.g. '.sql') for broader perimeter defense and compact rules.
 */
export const SENSITIVE_EXTENSIONS: readonly string[] = [
	// Compound archive extensions (must precede single extensions)
	'.tar.gz',
	'.tar.bz2',
	'.tar.xz',
	// Databases & dumps
	'.sql',
	'.db',
	'.sqlite',
	'.sqlite3',
	'.dump',
	'.rdb',
	'.mdb',
	'.accdb',
	// Backups & archives
	'.bak',
	'.old',
	'.orig',
	'.backup',
	'.swp',
	'.~',
	'.sav',
	'.save',
	'.copy',
	'.tar',
	'.tgz',
	'.gz',
	'.bz2',
	'.xz',
	'.zip',
	'.rar',
	'.7z',
	// Configs, secrets & environment
	'.env',
	'.ini',
	'.conf',
	'.cfg',
	'.config',
	'.yml',
	'.yaml',
	'.toml',
	// Keys, certificates & keystores
	'.key',
	'.pem',
	'.crt',
	'.cer',
	'.der',
	'.p12',
	'.pfx',
	'.jks',
	'.keystore',
	'.pub',
	// Logs
	'.log',
	// Scripts & executables
	'.sh',
	'.bash',
	'.bat',
	'.cmd',
	'.ps1',
	'.vbs',
	// Source control & metadata
	'.git',
	'.svn',
	'.hg',
	'.ds_store',
	'.htpasswd',
	'.htaccess',
];

/**
 * Cleans and extracts a meaningful literal token from an attack payload for strict matching.
 * For sensitive file checks, consolidates specific filenames (e.g. "dump.sql", "db.sql") into
 * their dangerous file extension (e.g. ".sql") or hidden directory prefix (e.g. ".git").
 */
export function sanitizeStrictToken(payload: string, category?: string): string {
	const trimmed = payload.replace(/[\r\n]+/g, ' ').trim();
	const normalized = trimmed.startsWith('/') ? trimmed.slice(1) : trimmed;

	if (category === 'Sensitive Files' || category === 'Path Traversal') {
		const lower = normalized.toLowerCase();

		// Check hidden VCS / env directory paths first (e.g. .git/config -> .git)
		if (lower.startsWith('.git') || lower.includes('/.git')) return '.git';
		if (lower.startsWith('.env') || lower.includes('/.env')) return '.env';
		if (lower.startsWith('.svn') || lower.includes('/.svn')) return '.svn';
		if (lower.startsWith('.hg') || lower.includes('/.hg')) return '.hg';

		// Check known sensitive extensions (.tar.gz before .gz, .sqlite3 before .sql, etc.)
		for (const ext of SENSITIVE_EXTENSIONS) {
			if (
				lower.endsWith(ext) ||
				lower.includes(`${ext}?`) ||
				lower.includes(`${ext}#`) ||
				lower.includes(`${ext}/`)
			) {
				return ext;
			}
		}
	}

	return trimmed.slice(0, 200);
}

/**
 * Determines whether a payload is targeted for headers, body, query, or uri path.
 */
export function detectInspectionLocation(
	category: string,
	method: string,
	payload: string
): 'query' | 'body' | 'header' | 'uri' {
	const heuristic = CATEGORY_HEURISTICS[category];
	if (category.includes('Header') || category === 'User-Agent' || category === 'IP Bypass') {
		return 'header';
	}
	if (category.includes('JSON Body') || category === 'XXE' || category === 'GraphQL Injection') {
		return 'body';
	}
	if (category === 'Path Traversal' || category === 'Sensitive Files') {
		return 'uri';
	}
	if (method === 'POST' || method === 'PUT') {
		return 'body';
	}
	return heuristic ? heuristic.defaultLocation : 'query';
}
