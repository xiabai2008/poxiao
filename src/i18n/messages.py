"""英文文案目录 (EN catalog) — D13

键为默认语言 (zh_CN) 的原文；值为英文译文。未列出的键在 en 模式下
回退为原文（中文），因此本目录只需增量补充，不要求全量翻译，
且对既有中文输出零破坏。

新增译文：在 ``EN`` 中追加 ``"中文原文": "English text"`` 即可。
"""

from typing import Dict

EN: Dict[str, str] = {
    # ── 通用状态词 (Out) ──────────────────────────────
    "成功": "Success",
    "失败": "Failed",
    "错误": "Error",
    "警告": "Warning",
    "信息": "Info",
    "跳过": "Skipped",
    "完成": "Completed",
    "开始": "Started",
    "用户中断": "Interrupted by user",
    "正在收集 DNS 记录...": "Collecting DNS records...",

    # ── SRC 报告 (src_reporter) 章节 / 字段标签 ────────
    "基本信息": "Basic Information",
    "漏洞类型": "Vulnerability Type",
    "漏洞描述": "Vulnerability Description",
    "复现步骤": "Reproduction Steps",
    "HTTP 证据": "HTTP Evidence",
    "修复建议": "Remediation Suggestion",
    "SRC 报告索引": "SRC Report Index",
    "危害等级": "Severity",
    "风险等级": "Risk Level",
    "危害级别": "Severity Level",
    "漏洞URL": "Vulnerable URL",
    "漏洞链接": "Vulnerability Link",
    "漏洞地址": "Vulnerability URL",

    # ── 严重级别 (severity) ───────────────────────────
    "严重": "Critical",
    "高危": "High",
    "中危": "Medium",
    "低危": "Low",
    "信息": "Info",

    # ── 漏洞类型 (vuln type) ──────────────────────────
    "SQL注入": "SQL Injection",
    "跨站脚本攻击(XSS)": "Cross-Site Scripting (XSS)",
    "命令注入": "Command Injection",
    "文件包含": "File Inclusion",
    "远程代码执行": "Remote Code Execution",
    "服务端请求伪造(SSRF)": "Server-Side Request Forgery (SSRF)",
    "XML外部实体注入(XXE)": "XML External Entity (XXE)",
    "敏感信息泄露": "Sensitive Information Disclosure",
    "跨域配置不当(CORS)": "CORS Misconfiguration",
    "备份文件泄露": "Backup File Disclosure",
    "配置文件泄露": "Configuration File Disclosure",
    "Git信息泄露": "Git Information Disclosure",
    "源代码泄露": "Source Code Disclosure",
    "调试信息泄露": "Debug Information Disclosure",
    "未授权访问": "Unauthorized Access",
    "API信息泄露": "API Information Disclosure",
    "数据库管理入口暴露": "Database Admin Panel Exposure",
    "Swagger/API文档泄露": "Swagger/API Docs Disclosure",
    "Spring Boot Actuator泄露": "Spring Boot Actuator Exposure",
    "phpinfo信息泄露": "phpinfo Disclosure",
    "默认凭据": "Default Credentials",
    "目录遍历": "Directory Listing",
    "缺少安全响应头": "Missing Security Headers",

    # ── HTML 报告 (html_report) ───────────────────────
    "破晓 · 扫描报告": "PoXiao · Scan Report",
    "生成时间": "Generated",
    "目标": "Target",
    "状态": "Status",
    "技术栈": "Tech Stack",
    "敏感路径": "Sensitive Paths",
    "CVE": "CVE",
    "风险": "Risk",
    "无目标数据": "No target data",
    "存活": "Alive",
    "不可达": "Unreachable",

    # ── SRC 报告自由文本（D13 延伸）───────────────────
    # 标题（_finding_title）
    "Git 仓库信息泄露": "Git Repository Information Disclosure",
    "配置文件可访问": "Configuration File Accessible",
    "备份文件泄露": "Backup File Disclosure",
    "调试信息泄露": "Debug Information Disclosure",
    "后台管理页面暴露": "Admin Panel Exposed",
    "API 接口信息泄露": "API Endpoint Information Disclosure",
    "源代码泄露": "Source Code Disclosure",
    "数据库管理入口暴露": "Database Admin Panel Exposed",
    "Swagger/API文档泄露": "Swagger/API Docs Disclosure",
    "Spring Boot Actuator信息泄露": "Spring Boot Actuator Information Disclosure",
    "phpinfo信息泄露": "phpinfo Information Disclosure",
    "默认凭据登录": "Default Credentials Login",
    "SQL注入漏洞": "SQL Injection Vulnerability",
    "CORS跨域配置不当": "CORS Misconfiguration",
    "敏感信息泄露 ({})": "Sensitive Information Disclosure ({})",
    "安全响应头": "Security Headers",

    # 自由文本描述（_finding_description，{0}=target_url, {1}=path_url）
    "目标站点 {0} 的 {1} 可被外部访问，存在 Git 版本控制信息泄露风险。攻击者可利用此漏洞下载完整源代码、历史提交记录及可能包含的数据库密码、API密钥等敏感配置信息。":
        "The {0} path {1} on the target site is externally accessible, posing a Git version control information disclosure risk. Attackers can exploit this to download the complete source code, commit history, and possibly sensitive configuration such as database passwords and API keys.",
    "目标站点 {0} 的 {1} 存在配置文件泄露风险。配置文件可能包含数据库连接信息、API密钥、云服务凭证等敏感数据，可被攻击者直接利用进行进一步入侵。":
        "The {0} path {1} on the target site has a configuration file disclosure risk. The configuration file may contain sensitive data such as database connection strings, API keys, and cloud service credentials, which attackers can directly exploit for further intrusion.",
    "目标站点 {0} 的 {1} 可能存在备份文件。备份文件可能包含源代码、数据库转储或配置文件，攻击者可下载后分析获取敏感信息。":
        "The {0} path {1} on the target site may contain backup files. Backup files may include source code, database dumps, or configuration files, which attackers can download and analyze to obtain sensitive information.",
    "目标站点 {0} 的 {1} 暴露了后台管理页面。攻击者可利用该页面进行暴力破解、默认凭据尝试或直接访问管理功能。":
        "The {0} path {1} on the target site exposes an admin management page. Attackers can use this page to perform brute-force attacks, attempt default credentials, or directly access management functions.",
    "目标站点 {0} 的 {1} 存在调试信息泄露。调试页面可能泄露服务器配置、环境变量、数据库连接等敏感信息。":
        "The {0} path {1} on the target site has a debug information disclosure. The debug page may leak sensitive information such as server configuration, environment variables, and database connections.",
    "目标站点 {0} 的 {1} 暴露了 API 接口文档。攻击者可获取完整接口列表，发现未授权访问接口或参数注入点。":
        "The {0} path {1} on the target site exposes API endpoint documentation. Attackers can obtain the complete endpoint list and discover unauthorized-access interfaces or parameter injection points.",
    "目标站点 {0} 的 {1} 暴露了数据库管理工具入口。攻击者可能通过默认凭据或漏洞直接操作数据库。":
        "The {0} path {1} on the target site exposes a database administration tool entry point. Attackers may directly operate the database through default credentials or vulnerabilities.",
    "目标站点 {0} 的 {1} 存在源代码泄露风险。攻击者可获取服务器端源代码，分析业务逻辑发现更多安全漏洞。":
        "The {0} path {1} on the target site has a source code disclosure risk. Attackers can obtain the server-side source code and analyze the business logic to discover more security vulnerabilities.",
    "目标站点 {0} 的 {1} 暴露了 Swagger/OpenAPI 文档。文档包含完整的 API 接口定义、参数说明和数据模型，攻击者可据此发现未授权接口或参数注入点。":
        "The {0} path {1} on the target site exposes Swagger/OpenAPI documentation. The documentation contains complete API interface definitions, parameter descriptions, and data models, which attackers can use to discover unauthorized interfaces or parameter injection points.",
    "目标站点 {0} 的 {1} 暴露了 Spring Boot Actuator 端点。Actuator 端点可能泄露环境变量（含数据库密码、API密钥）、堆转储、配置信息等敏感数据。":
        "The {0} path {1} on the target site exposes Spring Boot Actuator endpoints. Actuator endpoints may leak sensitive data such as environment variables (including database passwords and API keys), heap dumps, and configuration information.",
    "目标站点 {0} 的 {1} 暴露了 phpinfo() 页面。该页面泄露 PHP 版本、服务器配置、环境变量、已加载扩展等信息，攻击者可据此构造针对性攻击。":
        "The {0} path {1} on the target site exposes a phpinfo() page. This page leaks information such as the PHP version, server configuration, environment variables, and loaded extensions, which attackers can use to craft targeted attacks.",
    "目标站点 {0} 的 {1} 存在默认凭据登录漏洞。攻击者可使用默认用户名和密码直接登录系统，获取管理权限。":
        "The {0} path {1} on the target site has a default credentials login vulnerability. Attackers can use default usernames and passwords to log in directly and obtain administrative privileges.",
    "目标站点 {0} 的 {1} 开启了目录遍历功能。攻击者可浏览目录结构，发现敏感文件（配置文件、备份文件、源代码等）。":
        "The {0} path {1} on the target site has directory listing enabled. Attackers can browse the directory structure and discover sensitive files (configuration files, backup files, source code, etc.).",
    "目标站点 {0} 缺少安全响应头。缺少安全头部可能导致点击劫持、MIME 嗅探、XSS 等安全风险。":
        "The {0} target site is missing security response headers. Missing security headers may lead to security risks such as clickjacking, MIME sniffing, and XSS.",
    "目标站点 {0} 的 {1} 存在 SQL 注入漏洞。攻击者可通过构造恶意 SQL 语句获取、篡改或删除数据库数据，甚至获取服务器权限。":
        "The {0} path {1} on the target site has a SQL Injection vulnerability. Attackers can craft malicious SQL statements to read, modify, or delete database data, and even obtain server privileges.",
    "目标站点 {0} 的 {1} 存在跨站脚本攻击(XSS)漏洞。攻击者可注入恶意脚本，窃取用户 Cookie、会话令牌或执行钓鱼攻击。":
        "The {0} path {1} on the target site has a Cross-Site Scripting (XSS) vulnerability. Attackers can inject malicious scripts to steal user cookies, session tokens, or perform phishing attacks.",
    "目标站点 {0} 的 {1} 存在服务端请求伪造(SSRF)漏洞。攻击者可利用该漏洞访问内网资源、云元数据服务或进行端口扫描。":
        "The {0} path {1} on the target site has a Server-Side Request Forgery (SSRF) vulnerability. Attackers can exploit this to access internal network resources, cloud metadata services, or perform port scanning.",
    "目标站点 {0} 的 {1} 存在 CORS 跨域配置不当问题。攻击者可从恶意网站发起跨域请求，窃取用户数据。":
        "The {0} path {1} on the target site has a CORS misconfiguration issue. Attackers can launch cross-origin requests from malicious websites to steal user data.",
    "目标站点 {0} 的 {1} 存在信息泄露风险。":
        "The {0} path {1} on the target site poses an information disclosure risk.",

    # 复现步骤（_finding_steps，{0}=path_url, {1}=base_url）
    "访问 {0}（或 {1}/.git/HEAD），确认返回 200 状态码":
        "Access {0} (or {1}/.git/HEAD) and confirm a 200 status code is returned",
    "访问 {0}/.git/config，获取 Git 配置信息":
        "Access {0}/.git/config to obtain Git configuration information",
    "使用 GitHack 等工具下载源码：GitHack.py {0}/.git/":
        "Use tools such as GitHack to download the source code: GitHack.py {0}/.git/",
    "访问 {0}，确认返回 200 状态码":
        "Access {0} and confirm a 200 status code is returned",
    "下载备份文件，检查文件内容":
        "Download the backup file and inspect its contents",
    "确认文件包含敏感信息（数据库配置、源码等）":
        "Confirm the file contains sensitive information (database config, source code, etc.)",
    "访问 {0}，确认返回 Swagger/OpenAPI 文档":
        "Access {0} and confirm the Swagger/OpenAPI documentation is returned",
    "查看 API 接口列表，记录敏感接口":
        "Review the API endpoint list and record sensitive endpoints",
    "测试接口是否可未授权访问":
        "Test whether the endpoints can be accessed without authorization",
    "访问 {0}，确认返回 API 文档或接口信息":
        "Access {0} and confirm the API documentation or endpoint information is returned",
    "查看接口列表，记录敏感接口":
        "Review the endpoint list and record sensitive endpoints",
    "访问 {0} 登录页面":
        "Access the {0} login page",
    "使用默认凭据 {username}:{password} 尝试登录":
        "Attempt to log in using default credentials {username}:{password}",
    "确认登录成功，获取后台访问权限":
        "Confirm successful login and obtain backend access",
    "访问 {0}，确认返回目录列表页面":
        "Access {0} and confirm a directory listing page is returned",
    "浏览目录结构，记录敏感文件":
        "Browse the directory structure and record sensitive files",
    "尝试访问敏感文件确认可读取":
        "Attempt to access sensitive files to confirm they are readable",
    "访问 {0}，确认返回配置文件内容":
        "Access {0} and confirm the configuration file content is returned",
    "检查配置文件中的敏感信息（数据库连接、API Key 等）":
        "Inspect sensitive information in the configuration file (database connections, API keys, etc.)",
    "确认信息可被利用":
        "Confirm the information can be exploited",
    "访问 {0}/actuator，确认返回 Actuator 端点列表":
        "Access {0}/actuator and confirm the Actuator endpoint list is returned",
    "访问 {0}/actuator/env，获取环境变量":
        "Access {0}/actuator/env to obtain environment variables",
    "访问 {0}/actuator/heapdump，下载堆转储分析敏感信息":
        "Access {0}/actuator/heapdump to download the heap dump and analyze sensitive information",
    "访问 {0}，确认返回 phpinfo() 或调试信息页面":
        "Access {0} and confirm a phpinfo() or debug information page is returned",
    "记录 PHP 版本、服务器配置、环境变量":
        "Record the PHP version, server configuration, and environment variables",
    "检查是否包含敏感信息（数据库密码、API Key 等）":
        "Check whether it contains sensitive information (database passwords, API keys, etc.)",
    "访问 {0}，确认返回 phpinfo() 页面":
        "Access {0} and confirm a phpinfo() page is returned",
    "访问 {0}，注入单引号 ' 观察响应":
        "Access {0}, inject a single quote ' and observe the response",
    "使用 SQLMap 验证：sqlmap -u \"{0}\" --batch":
        "Verify with SQLMap: sqlmap -u \"{0}\" --batch",
    "确认可注入，获取数据库信息":
        "Confirm injectability and obtain database information",
    "访问 {0}，注入 payload: <script>alert(1)</script>":
        "Access {0}, inject the payload: <script>alert(1)</script>",
    "确认 payload 被反射/存储":
        "Confirm the payload is reflected/stored",
    "在浏览器中触发弹窗验证":
        "Trigger the alert in a browser to verify",
    "访问 {0}，注入内网地址：http://127.0.0.1/":
        "Access {0}, inject the internal address: http://127.0.0.1/",
    "观察响应是否包含内网信息":
        "Observe whether the response contains internal network information",
    "尝试访问云元数据：http://169.254.169.254/":
        "Attempt to access cloud metadata: http://169.254.169.254/",
    "使用 curl 发送请求，设置 Origin: https://evil.com":
        "Send a request with curl, setting Origin: https://evil.com",
    "检查响应头 Access-Control-Allow-Origin 是否为 *":
        "Check whether the Access-Control-Allow-Origin response header is *",
    "确认 Access-Control-Allow-Credentials: true":
        "Confirm Access-Control-Allow-Credentials: true",
    "使用 curl -I {0} 检查响应头":
        "Use curl -I {0} to inspect the response headers",
    "确认 {0} 缺失":
        "Confirm {0} is missing",
    "说明缺失该头部的安全风险":
        "Explain the security risk of the missing header",
    "访问 {0}，确认管理后台页面可访问":
        "Access {0} and confirm the admin backend page is accessible",
    "记录页面信息（框架、版本等）":
        "Record page information (framework, version, etc.)",
    "尝试默认凭据或暴力破解登录":
        "Attempt default credentials or brute-force login",
    "访问 {0}，确认数据库管理工具可访问":
        "Access {0} and confirm the database admin tool is accessible",
    "记录工具类型和版本信息":
        "Record the tool type and version information",
    "尝试默认凭据登录（如 root:root、admin:admin）":
        "Attempt default credentials login (e.g. root:root, admin:admin)",
    "访问 {0}，确认返回源代码文件":
        "Access {0} and confirm a source code file is returned",
    "检查文件内容，确认包含业务逻辑代码":
        "Inspect the file content and confirm it contains business logic code",
    "分析代码中的硬编码密钥、注释信息等":
        "Analyze hardcoded keys, comments, and other information in the code",
    "使用浏览器访问 {0}":
        "Access {0} using a browser",
    "观察到页面返回了敏感信息/配置/管理功能":
        "Observe that the page returns sensitive information, configuration, or management functions",
    "截图保存证据":
        "Take a screenshot to preserve evidence",

    # 修复建议（_default_suggestion，多行）
    "1. 从生产环境删除 .git 目录\n2. 在 Web 服务器配置中禁止访问 .git 路径（Nginx: location ~ /\\.git { deny all; }）\n3. 部署时使用 `git archive` 导出而非直接 clone\n4. 在 .gitignore 中排除敏感配置文件":
        "1. Remove the .git directory from the production environment\n2. Block access to .git paths in the web server config (Nginx: location ~ /\\.git { deny all; })\n3. Use `git archive` to export when deploying instead of a direct clone\n4. Exclude sensitive config files in .gitignore",
    "1. 将配置文件移至 Web 根目录之外\n2. 配置 Web 服务器禁止访问 .env / .config / .yaml 等文件\n3. 敏感配置使用环境变量或密钥管理服务\n4. 定期检查并清理残留配置文件":
        "1. Move config files outside the web root\n2. Configure the web server to block access to .env / .config / .yaml and similar files\n3. Store sensitive config via environment variables or a secret manager\n4. Periodically inspect and clean up leftover config files",
    "1. 立即删除 Web 目录下的备份文件\n2. 配置服务器禁止访问 .bak / .zip / .tar / .sql 等文件\n3. 备份文件存储在非 Web 可访问的目录\n4. 定期清理临时文件和历史备份":
        "1. Immediately delete backup files under the web directory\n2. Configure the server to block access to .bak / .zip / .tar / .sql and similar files\n3. Store backup files in a directory not accessible via the web\n4. Periodically clean up temporary and historical backups",
    "1. 在生产环境禁用 Swagger UI 和 API 文档端点\n2. 如需保留，添加 IP 白名单或认证机制\n3. 配置 Spring Boot: springdoc.api-docs.enabled=false\n4. 使用 Nginx 屏蔽 /swagger-ui.html、/v2/api-docs 等路径":
        "1. Disable Swagger UI and API doc endpoints in production\n2. If retention is needed, add an IP allowlist or authentication\n3. Configure Spring Boot: springdoc.api-docs.enabled=false\n4. Use Nginx to block paths such as /swagger-ui.html and /v2/api-docs",
    "1. 在生产环境关闭 API 文档自动生成\n2. 对 API 接口添加认证和授权机制\n3. 限制 API 接口的访问权限\n4. 使用 API 网关统一管理接口访问":
        "1. Disable automatic API doc generation in production\n2. Add authentication and authorization to API endpoints\n3. Restrict access permissions for API endpoints\n4. Use an API gateway to centrally manage endpoint access",
    "1. 立即修改所有默认密码\n2. 实施密码策略：最小长度、复杂度要求\n3. 启用双因素认证(2FA)\n4. 限制登录尝试次数，防止暴力破解\n5. 修改默认用户名，避免使用 admin/root":
        "1. Immediately change all default passwords\n2. Enforce a password policy: minimum length and complexity\n3. Enable two-factor authentication (2FA)\n4. Limit login attempts to prevent brute-force\n5. Change default usernames, avoid admin/root",
    "1. 在 Web 服务器配置中禁用目录列表\n   Nginx: autoindex off;\n   Apache: Options -Indexes\n2. 为每个目录添加默认首页文件（index.html）\n3. 将敏感文件移至 Web 根目录之外":
        "1. Disable directory listing in the web server config\n   Nginx: autoindex off;\n   Apache: Options -Indexes\n2. Add a default index file (index.html) for each directory\n3. Move sensitive files outside the web root",
    "1. 对管理后台加强访问控制（IP 白名单 / VPN）\n2. 启用双因素认证(2FA)\n3. 避免使用常见管理路径（/admin、/manager）\n4. 修改默认端口，增加访问门槛":
        "1. Strengthen access control for the admin backend (IP allowlist / VPN)\n2. Enable two-factor authentication (2FA)\n3. Avoid common admin paths (/admin, /manager)\n4. Change the default port to raise the access barrier",
    "1. 在生产环境关闭 debug 模式\n2. 删除测试文件（phpinfo.php / test.php / debug 页面）\n3. 配置 PHP: display_errors = Off\n4. 日志输出到文件而非页面":
        "1. Disable debug mode in production\n2. Delete test files (phpinfo.php / test.php / debug pages)\n3. Configure PHP: display_errors = Off\n4. Output logs to files instead of pages",
    "1. 立即删除服务器上的 phpinfo.php 文件\n2. 在 php.ini 中设置 expose_php = Off\n3. 配置 display_errors = Off，避免泄露路径信息\n4. 定期扫描并清理测试文件":
        "1. Immediately delete the phpinfo.php file on the server\n2. Set expose_php = Off in php.ini\n3. Set display_errors = Off to avoid leaking path information\n4. Periodically scan and clean up test files",
    "1. 限制数据库管理工具的访问 IP\n2. 使用强密码并定期更换\n3. 禁用 phpMyAdmin / Adminer 等工具的远程访问\n4. 将管理工具部署在内网，通过 VPN 访问":
        "1. Restrict access IPs for database admin tools\n2. Use strong passwords and rotate them regularly\n3. Disable remote access to tools such as phpMyAdmin / Adminer\n4. Deploy admin tools on the internal network and access via VPN",
    "1. 删除服务器上的编辑器临时文件（.swp / ~ / .bak）\n2. 配置 Web 服务器禁止访问 .swp / ~ / .bak 文件\n3. 使用 .gitignore 排除编辑器临时文件\n4. 部署前检查并清理非必要文件":
        "1. Delete editor temporary files on the server (.swp / ~ / .bak)\n2. Configure the web server to block access to .swp / ~ / .bak files\n3. Use .gitignore to exclude editor temporary files\n4. Inspect and clean up unnecessary files before deployment",
    "1. 限制 Actuator 端点访问，仅暴露必要端点\n   management.endpoints.web.exposure.include=health,info\n2. 为 Actuator 端点添加认证\n   management.endpoints.web.base-path=/management\n3. 使用 Spring Security 限制 /actuator 路径\n4. 在生产环境禁用 /env 和 /heapdump 端点":
        "1. Restrict Actuator endpoint access, exposing only necessary endpoints\n   management.endpoints.web.exposure.include=health,info\n2. Add authentication to Actuator endpoints\n   management.endpoints.web.base-path=/management\n3. Use Spring Security to restrict the /actuator path\n4. Disable /env and /heapdump endpoints in production",
    "1. 使用参数化查询（PreparedStatement）替代字符串拼接\n2. 对用户输入进行严格的输入验证和过滤\n3. 部署 WAF（Web 应用防火墙）拦截 SQL 注入攻击\n4. 使用 ORM 框架减少手动 SQL 编写\n5. 遵循最小权限原则配置数据库用户":
        "1. Use parameterized queries (PreparedStatement) instead of string concatenation\n2. Apply strict input validation and filtering on user input\n3. Deploy a WAF to block SQL injection attacks\n4. Use an ORM framework to reduce manual SQL\n5. Follow the least-privilege principle for database users",
    "1. 对所有用户输入进行输出编码（HTML / JS / URL 编码）\n2. 添加 Content-Security-Policy (CSP) 响应头\n3. 设置 HttpOnly 标记保护 Cookie\n4. 使用模板引擎的自动转义功能\n5. 对用户输入进行严格的白名单验证":
        "1. Encode all user input on output (HTML / JS / URL encoding)\n2. Add the Content-Security-Policy (CSP) response header\n3. Set the HttpOnly flag to protect cookies\n4. Use the auto-escaping feature of the template engine\n5. Apply strict allowlist validation to user input",
    "1. 对用户可控的 URL 进行白名单验证\n2. 禁止请求内网地址（10.x / 172.16-31.x / 192.168.x）\n3. 禁止访问云元数据地址（169.254.169.254）\n4. 限制请求协议（仅允许 http/https）\n5. 使用 DNS 解析验证目标地址":
        "1. Apply allowlist validation to user-controlled URLs\n2. Block requests to internal addresses (10.x / 172.16-31.x / 192.168.x)\n3. Block access to cloud metadata addresses (169.254.169.254)\n4. Restrict request protocols (http/https only)\n5. Use DNS resolution to verify the target address",
    "1. 限制 Access-Control-Allow-Origin 为可信域名，不使用通配符 *\n2. 不要同时设置 Origin: * 和 Credentials: true\n3. 限制允许的 HTTP 方法（Access-Control-Allow-Methods）\n4. 定期审查 CORS 配置":
        "1. Restrict Access-Control-Allow-Origin to trusted domains, do not use the wildcard *\n2. Do not set both Origin: * and Credentials: true\n3. Restrict allowed HTTP methods (Access-Control-Allow-Methods)\n4. Periodically review the CORS configuration",
    "1. 添加缺失的安全响应头\n   X-Content-Type-Options: nosniff\n   X-Frame-Options: DENY\n   X-XSS-Protection: 1; mode=block\n   Strict-Transport-Security: max-age=31536000\n   Content-Security-Policy: default-src 'self'\n2. 在 Web 服务器或应用框架中统一配置\n3. 使用安全中间件自动添加响应头":
        "1. Add the missing security response headers\n   X-Content-Type-Options: nosniff\n   X-Frame-Options: DENY\n   X-XSS-Protection: 1; mode=block\n   Strict-Transport-Security: max-age=31536000\n   Content-Security-Policy: default-src 'self'\n2. Configure centrally in the web server or application framework\n3. Use security middleware to add response headers automatically",
    "1. 升级相关组件到最新安全版本\n2. 关注官方安全公告及时修复\n3. 如无法升级，使用 WAF 规则临时防护\n4. 评估漏洞影响范围，优先修复高危漏洞":
        "1. Upgrade the affected component to the latest secure version\n2. Monitor official security advisories and patch promptly\n3. If upgrade is not possible, use WAF rules as a temporary mitigation\n4. Assess the vulnerability impact scope and prioritize high-risk fixes",
    "建议联系厂商进行安全加固。":
        "Recommend contacting the vendor for security hardening.",

    # CVE 报告自由文本（generate_from_cve）
    "[{0}] 疑似 {1}: {2}":
        "[{0}] Suspected {1}: {2}",
    "目标使用可能存在 {0} 漏洞的组件。":
        "The target uses a component that may be affected by the {0} vulnerability.",
    "建议验证该漏洞是否可被实际利用。":
        "It is recommended to verify whether the vulnerability can be exploited in practice.",
    "漏洞描述: {0}":
        "Vulnerability description: {0}",
    "使用破晓扫描，识别到目标技术栈可能受此 CVE 影响":
        "Scanned with PoXiao and identified that the target tech stack may be affected by this CVE",
    "手动验证：参考 {0} 公开 PoC 进行复现":
        "Manual verification: reproduce using the public PoC referenced by {0}",
    "记录复现结果（截图/响应内容）":
        "Record the reproduction result (screenshot / response content)",
    "升级受影响的组件版本，参考 {0} 公告中的修复版本。":
        "Upgrade the affected component version, referring to the fixed version in the {0} advisory.",
}
