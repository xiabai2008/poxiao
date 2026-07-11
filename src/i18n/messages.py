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
}
