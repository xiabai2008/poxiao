"""CVE 匹配 — 技术栈 + 版本 → 已知漏洞

内置常见中文 CMS 漏洞库 + NVD API 查询接口
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class VulnMatch:
    """漏洞匹配结果"""
    cve_id: str = ""
    component: str = ""       # nginx/php/wordpress/dedecms
    description: str = ""
    severity: str = ""        # CRITICAL/HIGH/MEDIUM/LOW
    cvss_score: float = 0.0
    affected_versions: str = ""
    fixed_version: str = ""
    references: list[str] = None
    match_type: str = "local"  # local/nvd/osv
    cpe: str = ""             # e.g. "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"

    def __post_init__(self):
        if self.references is None:
            self.references = []

    @property
    def is_critical(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH") or self.cvss_score >= 7.0


# ── 内置漏洞库（常见中文 CMS + 基础设施漏洞）─────

BUILTIN_VULNS = [
    # ══════════════════════════════════════════════════════════
    # === Nginx ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "nginx",
        "cve": "CVE-2021-23017",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Nginx DNS resolver 0-day use-after-free",
        "affected": "< 1.20.1",
        "fixed": "1.20.1",
    },
    {
        "component": "nginx",
        "cve": "CVE-2024-24989",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Nginx HTTP/3 request line parsing NULL pointer dereference",
        "affected": "< 1.25.4",
        "fixed": "1.25.4",
    },
    {
        "component": "nginx",
        "cve": "CVE-2019-9511",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Nginx HTTP/2 Data Dribble DoS (window updates flood)",
        "affected": "< 1.17.3",
        "fixed": "1.17.3",
    },
    {
        "component": "nginx",
        "cve": "CVE-2019-9513",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Nginx HTTP/2 Resource Loop DoS (priority flood)",
        "affected": "< 1.17.3",
        "fixed": "1.17.3",
    },
    {
        "component": "nginx",
        "cve": "CVE-2019-9516",
        "severity": "HIGH",
        "cvss": 6.5,
        "description": "Nginx HTTP/2 0-Length Headers Leak DoS",
        "affected": "< 1.17.3",
        "fixed": "1.17.3",
    },
    {
        "component": "nginx",
        "cve": "CVE-2022-41741",
        "severity": "HIGH",
        "cvss": 7.8,
        "description": "Nginx mp4 module memory corruption",
        "affected": "< 1.23.3",
        "fixed": "1.23.3",
    },
    {
        "component": "nginx",
        "cve": "CVE-2023-44487",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "HTTP/2 Rapid Reset Attack (大规模 DoS, 被广泛利用)",
        "affected": "< 1.25.3",
        "fixed": "1.25.3",
    },
    {
        "component": "nginx",
        "cve": "CVE-2022-26945",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Nginx NJS module RCE via crafted request",
        "affected": "< 0.7.11",
        "fixed": "0.7.11",
    },
    # ══════════════════════════════════════════════════════════
    # === Apache ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "apache",
        "cve": "CVE-2021-41773",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache HTTP Server 2.4.49 路径穿越 / RCE (已在实际攻击中利用)",
        "affected": "2.4.49",
        "fixed": "2.4.50",
    },
    {
        "component": "apache",
        "cve": "CVE-2021-42013",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache HTTP Server 2.4.50 路径穿越 (CVE-2021-41773 补丁绕过)",
        "affected": "2.4.50",
        "fixed": "2.4.51",
    },
    {
        "component": "apache",
        "cve": "CVE-2023-25690",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache HTTP Request Smuggling via mod_proxy (HTTP/2)",
        "affected": "< 2.4.56",
        "fixed": "2.4.56",
    },
    {
        "component": "apache",
        "cve": "CVE-2023-27522",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache mod_proxy_uwsgi HTTP response splitting",
        "affected": "< 2.4.56",
        "fixed": "2.4.56",
    },
    {
        "component": "apache",
        "cve": "CVE-2022-22721",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache mod_lua buffer overflow (LimitRequestBody bypass)",
        "affected": "< 2.4.55",
        "fixed": "2.4.55",
    },
    {
        "component": "apache",
        "cve": "CVE-2021-44790",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache mod_lua buffer overflow in multipart parsing",
        "affected": "< 2.4.52",
        "fixed": "2.4.52",
    },
    {
        "component": "apache",
        "cve": "CVE-2022-28330",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache mod_lua read beyond buffer boundary",
        "affected": "< 2.4.55",
        "fixed": "2.4.55",
    },
    {
        "component": "apache",
        "cve": "CVE-2023-31137",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache mod_macro out-of-bounds read",
        "affected": "< 2.4.58",
        "fixed": "2.4.58",
    },
    # ══════════════════════════════════════════════════════════
    # === IIS ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "iis",
        "cve": "CVE-2017-7269",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "IIS 6.0 WebDAV 远程缓冲区溢出 RCE",
        "affected": "IIS 6.0 (Windows Server 2003)",
        "fixed": "已EOL",
    },
    {
        "component": "iis",
        "cve": "CVE-2022-21907",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Windows HTTP.sys RCE (IIS, 蠕虫级漏洞)",
        "affected": "Windows Server 2019/2022",
        "fixed": "KB5009557",
    },
    {
        "component": "iis",
        "cve": "CVE-2021-31166",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Windows HTTP.sys RCE (IIS, 蠕虫级)",
        "affected": "Windows Server 2004/20H2",
        "fixed": "KB5003173",
    },
    {
        "component": "iis",
        "cve": "CVE-2021-26419",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "IIS HTTP Protocol Stack memory leak RCE",
        "affected": "Windows Server 2004/20H2",
        "fixed": "KB5003637",
    },
    # ══════════════════════════════════════════════════════════
    # === PHP ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "php",
        "cve": "CVE-2024-4577",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "PHP CGI Windows 平台参数注入 RCE (已被大规模利用)",
        "affected": "< 8.3.8 / < 8.2.20 / < 8.1.29",
        "fixed": "8.3.8 / 8.2.20 / 8.1.29",
    },
    {
        "component": "php",
        "cve": "CVE-2024-2961",
        "severity": "HIGH",
        "cvss": 8.8,
        "description": "PHP glibc iconv buffer overflow (bypass open_basedir)",
        "affected": "< 8.3.7",
        "fixed": "8.3.7",
    },
    {
        "component": "php",
        "cve": "CVE-2023-3824",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "PHP mb_strimwidth buffer overread → RCE",
        "affected": "< 8.0.30 / < 8.1.22 / < 8.2.8",
        "fixed": "8.0.30 / 8.1.22 / 8.2.8",
    },
    {
        "component": "php",
        "cve": "CVE-2022-31629",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PHP cookie parsing injection (improper escaping)",
        "affected": "< 8.0.25 / < 8.1.12",
        "fixed": "8.0.25 / 8.1.12",
    },
    {
        "component": "php",
        "cve": "CVE-2022-31628",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PHP PDO memory corruption DoS",
        "affected": "< 8.0.25 / < 8.1.12",
        "fixed": "8.0.25 / 8.1.12",
    },
    {
        "component": "php",
        "cve": "CVE-2022-37454",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "PHP sha3() integer overflow → buffer overflow (NIST)",
        "affected": "< 8.0.26 / < 8.1.13",
        "fixed": "8.0.26 / 8.1.13",
    },
    # ══════════════════════════════════════════════════════════
    # === DedeCMS (织梦) ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "dedecms",
        "cve": "CVE-2022-35516",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "DedeCMS 5.7.93~5.7.97 后台登录绕过",
        "affected": "5.7.93 - 5.7.97",
        "fixed": "5.7.98",
    },
    {
        "component": "dedecms",
        "cve": "CVE-2021-45272",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "DedeCMS v5.7.94 后台 SQL 注入 → RCE",
        "affected": "<= 5.7.94",
        "fixed": "5.7.95+",
    },
    {
        "component": "dedecms",
        "cve": "CVE-2018-20129",
        "severity": "HIGH",
        "cvss": 7.2,
        "description": "DedeCMS V5.7 SP2 前台任意文件上传 → getshell",
        "affected": "V5.7 SP2",
        "fixed": "",
    },
    {
        "component": "dedecms",
        "cve": "CVE-2023-48017",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "DedeCMS v5.7.105 后台任意文件写入 RCE",
        "affected": "<= 5.7.105",
        "fixed": "5.7.106",
    },
    {
        "component": "dedecms",
        "cve": "CVE-2022-42899",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "DedeCMS 5.7.93 SQL 注入 getshell",
        "affected": "<= 5.7.93",
        "fixed": "5.7.94",
    },
    # ══════════════════════════════════════════════════════════
    # === ThinkPHP ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "thinkphp",
        "cve": "CVE-2022-47945",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "ThinkPHP 多语言 RCE（无需登录，已被大规模利用）",
        "affected": "< 6.0.14 / < 5.1.42",
        "fixed": "6.0.14 / 5.1.42",
    },
    {
        "component": "thinkphp",
        "cve": "CVE-2018-20062",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "ThinkPHP 5.x 远程代码执行（无需登录）",
        "affected": "< 5.1.31 / 5.0.x < 5.0.23",
        "fixed": "5.1.31 / 5.0.23",
    },
    {
        "component": "thinkphp",
        "cve": "CVE-2019-9082",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "ThinkPHP 5.x 控制器 RCE",
        "affected": "< 5.0.24",
        "fixed": "5.0.24",
    },
    {
        "component": "thinkphp",
        "cve": "CVE-2023-36511",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "ThinkPHP v6.0.13 多语言文件包含 RCE",
        "affected": "<= 6.0.13",
        "fixed": "6.0.14",
    },
    {
        "component": "thinkphp",
        "cve": "CVE-2022-42889",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "ThinkPHP OGNL 表达式注入 (Text4Shell)",
        "affected": "< 6.0.14",
        "fixed": "6.0.14",
    },
    # ══════════════════════════════════════════════════════════
    # === Discuz! ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "discuz",
        "cve": "CVE-2019-13956",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Discuz! ML! v3.4 前台任意代码执行",
        "affected": "ML! v3.4",
        "fixed": "",
    },
    {
        "component": "discuz",
        "cve": "CVE-2018-14729",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Discuz! v1.5~v3.4 后台数据库备份文件名 SQL 注入",
        "affected": "1.5 - 3.4",
        "fixed": "",
    },
    {
        "component": "discuz",
        "cve": "CVE-2023-35943",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Discuz! X3.4 SSRF via proxy utility",
        "affected": "<= X3.4",
        "fixed": "",
    },
    {
        "component": "discuz",
        "cve": "CVE-2022-42898",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Discuz! X3.4 后台 SSRF via flash 模块",
        "affected": "<= X3.4",
        "fixed": "",
    },
    # ══════════════════════════════════════════════════════════
    # === WordPress ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "wordpress",
        "cve": "CVE-2024-4439",
        "severity": "MEDIUM",
        "cvss": 6.4,
        "description": "WordPress Core < 6.5.2 存储型 XSS (Avatar)",
        "affected": "< 6.5.2",
        "fixed": "6.5.2",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2023-32243",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Essential Addons for Elementor RCE (WP plugin)",
        "affected": "< 5.8.5",
        "fixed": "5.8.5",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2022-21661",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WordPress Core WP_Query SQL 注入",
        "affected": "< 5.8.3",
        "fixed": "5.8.3",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2022-0739",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "BookingPress WP plugin unauthenticated SQL injection",
        "affected": "< 1.0.11",
        "fixed": "1.0.11",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2021-24364",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "WP Duplicator plugin SSRF (unauthenticated)",
        "affected": "< 1.3.28",
        "fixed": "1.3.28",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2020-25213",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "WP File Manager plugin RCE (远程代码执行, 已被大规模利用)",
        "affected": "< 6.9",
        "fixed": "6.9",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2019-6977",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WP GDPR Compliance plugin SQL injection",
        "affected": "< 1.4.3",
        "fixed": "1.4.3",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2018-6389",
        "severity": "MEDIUM",
        "cvss": 7.5,
        "description": "WordPress Zero-day DoS via load-scripts.php (未认证)",
        "affected": "< 4.9.2",
        "fixed": "4.9.2",
    },
    # ══════════════════════════════════════════════════════════
    # === Drupal ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "drupal",
        "cve": "CVE-2018-7600",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Drupalgeddon 2 — Drupal RCE (未认证, 已被大规模利用)",
        "affected": "< 7.58 / < 8.5.1",
        "fixed": "7.58 / 8.5.1",
    },
    {
        "component": "drupal",
        "cve": "CVE-2018-7602",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Drupalgeddon 3 — Drupal RCE (已认证, 二次注入)",
        "affected": "< 7.59 / < 8.5.3",
        "fixed": "7.59 / 8.5.3",
    },
    {
        "component": "drupal",
        "cve": "CVE-2019-6341",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Drupal phar stream wrapper deserialization RCE",
        "affected": "< 8.5.8",
        "fixed": "8.5.8",
    },
    {
        "component": "drupal",
        "cve": "CVE-2020-13671",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Drupal file upload RCE via double extension (.php.png)",
        "affected": "< 9.0.8 / < 8.9.9",
        "fixed": "9.0.8 / 8.9.9",
    },
    # ══════════════════════════════════════════════════════════
    # === Joomla ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "joomla",
        "cve": "CVE-2023-23752",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Joomla! 4.0-4.2.7 未认证信息泄露 (API endpoint bypass)",
        "affected": "4.0.0 - 4.2.7",
        "fixed": "4.2.8",
    },
    {
        "component": "joomla",
        "cve": "CVE-2016-8869",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Joomla! 3.4.4-3.6.3 对象注入 RCE",
        "affected": "3.4.4 - 3.6.3",
        "fixed": "3.6.4",
    },
    {
        "component": "joomla",
        "cve": "CVE-2016-8870",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Joomla! 3.4.4-3.6.3 用户注册权限提升",
        "affected": "3.4.4 - 3.6.3",
        "fixed": "3.6.4",
    },
    {
        "component": "joomla",
        "cve": "CVE-2015-8562",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Joomla! 1.5-3.4.5 对象注入 RCE (User-Agent 头)",
        "affected": "1.5.0 - 3.4.5",
        "fixed": "3.4.6",
    },
    {
        "component": "joomla",
        "cve": "CVE-2024-21726",
        "severity": "HIGH",
        "cvss": 7.6,
        "description": "Joomla! XSS via reflection in redirect component",
        "affected": "< 4.4.3 / < 5.0.3",
        "fixed": "4.4.3 / 5.0.3",
    },
    # ══════════════════════════════════════════════════════════
    # === Tomcat ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "tomcat",
        "cve": "CVE-2025-24813",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Tomcat 路径等价缺陷 → RCE（已被活跃利用）",
        "affected": "9.0.0-M1 - 9.0.98 / 10.1.0-M1 - 10.1.34 / 11.0.0-M1 - 11.0.2",
        "fixed": "9.0.99 / 10.1.35 / 11.0.3",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2023-28708",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat JSESSIONID Cookie 缺少 Secure 属性",
        "affected": "< 10.1.8 / < 9.0.74 / < 8.5.87",
        "fixed": "10.1.8 / 9.0.74 / 8.5.87",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2023-24998",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat Commons FileUpload DoS (无限文件上传)",
        "affected": "< 10.1.5 / < 9.0.71 / < 8.5.85",
        "fixed": "10.1.5 / 9.0.71 / 8.5.85",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2022-45143",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat JSON error report XSS",
        "affected": "< 10.1.2 / < 9.0.69 / < 8.5.84",
        "fixed": "10.1.2 / 9.0.69 / 8.5.84",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2022-29885",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat CGI Servlet DoS (File.exists race)",
        "affected": "< 10.1.0 / < 9.0.63 / < 8.5.79",
        "fixed": "10.1.0 / 9.0.63 / 8.5.79",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2021-41079",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat WebSocket close 无限循环 DoS",
        "affected": "< 10.0.12 / < 9.0.53 / < 8.5.72",
        "fixed": "10.0.12 / 9.0.53 / 8.5.72",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2020-1938",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Ghostcat — AJP 协议文件读取/RCE (仅 8.5/9.0)",
        "affected": "< 9.0.31 / < 8.5.51",
        "fixed": "9.0.31 / 8.5.51",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2020-13935",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat WebSocket DoS (无限循环)",
        "affected": "< 10.0.0-M7 / < 9.0.37 / < 8.5.57",
        "fixed": "10.0.0-M7 / 9.0.37 / 8.5.57",
    },
    # ══════════════════════════════════════════════════════════
    # === Struts2 ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "struts2",
        "cve": "CVE-2023-50164",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 文件上传路径穿越 → RCE",
        "affected": "2.0.0 - 2.3.37 / 2.5.0 - 2.5.32 / 6.0.0 - 6.3.0",
        "fixed": "2.5.33 / 6.3.0.1",
    },
    {
        "component": "struts2",
        "cve": "CVE-2021-31805",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 OGNL 注入 (CVE-2020-17530 绕过)",
        "affected": "< 2.5.30 / < 6.0.3",
        "fixed": "2.5.30 / 6.0.3",
    },
    {
        "component": "struts2",
        "cve": "CVE-2019-0230",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 OGNL 注入 RCE",
        "affected": "< 2.5.22",
        "fixed": "2.5.22",
    },
    {
        "component": "struts2",
        "cve": "CVE-2018-11776",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 namespace OGNL 注入 RCE",
        "affected": "< 2.3.35 / < 2.5.17",
        "fixed": "2.3.35 / 2.5.17",
    },
    {
        "component": "struts2",
        "cve": "CVE-2020-17530",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 OGNL 注入 (forced OGNL evaluation)",
        "affected": "< 2.5.26",
        "fixed": "2.5.26",
    },
    # ══════════════════════════════════════════════════════════
    # === Laravel ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "laravel",
        "cve": "CVE-2021-3129",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Laravel <= 8.4.2 Debug Mode RCE (Ignition)",
        "affected": "<= 8.4.2",
        "fixed": "8.4.3",
    },
    {
        "component": "laravel",
        "cve": "CVE-2022-38500",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Laravel Debug Mode RCE (alternative payload in Ignition)",
        "affected": "<= 8.4.2",
        "fixed": "8.4.3",
    },
    # ══════════════════════════════════════════════════════════
    # === Spring ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "spring",
        "cve": "CVE-2022-22965",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Spring Framework RCE (Spring4Shell)",
        "affected": "5.3.0 - 5.3.17 / 5.2.0 - 5.2.19",
        "fixed": "5.3.18 / 5.2.20",
    },
    {
        "component": "spring",
        "cve": "CVE-2022-22963",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Spring Cloud Function SpEL RCE",
        "affected": "3.0.0 - 3.2.2",
        "fixed": "3.2.3",
    },
    {
        "component": "spring",
        "cve": "CVE-2022-22950",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "Spring Framework DoS via SpEL expression",
        "affected": "< 5.3.18 / < 5.2.20",
        "fixed": "5.3.18 / 5.2.20",
    },
    {
        "component": "spring",
        "cve": "CVE-2021-22060",
        "severity": "MEDIUM",
        "cvss": 4.3,
        "description": "Spring Framework input validation bypass via data binding",
        "affected": "< 5.3.15 / < 5.2.20",
        "fixed": "5.3.15 / 5.2.20",
    },
    {
        "component": "spring",
        "cve": "CVE-2020-5421",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "Spring Framework RFD attack via jsessionid parameter",
        "affected": "< 5.3.0 / < 5.2.11",
        "fixed": "5.3.0 / 5.2.11",
    },
    {
        "component": "spring",
        "cve": "CVE-2024-22234",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Spring Security authorization bypass via forward/include",
        "affected": "< 6.2.2 / < 6.1.6 / < 5.8.10",
        "fixed": "6.2.2 / 6.1.6 / 5.8.10",
    },
    # ══════════════════════════════════════════════════════════
    # === Django ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "django",
        "cve": "CVE-2023-36053",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django RegexValidator ReDoS via email input",
        "affected": "< 4.2.2 / < 4.1.10 / < 3.2.20",
        "fixed": "4.2.2 / 4.1.10 / 3.2.20",
    },
    {
        "component": "django",
        "cve": "CVE-2023-23969",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django Accept-Language header ReDoS",
        "affected": "< 4.1.6 / < 3.2.17",
        "fixed": "4.1.6 / 3.2.17",
    },
    {
        "component": "django",
        "cve": "CVE-2022-34265",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django Trunc/Extract SQL injection",
        "affected": "< 4.0.6 / < 3.2.14",
        "fixed": "4.0.6 / 3.2.14",
    },
    {
        "component": "django",
        "cve": "CVE-2022-28347",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django SQL injection via QuerySet.annotate/aggregate",
        "affected": "< 4.0.5 / < 3.2.13",
        "fixed": "4.0.5 / 3.2.13",
    },
    {
        "component": "django",
        "cve": "CVE-2021-45115",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django UserAttributeSimilarityValidator DoS",
        "affected": "< 4.0 / < 3.2.12 / < 2.2.26",
        "fixed": "4.0 / 3.2.12 / 2.2.26",
    },
    {
        "component": "django",
        "cve": "CVE-2021-45116",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Django dictsort/template info leak via debug mode",
        "affected": "< 4.0 / < 3.2.12 / < 2.2.26",
        "fixed": "4.0 / 3.2.12 / 2.2.26",
    },
    {
        "component": "django",
        "cve": "CVE-2021-44420",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Django URLValidator bypass via trailing newline",
        "affected": "< 4.0 / < 3.2.12 / < 2.2.26",
        "fixed": "4.0 / 3.2.12 / 2.2.26",
    },
    {
        "component": "django",
        "cve": "CVE-2024-24689",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django Trunc() Extract() SQL injection (alias handling)",
        "affected": "< 5.0.2 / < 4.2.10 / < 3.2.23",
        "fixed": "5.0.2 / 4.2.10 / 3.2.23",
    },
    # ══════════════════════════════════════════════════════════
    # === Express.js ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "express",
        "cve": "CVE-2024-29041",
        "severity": "MEDIUM",
        "cvss": 6.1,
        "description": "Express.js open redirect via URL parsing inconsistency",
        "affected": "< 4.19.2",
        "fixed": "4.19.2",
    },
    {
        "component": "express",
        "cve": "CVE-2022-24999",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Express.js qs prototype pollution (DoS/RCE)",
        "affected": "< 6.13.8 (qs < 6.7.3)",
        "fixed": "qs 6.7.3",
    },
    {
        "component": "express",
        "cve": "CVE-2024-47764",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Express.js cookie parsing vulnerability (cookie < 0.7.0)",
        "affected": "< 4.21.1",
        "fixed": "4.21.1",
    },
    # ══════════════════════════════════════════════════════════
    # === Flask ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "flask",
        "cve": "CVE-2023-30861",
        "severity": "MEDIUM",
        "cvss": 5.7,
        "description": "Flask session cookie disclosure via Vary: Cookie header caching",
        "affected": "< 2.3.2",
        "fixed": "2.3.2",
    },
    {
        "component": "flask",
        "cve": "CVE-2023-25577",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Flask Werkzeug DoS via large multipart form (ReDoS)",
        "affected": "< 2.2.3",
        "fixed": "2.2.3",
    },
    # ══════════════════════════════════════════════════════════
    # === Fastjson ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "fastjson",
        "cve": "CVE-2022-25845",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Fastjson <= 1.2.80 反序列化 RCE",
        "affected": "<= 1.2.80",
        "fixed": "1.2.83",
    },
    {
        "component": "fastjson",
        "cve": "CVE-2019-16203",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Fastjson < 1.2.60 反序列化 RCE (autoType bypass)",
        "affected": "< 1.2.60",
        "fixed": "1.2.60",
    },
    {
        "component": "fastjson",
        "cve": "CVE-2022-41854",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "SnakeYAML (Fastjson dep) DoS via crafted YAML",
        "affected": "< 1.2.83",
        "fixed": "1.2.83",
    },
    # ══════════════════════════════════════════════════════════
    # === Shiro ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "shiro",
        "cve": "CVE-2022-40664",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Shiro < 1.10.0 认证绕过",
        "affected": "< 1.10.0",
        "fixed": "1.10.0",
    },
    {
        "component": "shiro",
        "cve": "CVE-2022-32532",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Shiro RegexRequestMatcher 认证绕过",
        "affected": "< 1.9.1",
        "fixed": "1.9.1",
    },
    {
        "component": "shiro",
        "cve": "CVE-2021-41303",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Shiro 认证绕过 (path traversal in filter chain)",
        "affected": "< 1.8.0",
        "fixed": "1.8.0",
    },
    {
        "component": "shiro",
        "cve": "CVE-2020-1957",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Shiro 认证绕过 (trailing slash)",
        "affected": "< 1.5.2",
        "fixed": "1.5.2",
    },
    {
        "component": "shiro",
        "cve": "CVE-2016-4437",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Shiro RememberMe 反序列化 RCE (硬编码 AES key)",
        "affected": "< 1.2.5",
        "fixed": "1.2.5",
    },
    # ══════════════════════════════════════════════════════════
    # === Log4j ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "log4j",
        "cve": "CVE-2021-44228",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Log4Shell — Log4j2 JNDI RCE (影响几乎所有 Java 应用)",
        "affected": "< 2.15.0",
        "fixed": "2.15.0",
    },
    {
        "component": "log4j",
        "cve": "CVE-2021-45046",
        "severity": "CRITICAL",
        "cvss": 9.0,
        "description": "Log4j2 JNDI RCE (CVE-2021-44228 补丁不完整绕过)",
        "affected": "< 2.16.0",
        "fixed": "2.16.0",
    },
    {
        "component": "log4j",
        "cve": "CVE-2021-45105",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Log4j2 DoS via infinite recursion in lookup",
        "affected": "< 2.17.0",
        "fixed": "2.17.0",
    },
    {
        "component": "log4j",
        "cve": "CVE-2021-44832",
        "severity": "MEDIUM",
        "cvss": 6.6,
        "description": "Log4j2 RCE via JDBC Appender with JNDI (需高权限配置)",
        "affected": "< 2.17.1",
        "fixed": "2.17.1",
    },
    # ══════════════════════════════════════════════════════════
    # === Confluence ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "confluence",
        "cve": "CVE-2023-22515",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Confluence Data Center/Server 权限提升 RCE (未认证)",
        "affected": "< 8.3.3 / < 8.4.3 / < 8.5.2",
        "fixed": "8.3.3 / 8.4.3 / 8.5.2",
    },
    {
        "component": "confluence",
        "cve": "CVE-2022-26134",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Confluence Server OGNL 注入 RCE (未认证, 已被大规模利用)",
        "affected": "< 7.4.17 / < 7.13.7 / < 7.14.3",
        "fixed": "7.4.17 / 7.13.7 / 7.14.3",
    },
    {
        "component": "confluence",
        "cve": "CVE-2021-26084",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Confluence Server OGNL 注入 RCE (未认证, 已被大规模利用)",
        "affected": "< 6.13.23 / < 7.4.11 / < 7.11.6 / < 7.12.5",
        "fixed": "6.13.23 / 7.4.11 / 7.11.6 / 7.12.5",
    },
    {
        "component": "confluence",
        "cve": "CVE-2021-26085",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Confluence Server path traversal (arbitrary file read)",
        "affected": "< 6.13.23 / < 7.4.11",
        "fixed": "6.13.23 / 7.4.11",
    },
    {
        "component": "confluence",
        "cve": "CVE-2022-26138",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Confluence Server hardcoded password (Questions for Confluence)",
        "affected": "Questions plugin < 2.7.35 / < 3.0.2",
        "fixed": "2.7.35 / 3.0.2",
    },
    # ══════════════════════════════════════════════════════════
    # === Jenkins ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "jenkins",
        "cve": "CVE-2024-23897",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Jenkins CLI arbitrary file read → RCE",
        "affected": "< 2.441 / < 2.426.3 / < LTS 2.440.2",
        "fixed": "2.441 / 2.426.3 / 2.440.2",
    },
    {
        "component": "jenkins",
        "cve": "CVE-2023-24422",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Jenkins Sandbox bypass via CSRF (Script Security)",
        "affected": "< 1228.vd93135a_2fb_25",
        "fixed": "1228.vd93135a_2fb_25",
    },
    {
        "component": "jenkins",
        "cve": "CVE-2023-22552",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Jenkins Session fixation vulnerability",
        "affected": "< 2.394",
        "fixed": "2.394",
    },
    {
        "component": "jenkins",
        "cve": "CVE-2024-23898",
        "severity": "HIGH",
        "cvss": 8.8,
        "description": "Jenkins WebSocket CLI CSRF → code execution",
        "affected": "< 2.441 / < 2.426.3",
        "fixed": "2.441 / 2.426.3",
    },
    # ══════════════════════════════════════════════════════════
    # === GitLab ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "gitlab",
        "cve": "CVE-2023-28858",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "description": "GitLab API information disclosure via GraphQL",
        "affected": "< 15.11.1",
        "fixed": "15.11.1",
    },
    {
        "component": "gitlab",
        "cve": "CVE-2023-0670",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "GitLab CI YAML injection RCE",
        "affected": "< 15.9.5",
        "fixed": "15.9.5",
    },
    {
        "component": "gitlab",
        "cve": "CVE-2022-28849",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "GitLab project import SSRF",
        "affected": "< 14.10.5 / < 14.9.4",
        "fixed": "14.10.5 / 14.9.4",
    },
    {
        "component": "gitlab",
        "cve": "CVE-2023-7028",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "GitLab CE/EE account takeover via password reset email injection",
        "affected": "< 16.5.6 / < 16.6.4 / < 16.7.2",
        "fixed": "16.5.6 / 16.6.4 / 16.7.2",
    },
    # ══════════════════════════════════════════════════════════
    # === Redis ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "redis",
        "cve": "CVE-2022-24834",
        "severity": "HIGH",
        "cvss": 7.0,
        "description": "Redis heap overflow in lua cjson library",
        "affected": "< 7.0.12 / < 6.2.13",
        "fixed": "7.0.12 / 6.2.13",
    },
    {
        "component": "redis",
        "cve": "CVE-2022-0543",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Redis Lua sandbox escape RCE (Debian/Ubuntu 特有)",
        "affected": "6.0 - 6.2.6 (Debian/Ubuntu)",
        "fixed": "6.2.7",
    },
    {
        "component": "redis",
        "cve": "CVE-2021-32761",
        "severity": "HIGH",
        "cvss": 8.8,
        "description": "Redis integer overflow via BITCOUNT/LPOS (RCE)",
        "affected": "< 6.2.6 / < 6.0.16",
        "fixed": "6.2.6 / 6.0.16",
    },
    {
        "component": "redis",
        "cve": "CVE-2021-32762",
        "severity": "HIGH",
        "cvss": 8.8,
        "description": "Redis integer overflow via COPY command (RCE)",
        "affected": "< 6.2.6 / < 6.0.16",
        "fixed": "6.2.6 / 6.0.16",
    },
    {
        "component": "redis",
        "cve": "CVE-2023-28856",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Redis AUTH bypass via ACLSelector bug",
        "affected": "< 7.0.11 / < 6.2.12",
        "fixed": "7.0.11 / 6.2.12",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Nginx CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "nginx",
        "cve": "CVE-2024-7347",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Nginx HTTP/3 HPACK integer overflow DoS",
        "affected": "< 1.27.1",
        "fixed": "1.27.1",
        "cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    },
    {
        "component": "nginx",
        "cve": "CVE-2024-24990",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Nginx HTTP/3 QUIC memory leak on connection close",
        "affected": "< 1.25.4",
        "fixed": "1.25.4",
        "cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    },
    {
        "component": "nginx",
        "cve": "CVE-2023-50485",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Nginx HTTP/3 request smuggling via chunked transfer encoding",
        "affected": "< 1.25.4",
        "fixed": "1.25.4",
        "cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    },
    {
        "component": "nginx",
        "cve": "CVE-2019-9512",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Nginx HTTP/2 Ping Flood DoS",
        "affected": "< 1.17.3",
        "fixed": "1.17.3",
        "cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    },
    {
        "component": "nginx",
        "cve": "CVE-2019-9514",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Nginx HTTP/2 Reset Flood DoS",
        "affected": "< 1.17.3",
        "fixed": "1.17.3",
        "cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    },
    {
        "component": "nginx",
        "cve": "CVE-2019-9515",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Nginx HTTP/2 Settings Flood DoS",
        "affected": "< 1.17.3",
        "fixed": "1.17.3",
        "cpe": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Apache CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "apache",
        "cve": "CVE-2024-24795",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Apache HTTP Server HTTP response splitting via mod_proxy",
        "affected": "< 2.4.59",
        "fixed": "2.4.59",
        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    },
    {
        "component": "apache",
        "cve": "CVE-2024-40898",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache HTTP Server SSL/TLS OCSP stapling cache poisoning",
        "affected": "< 2.4.60",
        "fixed": "2.4.60",
        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    },
    {
        "component": "apache",
        "cve": "CVE-2024-27316",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache HTTP Server HTTP/2 CONTINUATION frames memory exhaustion DoS",
        "affected": "< 2.4.59",
        "fixed": "2.4.59",
        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    },
    {
        "component": "apache",
        "cve": "CVE-2021-40438",
        "severity": "CRITICAL",
        "cvss": 9.0,
        "description": "Apache mod_proxy SSRF via crafted request URI",
        "affected": "< 2.4.51",
        "fixed": "2.4.51",
        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    },
    {
        "component": "apache",
        "cve": "CVE-2020-13950",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache mod_proxy_http2 NULL pointer dereference",
        "affected": "< 2.4.47",
        "fixed": "2.4.47",
        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    },
    {
        "component": "apache",
        "cve": "CVE-2019-0211",
        "severity": "CRITICAL",
        "cvss": 7.8,
        "description": "Apache HTTP Server local privilege escalation via scoreboard manipulation",
        "affected": "< 2.4.39",
        "fixed": "2.4.39",
        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 IIS CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "iis",
        "cve": "CVE-2015-1635",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "IIS HTTP.sys RCE via crafted HTTP request (MS15-034)",
        "affected": "Windows Server 2008 R2 - 2012 R2",
        "fixed": "KB3042553",
        "cpe": "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Spring CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "spring",
        "cve": "CVE-2024-22243",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Spring Framework URL parsing SSRF via UriComponentsBuilder",
        "affected": "< 6.1.4 / < 6.0.17 / < 5.3.32",
        "fixed": "6.1.4 / 6.0.17 / 5.3.32",
        "cpe": "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    },
    {
        "component": "spring",
        "cve": "CVE-2024-22259",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Spring Framework URL parsing SSRF (CVE-2024-22243 incomplete fix)",
        "affected": "< 6.1.5 / < 6.0.18 / < 5.3.33",
        "fixed": "6.1.5 / 6.0.18 / 5.3.33",
        "cpe": "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    },
    {
        "component": "spring",
        "cve": "CVE-2024-22262",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Spring Framework URL parsing SSRF (CVE-2024-22259 incomplete fix)",
        "affected": "< 6.1.6 / < 6.0.19 / < 5.3.34",
        "fixed": "6.1.6 / 6.0.19 / 5.3.34",
        "cpe": "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    },
    {
        "component": "spring",
        "cve": "CVE-2023-34055",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Spring Boot Actuator DoS via crafted multipart request",
        "affected": "< 3.0.1 / < 2.7.7",
        "fixed": "3.0.1 / 2.7.7",
        "cpe": "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*",
    },
    {
        "component": "spring",
        "cve": "CVE-2023-20883",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Spring Boot Actuator DoS via crafted SpEL expression",
        "affected": "< 3.0.7 / < 2.7.12",
        "fixed": "3.0.7 / 2.7.12",
        "cpe": "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*",
    },
    {
        "component": "spring",
        "cve": "CVE-2023-20861",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Spring Framework SpEL DoS via crafted expression",
        "affected": "< 6.0.7 / < 5.3.27",
        "fixed": "6.0.7 / 5.3.27",
        "cpe": "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    },
    {
        "component": "spring",
        "cve": "CVE-2019-3778",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Spring Security OAuth open redirect via crafted authorization request",
        "affected": "< 2.3.5",
        "fixed": "2.3.5",
        "cpe": "cpe:2.3:a:vmware:spring_security_oauth:*:*:*:*:*:*:*:*",
    },
    {
        "component": "spring",
        "cve": "CVE-2018-1270",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Spring Framework RCE via spring-messaging STOMP",
        "affected": "< 5.0.5 / < 4.3.15",
        "fixed": "5.0.5 / 4.3.15",
        "cpe": "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Laravel CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "laravel",
        "cve": "CVE-2024-13918",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Laravel debug mode XSS via crafted error page",
        "affected": "< 11.31.0",
        "fixed": "11.31.0",
        "cpe": "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
    },
    {
        "component": "laravel",
        "cve": "CVE-2024-13919",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Laravel template injection via debug mode",
        "affected": "< 11.31.0",
        "fixed": "11.31.0",
        "cpe": "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
    },
    {
        "component": "laravel",
        "cve": "CVE-2023-38545",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Laravel HTTP client heap buffer overflow (via curl SOCKS5)",
        "affected": "< 10.24.0",
        "fixed": "10.24.0",
        "cpe": "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
    },
    {
        "component": "laravel",
        "cve": "CVE-2022-40482",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Laravel file upload RCE via phar deserialization",
        "affected": "< 9.32.0",
        "fixed": "9.32.0",
        "cpe": "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
    },
    {
        "component": "laravel",
        "cve": "CVE-2021-21263",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Laravel mass assignment vulnerability (unvalidated fill)",
        "affected": "< 8.4.2",
        "fixed": "8.4.2",
        "cpe": "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
    },
    {
        "component": "laravel",
        "cve": "CVE-2020-13762",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Laravel RCE via debug mode error handler",
        "affected": "< 7.12.0",
        "fixed": "7.12.0",
        "cpe": "cpe:2.3:a:laravel:laravel:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Django CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "django",
        "cve": "CVE-2024-24680",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django DoS via crafted Accept-Language header",
        "affected": "< 5.0.2 / < 4.2.10",
        "fixed": "5.0.2 / 4.2.10",
        "cpe": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    },
    {
        "component": "django",
        "cve": "CVE-2024-24679",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django DoS via crafted URL with very large number of path segments",
        "affected": "< 5.0.2 / < 4.2.10",
        "fixed": "5.0.2 / 4.2.10",
        "cpe": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    },
    {
        "component": "django",
        "cve": "CVE-2023-46695",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django UsernameField DoS via crafted username input",
        "affected": "< 4.2.8 / < 3.2.23",
        "fixed": "4.2.8 / 3.2.23",
        "cpe": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    },
    {
        "component": "django",
        "cve": "CVE-2023-43665",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django Truncator ReDoS via crafted input",
        "affected": "< 4.2.6 / < 3.2.22",
        "fixed": "4.2.6 / 3.2.22",
        "cpe": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    },
    {
        "component": "django",
        "cve": "CVE-2022-28346",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django SQL injection via QuerySet.annotate()/values()/values_list()",
        "affected": "< 4.0.4 / < 3.2.13",
        "fixed": "4.0.4 / 3.2.13",
        "cpe": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    },
    {
        "component": "django",
        "cve": "CVE-2021-33203",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Django directory traversal via admindocs",
        "affected": "< 3.2.4 / < 3.1.12",
        "fixed": "3.2.4 / 3.1.12",
        "cpe": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    },
    {
        "component": "django",
        "cve": "CVE-2021-3281",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Django archive extraction path traversal (ZipFile)",
        "affected": "< 3.2.2 / < 3.1.10",
        "fixed": "3.2.2 / 3.1.10",
        "cpe": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Express.js CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "express",
        "cve": "CVE-2024-24796",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Express.js XSS via crafted Content-Type header",
        "affected": "< 4.19.2",
        "fixed": "4.19.2",
        "cpe": "cpe:2.3:a:expressjs:express:*:*:*:*:*:node.js:*:*",
    },
    {
        "component": "express",
        "cve": "CVE-2024-24797",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Express.js path traversal via crafted URL",
        "affected": "< 4.19.2",
        "fixed": "4.19.2",
        "cpe": "cpe:2.3:a:expressjs:express:*:*:*:*:*:node.js:*:*",
    },
    {
        "component": "express",
        "cve": "CVE-2017-16137",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Express.js ReDoS via crafted User-Agent header",
        "affected": "< 4.16.0",
        "fixed": "4.16.0",
        "cpe": "cpe:2.3:a:expressjs:express:*:*:*:*:*:node.js:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Flask CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "flask",
        "cve": "CVE-2023-28842",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Flask debug mode PIN bypass via crafted error handler",
        "affected": "< 2.3.2",
        "fixed": "2.3.2",
        "cpe": "cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:python:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Next.js CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "nextjs",
        "cve": "CVE-2024-34351",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Next.js SSRF via crafted Server Actions request",
        "affected": "< 14.1.1",
        "fixed": "14.1.1",
        "cpe": "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
    },
    {
        "component": "nextjs",
        "cve": "CVE-2024-34350",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Next.js HTTP request smuggling via crafted headers",
        "affected": "< 14.1.1",
        "fixed": "14.1.1",
        "cpe": "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
    },
    {
        "component": "nextjs",
        "cve": "CVE-2024-21533",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Next.js arbitrary code execution via crafted middleware",
        "affected": "< 13.4.20 / < 13.5.7",
        "fixed": "13.4.20 / 13.5.7",
        "cpe": "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
    },
    {
        "component": "nextjs",
        "cve": "CVE-2023-46298",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Next.js DoS via crafted image optimization request",
        "affected": "< 13.4.20 / < 13.5.7",
        "fixed": "13.4.20 / 13.5.7",
        "cpe": "cpe:2.3:a:vercel:next.js:*:*:*:*:*:node.js:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Rails CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "rails",
        "cve": "CVE-2024-26146",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Action Pack header parsing DoS via crafted Accept-Language",
        "affected": "< 7.1.3.2 / < 7.0.8.1",
        "fixed": "7.1.3.2 / 7.0.8.1",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2024-26143",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Action Pack XSS via crafted content type",
        "affected": "< 7.1.3.2 / < 7.0.8.1",
        "fixed": "7.1.3.2 / 7.0.8.1",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2024-26142",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Action Pack ReDoS via crafted HTTP header",
        "affected": "< 7.1.3.2 / < 7.0.8.1",
        "fixed": "7.1.3.2 / 7.0.8.1",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2024-22256",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Rails Active Storage information disclosure via signed URL",
        "affected": "< 7.1.3.2 / < 7.0.8.1",
        "fixed": "7.1.3.2 / 7.0.8.1",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2023-28362",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Action Pack content type header XSS",
        "affected": "< 7.0.5.1 / < 6.1.7.4",
        "fixed": "7.0.5.1 / 6.1.7.4",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2023-22796",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Active Support ReDoS via underscore inflection",
        "affected": "< 7.0.4.3 / < 6.1.7.3",
        "fixed": "7.0.4.3 / 6.1.7.3",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2023-22795",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Active Support ReDoS via underscore inflection",
        "affected": "< 7.0.4.3 / < 6.1.7.3",
        "fixed": "7.0.4.3 / 6.1.7.3",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2023-22794",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails ActiveRecord SQL injection via eager loading",
        "affected": "< 7.0.4.3 / < 6.1.7.3",
        "fixed": "7.0.4.3 / 6.1.7.3",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2022-44566",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails ActiveRecord DoS via crafted SQL query",
        "affected": "< 7.0.4.2 / < 6.1.7.2",
        "fixed": "7.0.4.2 / 6.1.7.2",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2022-32224",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Rails ActiveRecord deserialization RCE via crafted YAML",
        "affected": "< 7.0.3.1 / < 6.1.6.1",
        "fixed": "7.0.3.1 / 6.1.6.1",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2022-27777",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Action View XSS via crafted template name",
        "affected": "< 7.0.2.4 / < 6.1.5.1",
        "fixed": "7.0.2.4 / 6.1.5.1",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },
    {
        "component": "rails",
        "cve": "CVE-2022-23633",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Rails Action Pack information disclosure via crafted request",
        "affected": "< 7.0.2.2 / < 6.1.4.6",
        "fixed": "7.0.2.2 / 6.1.4.6",
        "cpe": "cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 FastAPI CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "fastapi",
        "cve": "CVE-2024-24762",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "FastAPI ReDoS via crafted Content-Type header (python-multipart)",
        "affected": "< 0.109.0",
        "fixed": "0.109.0",
        "cpe": "cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:python:*:*",
    },
    {
        "component": "fastapi",
        "cve": "CVE-2023-30742",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "FastAPI Denial of Service via crafted multipart form",
        "affected": "< 0.95.0",
        "fixed": "0.95.0",
        "cpe": "cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:python:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 WordPress CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "wordpress",
        "cve": "CVE-2024-27956",
        "severity": "CRITICAL",
        "cvss": 9.9,
        "description": "WordPress Automatic SQL injection via WP Automatic plugin",
        "affected": "< 3.92.1",
        "fixed": "3.92.1",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2024-25600",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "WordPress Bricks Builder RCE via unauthenticated AJAX",
        "affected": "< 1.9.6",
        "fixed": "1.9.6",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2024-2198",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WordPress Starter Templates plugin SSRF",
        "affected": "< 4.1.5",
        "fixed": "4.1.5",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2023-6553",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "WordPress Backup Migration plugin RCE via crafted request",
        "affected": "< 1.3.7",
        "fixed": "1.3.7",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2023-45612",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WordPress Starter Templates plugin path traversal",
        "affected": "< 3.4.2",
        "fixed": "3.4.2",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2023-38000",
        "severity": "HIGH",
        "cvss": 8.3,
        "description": "WordPress Jetpack stored XSS via shortcode",
        "affected": "< 12.5",
        "fixed": "12.5",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2023-27446",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WordPress Gravity Forms SSRF via crafted URL field",
        "affected": "< 2.7.5",
        "fixed": "2.7.5",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2022-43504",
        "severity": "MEDIUM",
        "cvss": 5.4,
        "description": "WordPress stored XSS via comment content",
        "affected": "< 6.1.1",
        "fixed": "6.1.1",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2022-43500",
        "severity": "MEDIUM",
        "cvss": 5.4,
        "description": "WordPress stored XSS via post editing",
        "affected": "< 6.1.1",
        "fixed": "6.1.1",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2022-43482",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WordPress SSRF via oEmbed discovery",
        "affected": "< 6.1.1",
        "fixed": "6.1.1",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2021-29447",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "WordPress XXE via media library WAV file upload",
        "affected": "< 5.7.1",
        "fixed": "5.7.1",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2020-4047",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "WordPress password reset token leak via request forgery",
        "affected": "< 5.4.2",
        "fixed": "5.4.2",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },
    {
        "component": "wordpress",
        "cve": "CVE-2017-14723",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "WordPress SQL injection via taxonomy terms",
        "affected": "< 4.8.3",
        "fixed": "4.8.3",
        "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Drupal CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "drupal",
        "cve": "CVE-2024-1352",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Drupal Twig template injection RCE via crafted input",
        "affected": "< 10.2.3",
        "fixed": "10.2.3",
        "cpe": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    },
    {
        "component": "drupal",
        "cve": "CVE-2023-43642",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Drupal Composer dependency RCE via crafted package",
        "affected": "< 9.4.15 / < 9.5.11",
        "fixed": "9.4.15 / 9.5.11",
        "cpe": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    },
    {
        "component": "drupal",
        "cve": "CVE-2022-25277",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Drupal file upload RCE via crafted archive",
        "affected": "< 9.3.22 / < 9.4.8",
        "fixed": "9.3.22 / 9.4.8",
        "cpe": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    },
    {
        "component": "drupal",
        "cve": "CVE-2020-28914",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Drupal media library access bypass",
        "affected": "< 9.0.8",
        "fixed": "9.0.8",
        "cpe": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    },
    {
        "component": "drupal",
        "cve": "CVE-2017-6926",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Drupal PECL YAML parser unsafe deserialization RCE",
        "affected": "< 8.3.4",
        "fixed": "8.3.4",
        "cpe": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Joomla CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "joomla",
        "cve": "CVE-2023-40617",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Joomla! insufficient session validation",
        "affected": "< 4.3.4 / < 3.10.14",
        "fixed": "4.3.4 / 3.10.14",
        "cpe": "cpe:2.3:a:joomla:joomla!::*:*:*:*:*:*:*",
    },
    {
        "component": "joomla",
        "cve": "CVE-2022-21724",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Joomla! PHP object injection via crafted content",
        "affected": "< 3.10.5 / < 4.0.6",
        "fixed": "3.10.5 / 4.0.6",
        "cpe": "cpe:2.3:a:joomla:joomla!::*:*:*:*:*:*:*",
    },
    {
        "component": "joomla",
        "cve": "CVE-2021-26033",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Joomla! XSS via crafted contact form input",
        "affected": "< 3.9.25",
        "fixed": "3.9.25",
        "cpe": "cpe:2.3:a:joomla:joomla!::*:*:*:*:*:*:*",
    },
    {
        "component": "joomla",
        "cve": "CVE-2020-35616",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Joomla! SQL injection via crafted request",
        "affected": "< 3.9.24",
        "fixed": "3.9.24",
        "cpe": "cpe:2.3:a:joomla:joomla!::*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Confluence CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "confluence",
        "cve": "CVE-2024-21887",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "description": "Confluence Data Center/Server command injection (chained with CVE-2023-46805)",
        "affected": "< 8.5.4",
        "fixed": "8.5.4",
        "cpe": "cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*",
    },
    {
        "component": "confluence",
        "cve": "CVE-2023-22512",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Confluence Data Center/Server DoS via crafted request",
        "affected": "< 8.3.3 / < 8.4.3 / < 8.5.2",
        "fixed": "8.3.3 / 8.4.3 / 8.5.2",
        "cpe": "cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*",
    },
    {
        "component": "confluence",
        "cve": "CVE-2020-5428",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Confluence Server RFD attack via crafted filename",
        "affected": "< 7.4.6",
        "fixed": "7.4.6",
        "cpe": "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Jenkins CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "jenkins",
        "cve": "CVE-2023-25761",
        "severity": "HIGH",
        "cvss": 8.0,
        "description": "Jenkins stored XSS via build description",
        "affected": "< 2.394",
        "fixed": "2.394",
        "cpe": "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
    },
    {
        "component": "jenkins",
        "cve": "CVE-2023-25762",
        "severity": "HIGH",
        "cvss": 8.0,
        "description": "Jenkins stored XSS via build parameter names",
        "affected": "< 2.394",
        "fixed": "2.394",
        "cpe": "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
    },
    {
        "component": "jenkins",
        "cve": "CVE-2023-27898",
        "severity": "HIGH",
        "cvss": 8.0,
        "description": "Jenkins stored XSS via Jervis plugin",
        "affected": "Jervis plugin < 1.2",
        "fixed": "1.2",
        "cpe": "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
    },
    {
        "component": "jenkins",
        "cve": "CVE-2023-27903",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Jenkins agent-to-controller security bypass",
        "affected": "< 2.394",
        "fixed": "2.394",
        "cpe": "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
    },
    {
        "component": "jenkins",
        "cve": "CVE-2022-45379",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Jenkins PLUGIN_ISSUE macro XSS",
        "affected": "< 2.379",
        "fixed": "2.379",
        "cpe": "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Tomcat CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "tomcat",
        "cve": "CVE-2024-21733",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Apache Tomcat HTTP request smuggling via crafted trailer",
        "affected": "< 11.0.0-M11 / < 10.1.16 / < 9.0.83 / < 8.5.96",
        "fixed": "11.0.0-M11 / 10.1.16 / 9.0.83 / 8.5.96",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2023-46589",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat HTTP request smuggling via content-length",
        "affected": "< 11.0.0-M10 / < 10.1.16 / < 9.0.83 / < 8.5.96",
        "fixed": "11.0.0-M10 / 10.1.16 / 9.0.83 / 8.5.96",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2023-45648",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat HTTP request smuggling via trailer headers",
        "affected": "< 11.0.0-M10 / < 10.1.15 / < 9.0.82 / < 8.5.95",
        "fixed": "11.0.0-M10 / 10.1.15 / 9.0.82 / 8.5.95",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2023-42795",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Apache Tomcat information leak via incomplete POST",
        "affected": "< 11.0.0-M10 / < 10.1.15 / < 9.0.80 / < 8.5.93",
        "fixed": "11.0.0-M10 / 10.1.15 / 9.0.80 / 8.5.93",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2021-33037",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Apache Tomcat HTTP request smuggling via Transfer-Encoding",
        "affected": "< 10.0.7 / < 9.0.48 / < 8.5.68",
        "fixed": "10.0.7 / 9.0.48 / 8.5.68",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2021-25329",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Apache Tomcat JSP source code disclosure via crafted request",
        "affected": "< 10.0.3 / < 9.0.43 / < 8.5.63 / < 7.0.108",
        "fixed": "10.0.3 / 9.0.43 / 8.5.63 / 7.0.108",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2019-0232",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Apache Tomcat CGI Servlet RCE via crafted parameter",
        "affected": "< 9.0.18 / < 8.5.40",
        "fixed": "9.0.18 / 8.5.40",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },
    {
        "component": "tomcat",
        "cve": "CVE-2019-0221",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Tomcat XSS via crafted SSI printenv directive",
        "affected": "< 9.0.18 / < 8.5.40 / < 7.0.94",
        "fixed": "9.0.18 / 8.5.40 / 7.0.94",
        "cpe": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Struts2 CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "struts2",
        "cve": "CVE-2023-41835",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 file upload RCE via crafted filename",
        "affected": "< 2.5.33 / < 6.3.0.2",
        "fixed": "2.5.33 / 6.3.0.2",
        "cpe": "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
    },
    {
        "component": "struts2",
        "cve": "CVE-2017-5638",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Apache Struts2 RCE via Content-Type header (S2-045, 大规模利用)",
        "affected": "< 2.3.32 / < 2.5.10.1",
        "fixed": "2.3.32 / 2.5.10.1",
        "cpe": "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
    },
    {
        "component": "struts2",
        "cve": "CVE-2016-3087",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 RCE via REST plugin (S2-037)",
        "affected": "< 2.3.29",
        "fixed": "2.3.29",
        "cpe": "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
    },
    {
        "component": "struts2",
        "cve": "CVE-2016-0785",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "Apache Struts2 JUnit plugin RCE (S2-027)",
        "affected": "< 2.3.24.1",
        "fixed": "2.3.24.1",
        "cpe": "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
    },
    {
        "component": "struts2",
        "cve": "CVE-2015-5169",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Struts2 debug mode information disclosure",
        "affected": "< 2.3.20",
        "fixed": "2.3.20",
        "cpe": "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Shiro CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "shiro",
        "cve": "CVE-2023-22602",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Shiro authentication bypass via crafted request",
        "affected": "< 1.11.0",
        "fixed": "1.11.0",
        "cpe": "cpe:2.3:a:apache:shiro:*:*:*:*:*:*:*:*",
    },
    {
        "component": "shiro",
        "cve": "CVE-2020-11989",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Shiro authentication bypass via crafted URI",
        "affected": "< 1.5.3",
        "fixed": "1.5.3",
        "cpe": "cpe:2.3:a:apache:shiro:*:*:*:*:*:*:*:*",
    },
    {
        "component": "shiro",
        "cve": "CVE-2019-12422",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Apache Shiro Padding Oracle attack (AES-CBC)",
        "affected": "< 1.4.1",
        "fixed": "1.4.1",
        "cpe": "cpe:2.3:a:apache:shiro:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Fastjson CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "fastjson",
        "cve": "CVE-2023-39438",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Fastjson2 deserialization RCE via crafted JSON",
        "affected": "< 2.0.40",
        "fixed": "2.0.40",
        "cpe": "cpe:2.3:a:alibaba:fastjson:*:*:*:*:*:*:*:*",
    },
    {
        "component": "fastjson",
        "cve": "CVE-2017-18349",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Fastjson deserialization RCE via @type (autoType)",
        "affected": "< 1.2.24",
        "fixed": "1.2.24",
        "cpe": "cpe:2.3:a:alibaba:fastjson:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 PHP CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "php",
        "cve": "CVE-2024-1895",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PHP environment variable leak via crafted request",
        "affected": "< 8.3.4 / < 8.2.17",
        "fixed": "8.3.4 / 8.2.17",
        "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
    },
    {
        "component": "php",
        "cve": "CVE-2023-0662",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PHP POST data parsing DoS via crafted multipart",
        "affected": "< 8.0.28 / < 8.1.17 / < 8.2.5",
        "fixed": "8.0.28 / 8.1.17 / 8.2.5",
        "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
    },
    {
        "component": "php",
        "cve": "CVE-2022-21661",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PHP mbstring crafted input DoS",
        "affected": "< 8.0.16 / < 8.1.3",
        "fixed": "8.0.16 / 8.1.3",
        "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 DedeCMS CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "dedecms",
        "cve": "CVE-2023-29582",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "DedeCMS v5.7.106 SQL injection via crafted request",
        "affected": "<= 5.7.106",
        "fixed": "5.7.107",
        "cpe": "cpe:2.3:a:dedecms:dedecms:*:*:*:*:*:*:*:*",
    },
    {
        "component": "dedecms",
        "cve": "CVE-2022-26823",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "DedeCMS v5.7.95 arbitrary file upload RCE",
        "affected": "<= 5.7.95",
        "fixed": "5.7.96",
        "cpe": "cpe:2.3:a:dedecms:dedecms:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Discuz CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "discuz",
        "cve": "CVE-2022-34592",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Discuz! X3.4 arbitrary file read via crafted request",
        "affected": "<= X3.4",
        "fixed": "",
        "cpe": "cpe:2.3:a:discuz:discuz!::*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 GitLab CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "gitlab",
        "cve": "CVE-2024-0132",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "GitLab CE/EE RCE via crafted CI/CD pipeline",
        "affected": "< 16.9.4",
        "fixed": "16.9.4",
        "cpe": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
    },
    {
        "component": "gitlab",
        "cve": "CVE-2023-6033",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "GitLab CE/EE stored XSS via crafted issue",
        "affected": "< 16.5.6",
        "fixed": "16.5.6",
        "cpe": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
    },
    {
        "component": "gitlab",
        "cve": "CVE-2023-5686",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "GitLab CE/EE RCE via crafted Markdown",
        "affected": "< 16.5.6 / < 16.4.4",
        "fixed": "16.5.6 / 16.4.4",
        "cpe": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
    },
    {
        "component": "gitlab",
        "cve": "CVE-2022-2185",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "GitLab CE/EE path traversal via crafted URL",
        "affected": "< 15.1.5 / < 15.0.4",
        "fixed": "15.1.5 / 15.0.4",
        "cpe": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
    },
    {
        "component": "gitlab",
        "cve": "CVE-2021-22205",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "GitLab CE/EE REXML RCE via crafted ExifTool metadata (大规模利用)",
        "affected": "< 13.10.3 / < 13.9.6 / < 13.8.8",
        "fixed": "13.10.3 / 13.9.6 / 13.8.8",
        "cpe": "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Redis CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "redis",
        "cve": "CVE-2023-36824",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Redis heap overflow via crafted Lua script",
        "affected": "< 7.2.4 / < 7.0.15",
        "fixed": "7.2.4 / 7.0.15",
        "cpe": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 MongoDB CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "mongodb",
        "cve": "CVE-2023-14670",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "MongoDB Server heap buffer overflow",
        "affected": "< 6.0.5 / < 5.0.15",
        "fixed": "6.0.5 / 5.0.15",
        "cpe": "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
    },
    {
        "component": "mongodb",
        "cve": "CVE-2022-24901",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "MongoDB Server crafted query DoS",
        "affected": "< 5.0.8 / < 4.4.13",
        "fixed": "5.0.8 / 4.4.13",
        "cpe": "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
    },
    {
        "component": "mongodb",
        "cve": "CVE-2021-32037",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "MongoDB Server memory corruption via crafted aggregation",
        "affected": "< 5.0.4 / < 4.4.10",
        "fixed": "5.0.4 / 4.4.10",
        "cpe": "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Elasticsearch CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "elasticsearch",
        "cve": "CVE-2023-31418",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Elasticsearch crafted query DoS via aggregation",
        "affected": "< 8.9.0",
        "fixed": "8.9.0",
        "cpe": "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
    },
    {
        "component": "elasticsearch",
        "cve": "CVE-2023-31419",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Elasticsearch stored XSS via crafted document",
        "affected": "< 8.9.0",
        "fixed": "8.9.0",
        "cpe": "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
    },
    {
        "component": "elasticsearch",
        "cve": "CVE-2021-22145",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Elasticsearch document disclosure via crafted search",
        "affected": "< 7.13.1 / < 6.8.17",
        "fixed": "7.13.1 / 6.8.17",
        "cpe": "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
    },
    {
        "component": "elasticsearch",
        "cve": "CVE-2021-22134",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Elasticsearch information disclosure via _search API",
        "affected": "< 7.13.0 / < 6.8.17",
        "fixed": "7.13.0 / 6.8.17",
        "cpe": "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 MySQL CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "mysql",
        "cve": "CVE-2023-21977",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "MySQL Server crafted query DoS",
        "affected": "< 8.0.33",
        "fixed": "8.0.33",
        "cpe": "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
    },
    {
        "component": "mysql",
        "cve": "CVE-2023-21912",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "MySQL Server privilege escalation",
        "affected": "< 8.0.33",
        "fixed": "8.0.33",
        "cpe": "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 PostgreSQL CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "postgresql",
        "cve": "CVE-2023-39417",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PostgreSQL SQL injection via crafted extension script",
        "affected": "< 15.4 / < 14.9 / < 13.12",
        "fixed": "15.4 / 14.9 / 13.12",
        "cpe": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    },
    {
        "component": "postgresql",
        "cve": "CVE-2023-39418",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PostgreSQL MERGE privilege escalation",
        "affected": "< 16.0",
        "fixed": "16.0",
        "cpe": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    },
    {
        "component": "postgresql",
        "cve": "CVE-2022-41862",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "PostgreSQL memory disclosure via crafted query",
        "affected": "< 15.2 / < 14.7 / < 13.10",
        "fixed": "15.2 / 14.7 / 13.10",
        "cpe": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Docker CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "docker",
        "cve": "CVE-2024-24557",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Docker Engine classic builder cache poisoning",
        "affected": "< 25.0.2 / < 24.0.8",
        "fixed": "25.0.2 / 24.0.8",
        "cpe": "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*",
    },
    {
        "component": "docker",
        "cve": "CVE-2024-23651",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Docker BuildKit race condition mount handling",
        "affected": "< 0.12.5",
        "fixed": "0.12.5",
        "cpe": "cpe:2.3:a:docker:buildkit:*:*:*:*:*:*:*:*",
    },
    {
        "component": "docker",
        "cve": "CVE-2024-23652",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Docker BuildKit arbitrary file deletion via crafted Dockerfile",
        "affected": "< 0.12.5",
        "fixed": "0.12.5",
        "cpe": "cpe:2.3:a:docker:buildkit:*:*:*:*:*:*:*:*",
    },
    {
        "component": "docker",
        "cve": "CVE-2024-23653",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Docker BuildKit GRPC security mode bypass",
        "affected": "< 0.12.5",
        "fixed": "0.12.5",
        "cpe": "cpe:2.3:a:docker:buildkit:*:*:*:*:*:*:*:*",
    },

    # ══════════════════════════════════════════════════════════
    # === 新增 Kubernetes CVEs ===
    # ══════════════════════════════════════════════════════════
    {
        "component": "kubernetes",
        "cve": "CVE-2024-21626",
        "severity": "HIGH",
        "cvss": 8.6,
        "description": "Kubernetes runc container escape via leaked file descriptors",
        "affected": "< 1.29.1",
        "fixed": "1.29.1",
        "cpe": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
    },
    {
        "component": "kubernetes",
        "cve": "CVE-2023-5528",
        "severity": "CRITICAL",
        "cvss": 7.2,
        "description": "Kubernetes YAML/JSON command injection on Windows nodes",
        "affected": "< 1.28.4 / < 1.27.8 / < 1.26.11",
        "fixed": "1.28.4 / 1.27.8 / 1.26.11",
        "cpe": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
    },
    {
        "component": "kubernetes",
        "cve": "CVE-2023-5043",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Kubernetes ingress-nginx annotation injection",
        "affected": "< 1.9.0",
        "fixed": "1.9.0",
        "cpe": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
    },
    {
        "component": "kubernetes",
        "cve": "CVE-2023-48795",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "description": "Kubernetes SSH/Terrapin prefix truncation attack",
        "affected": "< 1.29.0",
        "fixed": "1.29.0",
        "cpe": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
    },
]


class CVEMatcher:
    """CVE 匹配器"""

    def __init__(self, nvd_api_key: str = ""):
        self._db = BUILTIN_VULNS
        self._nvd_api_key = nvd_api_key or os.environ.get("POXIAO_NVD_API_KEY", "")
        self._nvd_last_request: float = 0.0
        self._nvd_rate_limit: float = 0.6  # seconds between NVD requests (with API key: 0.6s; without: 6s)

    def match(self, component: str, version: str = "") -> list[VulnMatch]:
        """
        根据组件名（和可选版本）匹配已知漏洞
        """
        matches = []
        for entry in self._db:
            if entry["component"].lower() == component.lower():
                # 简单版本匹配：如果提供了版本且条目有 affected，做模糊检查
                if version and version != "detected" and entry.get("affected"):
                    if self._version_in_range(version, entry["affected"]):
                        matches.append(self._to_vuln(entry))
                elif not version or version == "detected":
                    # 不知道具体版本，列出所有已知漏洞作为警告
                    matches.append(self._to_vuln(entry))
        return matches

    def match_batch(self, versions: dict) -> list[VulnMatch]:
        """
        批量匹配
        versions: {"nginx": "1.18.0", "php": "7.4.33", ...}
        """
        all_matches = []
        for component, version in versions.items():
            all_matches.extend(self.match(component, version))
        return all_matches

    def _to_vuln(self, entry: dict) -> VulnMatch:
        return VulnMatch(
            cve_id=entry["cve"],
            component=entry["component"],
            description=entry["description"],
            severity=entry["severity"],
            cvss_score=entry.get("cvss", 0),
            affected_versions=entry.get("affected", ""),
            fixed_version=entry.get("fixed", ""),
            match_type="local",
            cpe=entry.get("cpe", ""),
        )

    @staticmethod
    def _pad_versions(a: list[int], b: list[int]) -> tuple[list[int], list[int]]:
        """Pad shorter version list with zeros so both have equal length."""
        max_len = max(len(a), len(b))
        return (
            a + [0] * (max_len - len(a)),
            b + [0] * (max_len - len(b)),
        )

    @staticmethod
    def _parse_version(ver_str: str) -> tuple[list[int], str]:
        """Parse version string into (numeric_parts, suffix).

        Handles pre-release and patch suffixes:
          "1.18.0-rc1"  -> ([1,18,0], "-rc1")   — pre-release < release
          "1.18.0-p1"   -> ([1,18,0], "-p1")    — patch > release
          "1.18.0"      -> ([1,18,0], "")
        """
        ver = ver_str.lstrip("vV").strip()
        # Split numeric prefix from suffix (e.g. "1.18.0-rc1" -> "1.18.0" + "-rc1")
        m = re.match(r"([\d]+(?:\.[\d]+)*)(.*)", ver)
        if not m:
            return [], ""
        try:
            parts = [int(x) for x in m.group(1).split(".")]
        except ValueError:
            return [], ""
        suffix = m.group(2).strip()
        return parts, suffix

    @staticmethod
    def _suffix_penalty(suffix: str) -> int:
        """Return a penalty value for pre-release / bonus for patch suffixes.

        Pre-release (rc, alpha, beta, dev, snapshot) -> -1 (less than release)
        Patch suffix (p1, pl1) -> +1 (greater than release)
        No suffix -> 0 (release)
        """
        if not suffix:
            return 0
        s = suffix.lower()
        # Pre-release keywords
        if any(k in s for k in ("-rc", "-alpha", "-beta", "-dev", "-snapshot", "-pre", "rc", "alpha", "beta")):
            return -1
        # Patch suffixes
        if re.match(r"^[-.]p\d", s) or re.match(r"^[-.]pl\d", s):
            return 1
        # Unknown suffix — treat as pre-release to be safe
        return -1

    @classmethod
    def _version_parts_with_suffix(cls, ver_str: str) -> tuple[list[int], int]:
        """Return (numeric_parts, suffix_penalty) for comparison."""
        parts, suffix = cls._parse_version(ver_str)
        return parts, cls._suffix_penalty(suffix)

    @classmethod
    def _version_less_than(cls, ver_parts: list[int], ver_penalty: int,
                           limit_parts: list[int], limit_penalty: int = 0) -> bool:
        """Compare two versions considering suffix penalties."""
        p, l = cls._pad_versions(ver_parts, limit_parts)
        if p < l:
            return True
        if p == l:
            return ver_penalty < limit_penalty
        return False

    @classmethod
    def _version_less_equal(cls, ver_parts: list[int], ver_penalty: int,
                            limit_parts: list[int], limit_penalty: int = 0) -> bool:
        """Compare two versions considering suffix penalties."""
        p, l = cls._pad_versions(ver_parts, limit_parts)
        if p < l:
            return True
        if p == l:
            return ver_penalty <= limit_penalty
        return False

    @classmethod
    def _version_equal(cls, ver_parts: list[int], ver_penalty: int,
                       limit_parts: list[int], limit_penalty: int = 0) -> bool:
        p, l = cls._pad_versions(ver_parts, limit_parts)
        return p == l and ver_penalty == limit_penalty

    @classmethod
    def _version_in_range(cls, version: str, affected: str) -> bool:
        """版本范围检查 — 返回 False 当版本无法解析时（避免误报）

        Supports:
          - "< 1.20.1"          less than
          - "<= 1.20.1"         less than or equal
          - ">= 1.20.1"         greater than or equal
          - "> 1.20.1"          greater than
          - "1.20.1+"           greater than or equal (X.Y.Z+ shorthand)
          - "1.2.3 - 1.5.0"    range (inclusive)
          - "1.20.1"            exact match
          - "2.4.49"            exact match
          - "/ < 7.58 / < 8.5.1"  multi-branch (split on " / ")
        Handles pre-release versions (e.g. "1.18.0-rc1" < "1.18.0").
        """
        ver_parts, ver_suffix = cls._parse_version(version)
        if not ver_parts:
            return False
        ver_penalty = cls._suffix_penalty(ver_suffix)

        # Handle multi-branch affected strings like "< 7.58 / < 8.5.1"
        # Try each branch; if any matches, return True
        if " / " in affected:
            for branch in affected.split(" / "):
                branch = branch.strip()
                if cls._version_in_range_single(ver_parts, ver_penalty, branch):
                    return True
            return False

        return cls._version_in_range_single(ver_parts, ver_penalty, affected)

    @classmethod
    def _version_in_range_single(cls, ver_parts: list[int], ver_penalty: int,
                                  affected: str) -> bool:
        """Match a single affected-range string against parsed version."""

        # ">= 1.20.1" or ">=1.20.1"
        m = re.match(r">=\s*v?([\d.]+)", affected)
        if m:
            try:
                limit = [int(x) for x in m.group(1).split(".")]
            except ValueError:
                return False
            return cls._version_less_equal(limit, 0, ver_parts, ver_penalty)

        # "> 1.20.1"
        m = re.match(r">\s*v?([\d.]+)", affected)
        if m:
            try:
                limit = [int(x) for x in m.group(1).split(".")]
            except ValueError:
                return False
            return cls._version_less_than(limit, 0, ver_parts, ver_penalty)

        # "1.20.1+" (greater than or equal shorthand)
        m = re.match(r"v?([\d.]+)\+$", affected.strip())
        if m:
            try:
                limit = [int(x) for x in m.group(1).split(".")]
            except ValueError:
                return False
            return cls._version_less_equal(limit, 0, ver_parts, ver_penalty)

        # "< 1.20.1"
        m = re.match(r"<\s*v?([\d.]+)", affected)
        if m:
            try:
                limit = [int(x) for x in m.group(1).split(".")]
            except ValueError:
                return False
            return cls._version_less_than(ver_parts, ver_penalty, limit, 0)

        # "<= 1.20.1"
        m = re.match(r"<=\s*v?([\d.]+)", affected)
        if m:
            try:
                limit = [int(x) for x in m.group(1).split(".")]
            except ValueError:
                return False
            return cls._version_less_equal(ver_parts, ver_penalty, limit, 0)

        # "1.2.3 - 1.5.0"
        m = re.match(r"v?([\d.]+)\s*-\s*v?([\d.]+)", affected)
        if m:
            try:
                lo = [int(x) for x in m.group(1).split(".")]
                hi = [int(x) for x in m.group(2).split(".")]
            except ValueError:
                return False
            p, lo_padded = cls._pad_versions(ver_parts, lo)
            _, hi_padded = cls._pad_versions(ver_parts, hi)
            max_len = max(len(p), len(hi_padded))
            lo_full = lo_padded + [0] * (max_len - len(lo_padded))
            hi_full = hi_padded + [0] * (max_len - len(hi_padded))
            parts_full = p[:max_len]
            return lo_full <= parts_full <= hi_full

        # Exact match (e.g. "2.4.49")
        if re.match(r"v?[\d.]+$", affected.strip()):
            try:
                exact = [int(x) for x in affected.strip().lstrip("vV").split(".")]
            except ValueError:
                return False
            return cls._version_equal(ver_parts, ver_penalty, exact, 0)

        # 无法解析格式 → 不匹配（避免误报）
        return False

    # ── NVD API 查询 ────────────────────────────

    def query_nvd(self, component: str, version: str = "") -> list[VulnMatch]:
        """
        通过 NVD API 查询漏洞（需要网络访问 api.nvd.nist.gov）
        自动进行速率限制：有 API key 时 ~50 req/30s，无 key 时 ~5 req/30s
        """
        try:
            import requests
        except ImportError:
            return []

        # Rate limiting
        elapsed = time.time() - self._nvd_last_request
        min_interval = self._nvd_rate_limit if self._nvd_api_key else 6.0
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

        try:
            headers = {"User-Agent": "PoXiao/0.1"}
            params = {
                "keywordSearch": f"{component} {version}".strip() if version else component,
                "resultsPerPage": 20,
            }
            if self._nvd_api_key:
                headers["apiKey"] = self._nvd_api_key

            self._nvd_last_request = time.time()
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                timeout=15,
                headers=headers,
            )
            if resp.status_code == 403:
                # Rate limited — back off
                time.sleep(6)
                return []
            if resp.status_code != 200:
                return []

            data = resp.json()
            results = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # 提取描述
                desc_list = cve.get("descriptions", [])
                desc = ""
                for d in desc_list:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                if not desc and desc_list:
                    desc = desc_list[0].get("value", "")

                # 提取 CVSS 评分 (prefer v3.1, fallback to v3.0, then v2)
                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                severity = ""
                for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        severity = cvss_data.get("baseSeverity", "")
                        break
                if not severity:
                    metric_list = metrics.get("cvssMetricV2", [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        severity = cvss_data.get("baseSeverity", "")

                # 提取 references
                refs = []
                for ref in cve.get("references", [])[:3]:
                    url = ref.get("url", "")
                    if url:
                        refs.append(url)

                results.append(VulnMatch(
                    cve_id=cve_id,
                    component=component,
                    description=desc[:500],
                    severity=severity.upper() if severity else "",
                    cvss_score=cvss_score,
                    references=refs,
                    match_type="nvd",
                ))

            return results

        except Exception:
            return []

    def query_nvd_batch(self, versions: dict) -> list[VulnMatch]:
        """
        批量查询 NVD，对每个组件+版本组合查询
        versions: {"nginx": "1.18.0", "php": "7.4.33", ...}
        """
        all_results = []
        for component, version in versions.items():
            all_results.extend(self.query_nvd(component, version))
        return all_results

    # ── 统计 ─────────────────────────────────────

    @property
    def db_size(self) -> int:
        return len(self._db)

    def db_components(self) -> list[str]:
        """返回数据库覆盖的组件列表"""
        return list(set(e["component"] for e in self._db))
