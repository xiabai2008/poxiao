"""CVE 匹配 — 技术栈 + 版本 → 已知漏洞

内置常见中文 CMS 漏洞库 + NVD API 查询接口
"""

import json
from dataclasses import dataclass
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

    def __post_init__(self):
        if self.references is None:
            self.references = []

    @property
    def is_critical(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH") or self.cvss_score >= 7.0


# ── 内置漏洞库（常见中文 CMS + 基础设施漏洞）─────

BUILTIN_VULNS = [
    # === Nginx ===
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
    # === Apache ===
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
    # === PHP ===
    {
        "component": "php",
        "cve": "CVE-2024-4577",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "PHP CGI Windows 平台参数注入 RCE (已被大规模利用)",
        "affected": "< 8.3.8 / < 8.2.20 / < 8.1.29",
        "fixed": "8.3.8 / 8.2.20 / 8.1.29",
    },
    # === DedeCMS (织梦) ===
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
    # === ThinkPHP ===
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
    # === Discuz! ===
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
    # === WordPress ===
    {
        "component": "wordpress",
        "cve": "CVE-2024-4439",
        "severity": "MEDIUM",
        "cvss": 6.4,
        "description": "WordPress Core < 6.5.2 存储型 XSS (Avatar)",
        "affected": "< 6.5.2",
        "fixed": "6.5.2",
    },
    # === Tomcat ===
    {
        "component": "tomcat",
        "cve": "CVE-2025-24813",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Tomcat 路径等价缺陷 → RCE（已被活跃利用）",
        "affected": "9.0.0-M1 ~ 9.0.98 / 10.1.0-M1 ~ 10.1.34 / 11.0.0-M1 ~ 11.0.2",
        "fixed": "9.0.99 / 10.1.35 / 11.0.3",
    },
    # === Struts2 ===
    {
        "component": "struts2",
        "cve": "CVE-2023-50164",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Struts2 文件上传路径穿越 → RCE",
        "affected": "2.0.0 - 2.3.37 / 2.5.0 - 2.5.32 / 6.0.0 - 6.3.0",
        "fixed": "2.5.33 / 6.3.0.1",
    },
    # === Laravel ===
    {
        "component": "laravel",
        "cve": "CVE-2021-3129",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Laravel <= 8.4.2 Debug Mode RCE (Ignition)",
        "affected": "<= 8.4.2",
        "fixed": "8.4.3",
    },
    # === Spring ===
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
    # === Fastjson ===
    {
        "component": "fastjson",
        "cve": "CVE-2022-25845",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Fastjson <= 1.2.80 反序列化 RCE",
        "affected": "<= 1.2.80",
        "fixed": "1.2.83",
    },
    # === Shiro ===
    {
        "component": "shiro",
        "cve": "CVE-2022-40664",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache Shiro < 1.10.0 认证绕过",
        "affected": "< 1.10.0",
        "fixed": "1.10.0",
    },
    # === IIS ===
    {
        "component": "iis",
        "cve": "CVE-2017-7269",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "IIS 6.0 WebDAV 远程缓冲区溢出 RCE",
        "affected": "IIS 6.0 (Windows Server 2003)",
        "fixed": "已EOL",
    },
]


class CVEMatcher:
    """CVE 匹配器"""

    def __init__(self):
        self._db = BUILTIN_VULNS

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
        )

    @staticmethod
    def _version_in_range(version: str, affected: str) -> bool:
        """简单版本范围检查"""
        # 移除前缀 v/V
        ver = version.lstrip("vV")
        try:
            parts = [int(x) for x in ver.split(".")]
        except ValueError:
            return True  # 无法解析版本 → 保守匹配

        # "< 1.20.1"
        m = __import__("re").match(r"<\s*v?([\d.]+)", affected)
        if m:
            limit = [int(x) for x in m.group(1).split(".")]
            return parts < limit

        # "<= 1.20.1"
        m = __import__("re").match(r"<=\s*v?([\d.]+)", affected)
        if m:
            limit = [int(x) for x in m.group(1).split(".")]
            return parts <= limit

        # "1.2.3 - 1.5.0" 或 ">= 1.2, < 1.5"
        m = __import__("re").match(r"v?([\d.]+)\s*-\s*v?([\d.]+)", affected)
        if m:
            lo = [int(x) for x in m.group(1).split(".")]
            hi = [int(x) for x in m.group(2).split(".")]
            return lo <= parts <= hi

        return True  # 无法解析 → 保守匹配

    # ── NVD API 查询（需要网络）──────────────────

    def query_nvd(self, component: str, version: str = "") -> list[VulnMatch]:
        """
        通过 NVD API 查询漏洞（需要网络访问 api.nvd.nist.gov）
        """
        try:
            import requests

            params = {"keywordSearch": component, "resultsPerPage": 10}
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                timeout=10,
                headers={"User-Agent": "PoXiao/0.1"},
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            results = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # 提取描述
                desc_list = cve.get("descriptions", [])
                desc = desc_list[0].get("value", "") if desc_list else ""

                # 提取 CVSS 评分
                metrics = cve.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
                cvss_score = cvss_v31.get("cvssData", {}).get("baseScore", 0)
                severity = cvss_v31.get("cvssData", {}).get("baseSeverity", "")

                results.append(VulnMatch(
                    cve_id=cve_id,
                    component=component,
                    description=desc[:500],
                    severity=severity,
                    cvss_score=cvss_score,
                    match_type="nvd",
                ))

            return results

        except Exception:
            return []

    # ── 统计 ─────────────────────────────────────

    @property
    def db_size(self) -> int:
        return len(self._db)

    def db_components(self) -> list[str]:
        """返回数据库覆盖的组件列表"""
        return list(set(e["component"] for e in self._db))
