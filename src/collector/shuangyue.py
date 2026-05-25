"""霜月 — 子域名收集器 v2

技术: crt.sh + certspotter + AlienVault + DNS字典爆破 + 泛解析检测
"""

import asyncio
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx
import dns.resolver


@dataclass
class Subdomain:
    """子域名"""
    domain: str
    source: str = ""
    ip: str = ""
    alive: bool = False
    status_code: int = 0
    title: str = ""
    category: str = ""  # admin / dev / api / portal / cdn / mail / unknown

    def to_url(self) -> str:
        return f"https://{self.domain}"


# ── 分类映射 ────────────────────────────────────

_CATEGORY_MAP = {
    "admin": ["admin", "manage", "manager", "sys", "system", "console",
              "dashboard", "control", "panel", "cpanel", "webmaster"],
    "dev": ["dev", "test", "demo", "staging", "stage", "uat", "qa",
            "beta", "alpha", "sandbox", "pre", "preview", "lab", "debug"],
    "api": ["api", "open", "openapi", "service", "services", "ws",
            "webservice", "rest", "gateway", "graphql"],
    "portal": ["app", "m", "mobile", "wap", "touch", "h5", "www"],
    "cdn": ["static", "assets", "cdn", "img", "images", "image",
            "upload", "download", "dl", "media", "video", "vod"],
    "mail": ["mail", "webmail", "email", "smtp", "pop", "imap",
             "mx", "mail2", "mails", "email2"],
    "biz": ["blog", "bbs", "forum", "community", "club", "wiki",
            "help", "support", "faq", "docs", "doc", "manual",
            "shop", "store", "mall", "buy", "pay", "order",
            "member", "user", "account", "passport", "login", "sso",
            "job", "jobs", "hr", "career", "about", "news"],
    "internal": ["erp", "oa", "crm", "vpn", "remote", "secure",
                 "ssl", "auth", "oauth", "sso", "ns1", "ns2", "dns"],
}


def _classify(subdomain: str) -> str:
    """根据前缀分类"""
    prefix = subdomain.split(".")[0].lower()
    for cat, prefixes in _CATEGORY_MAP.items():
        if prefix in prefixes:
            return cat
    return "unknown"


# ── 子域名字典（扩展版）──────────────────────────

COMMON_SUBDOMAINS = [
    # 通用服务
    "www", "mail", "webmail", "email", "smtp", "pop", "imap", "mx",
    "ftp", "sftp", "ns1", "ns2", "dns", "dns1", "dns2",
    # 管理后台
    "admin", "manage", "manager", "sys", "system", "console",
    "dashboard", "control", "panel", "cpanel", "webmaster",
    # 开发测试
    "dev", "test", "demo", "staging", "stage", "uat", "qa",
    "beta", "alpha", "sandbox", "pre", "preview", "lab", "debug",
    "gray", "canary", "dev2", "test2", "beta2", "test3",
    # API / 微服务
    "api", "api2", "api3", "open", "openapi", "service", "services",
    "ws", "webservice", "rest", "gateway", "graphql", "rpc", "grpc",
    # 前端 / 移动端
    "app", "apps", "m", "mobile", "wap", "touch", "h5", "pc",
    "static", "assets", "cdn", "cdn1", "cdn2", "image", "images",
    "img", "upload", "download", "dl", "media", "video", "vod", "live",
    # 业务系统
    "blog", "bbs", "forum", "community", "club", "wiki",
    "help", "support", "faq", "docs", "doc", "manual", "kb",
    "shop", "store", "mall", "buy", "pay", "order", "trade",
    "member", "user", "account", "passport", "login", "sso", "uc",
    "job", "jobs", "hr", "career", "about", "news", "press",
    "data", "report", "bi", "monitor", "log", "elk", "grafana",
    # 安全
    "vpn", "remote", "secure", "ssl", "auth", "oauth", "sso",
    # 中国企业特色
    "erp", "oa", "crm", "scm", "wms", "mes", "ehr",
    "mail2", "mails", "email2", "app2", "m2", "wap2",
    "ec", "b2b", "b2c", "c2c", "o2o",
    "wechat", "wx", "mp", "miniapp",
    # 其他
    "backup", "backup2", "old", "new", "v2", "v3",
    "en", "cn", "global", "intl", "hk", "us",
    "jenkins", "gitlab", "git", "svn", "nexus", "harbor",
    "kibana", "prometheus", "alertmanager", "zabbix", "nagios",
    "jira", "confluence", "wiki2",
]


class ShuangYue:
    """霜月 — 子域名收集器 v2"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
        self._wildcard_ips: set[str] = set()

    # ── 泛解析检测 ──────────────────────────────

    def _detect_wildcard(self, domain: str) -> bool:
        """检测 DNS 泛解析"""
        rand_sub = f"_shuangyue_wildcard_test_{id(self)}.{domain}"
        try:
            answers = self.resolver.resolve(rand_sub, "A")
            for a in answers:
                self._wildcard_ips.add(str(a))
            return len(self._wildcard_ips) > 0
        except Exception:
            return False

    def _is_wildcard(self, subdomain: str) -> bool:
        """判断是否是泛解析"""
        if not self._wildcard_ips:
            return False
        try:
            answers = self.resolver.resolve(subdomain, "A")
            for a in answers:
                if str(a) in self._wildcard_ips:
                    return True
        except Exception:
            pass
        return False

    # ── 证书透明源 ──────────────────────────────

    def _crt_sh(self, domain: str) -> list[str]:
        """crt.sh + certspotter 证书透明"""
        subdomains = set()

        # crt.sh
        for url in [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://crt.sh/?q=%.{domain}&output=json",
        ]:
            try:
                resp = httpx.get(url, timeout=15, follow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    continue
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", entry.get("common_name", ""))
                    for line in name.split("\n"):
                        line = line.strip().lower().rstrip(".")
                        if line.startswith("*."):
                            line = line[2:]
                        if line.endswith(f".{domain}") or line == domain:
                            subdomains.add(line)
                break
            except Exception:
                continue

        # certspotter (备用)
        if not subdomains:
            try:
                url = f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names"
                resp = httpx.get(url, timeout=15,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    for entry in resp.json():
                        for name in entry.get("dns_names", []):
                            name = name.strip().lower().rstrip(".")
                            if name.endswith(f".{domain}") or name == domain:
                                subdomains.add(name)
            except Exception:
                pass

        # AlienVault OTX
        if not subdomains:
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
                resp = httpx.get(url, timeout=10,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    for entry in resp.json().get("passive_dns", []):
                        hostname = entry.get("hostname", "").strip().lower().rstrip(".")
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            subdomains.add(hostname)
            except Exception:
                pass

        return list(subdomains)

    # ── DNS 字典爆破（异步）─────────────────────

    async def _dns_brute(self, domain: str, wordlist: list[str] = None) -> list[str]:
        """DNS 字典爆破（带泛解析过滤，异步）"""
        if wordlist is None:
            wordlist = COMMON_SUBDOMAINS

        import concurrent.futures

        def _resolve_one(target: str) -> Optional[str]:
            try:
                answers = self.resolver.resolve(target, "A")
                ips = [str(a) for a in answers]
                if self._wildcard_ips and all(ip in self._wildcard_ips for ip in ips):
                    return None
                return target
            except Exception:
                return None

        loop = asyncio.get_event_loop()
        found = []
        sem = asyncio.Semaphore(20)  # 并发 DNS 查询

        async def worker(prefix: str):
            async with sem:
                target = f"{prefix}.{domain}"
                result = await loop.run_in_executor(None, _resolve_one, target)
                if result:
                    found.append(result)

        await asyncio.gather(*[worker(p) for p in wordlist])
        return found

    # ── 存活验证 ─────────────────────────────────

    async def _check_alive(self, subdomain: str,
                           client: httpx.AsyncClient) -> Optional[Subdomain]:
        """异步检测 http/https 存活"""
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                resp = await client.get(url, timeout=self.timeout)
                title = ""
                m = re.search(r"<title[^>]*>(.+?)</title>", resp.text, re.IGNORECASE)
                if m:
                    title = m.group(1).strip()

                ip = ""
                try:
                    answers = self.resolver.resolve(subdomain, "A")
                    ip = str(answers[0])
                except Exception:
                    pass

                return Subdomain(
                    domain=subdomain,
                    alive=True,
                    status_code=resp.status_code,
                    title=title[:80],
                    ip=ip,
                    category=_classify(subdomain),
                )
            except Exception:
                continue
        return None

    # ── 主流程 ───────────────────────────────────

    async def collect(
        self,
        domain: str,
        use_crtsh: bool = True,
        use_brute: bool = True,
        check_alive: bool = True,
    ) -> list[Subdomain]:
        """收集子域名"""
        all_subs: set[str] = set()
        sources: dict[str, str] = {}

        # 0. 泛解析检测
        has_wildcard = self._detect_wildcard(domain)

        # 1. 证书透明
        if use_crtsh:
            crt_results = self._crt_sh(domain)
            for s in crt_results:
                all_subs.add(s)
                sources[s] = "crtsh"

        # 2. DNS 爆破
        if use_brute:
            brute_results = await self._dns_brute(domain)
            for s in brute_results:
                if s not in all_subs:
                    all_subs.add(s)
                    sources[s] = "dns_brute"

        # 3. 存活验证
        if check_alive and all_subs:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                sem = asyncio.Semaphore(15)

                async def verify(sub: str):
                    async with sem:
                        alive = await self._check_alive(sub, client)
                        if alive:
                            alive.source = sources.get(sub, "unknown")
                            if self._wildcard_ips and alive.ip in self._wildcard_ips:
                                alive.alive = False  # 泛解析降级
                            return alive
                        return Subdomain(
                            domain=sub,
                            source=sources.get(sub, "unknown"),
                            category=_classify(sub),
                        )

                tasks = [verify(s) for s in all_subs]
                results = await asyncio.gather(*tasks)
        else:
            results = [
                Subdomain(domain=s, source=sources.get(s, "unknown"),
                          category=_classify(s))
                for s in all_subs
            ]

        results.sort(key=lambda x: (-x.alive, x.domain))
        return results

    def collect_sync(self, domain: str, **kwargs) -> list[Subdomain]:
        return asyncio.run(self.collect(domain, **kwargs))

    # ── 导出 ────────────────────────────────────

    def to_target_file(self, subs: list[Subdomain], output_path: str):
        """导出为破晓扫描目标格式"""
        alive = [s for s in subs if s.alive]
        lines = []
        for s in alive:
            lines.append(f"{s.to_url():50s} # {s.title[:30] if s.title else s.category}")
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def summary(self, subs: list[Subdomain]) -> str:
        """生成摘要"""
        alive = [s for s in subs if s.alive]
        by_cat = defaultdict(list)
        for s in alive:
            by_cat[s.category].append(s)

        lines = [
            f"共 {len(subs)} 个子域名 | 存活 {len(alive)}",
            f"  证书透明: {sum(1 for s in subs if s.source == 'crtsh')}",
            f"  DNS 爆破: {sum(1 for s in subs if s.source == 'dns_brute')}",
            f"  泛解析: {'是' if self._wildcard_ips else '否'}",
            "",
            "按类别:",
        ]
        for cat in ["admin", "dev", "api", "portal", "mail", "biz", "internal", "cdn", "unknown"]:
            if cat in by_cat:
                lines.append(f"  {cat:10s}: {len(by_cat[cat])} 个")
        return "\n".join(lines)
