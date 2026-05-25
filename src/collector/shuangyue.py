"""霜月 — 子域名收集器

技术: crt.sh 证书透明日志 + DNS 字典爆破 + 存活验证
"""

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx
import dns.resolver


@dataclass
class Subdomain:
    """子域名"""
    domain: str
    source: str = ""        # crtsh / dns_brute / search
    ip: str = ""
    alive: bool = False
    status_code: int = 0
    title: str = ""

    def to_url(self) -> str:
        return f"https://{self.domain}"


# ── 常见子域名字典 ─────────────────────────────────

COMMON_SUBDOMAINS = [
    # 通用
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "smtp", "webmail", "email",
    # 管理
    "admin", "manage", "manager", "sys", "system", "console",
    "dashboard", "control", "panel", "cpanel", "webmaster",
    # 开发/测试
    "dev", "test", "demo", "staging", "stage", "uat", "qa",
    "beta", "alpha", "sandbox", "pre", "preview", "lab",
    # API/服务
    "api", "api2", "api3", "open", "openapi", "service",
    "services", "ws", "webservice", "rest", "gateway",
    # 应用
    "app", "apps", "m", "mobile", "wap", "touch", "h5",
    "static", "assets", "cdn", "img", "images", "image",
    "upload", "download", "dl", "media", "video", "vod",
    # 业务
    "blog", "bbs", "forum", "community", "club", "wiki",
    "help", "support", "faq", "docs", "doc", "manual",
    "shop", "store", "mall", "buy", "pay", "order",
    "member", "user", "account", "passport", "login", "sso",
    "job", "jobs", "hr", "career", "about", "news",
    # 安全
    "vpn", "remote", "secure", "ssl", "auth", "oauth",
    # 国内特色
    "erp", "oa", "crm", "mail2", "mails", "email2",
    "test2", "dev2", "beta2", "app2", "m2", "wap2",
]


class ShuangYue:
    """霜月 — 子域名收集器"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5

    # ── crt.sh 证书透明 ──────────────────────────

    def _crt_sh(self, domain: str) -> list[str]:
        """通过 crt.sh 证书透明日志获取子域名"""
        subdomains = set()

        # 尝试多个 crt.sh URL 格式
        urls = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://crt.sh/?q=%.{domain}&output=json",
        ]
        for url in urls:
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
                break  # 成功就不用试第二个 URL 了
            except Exception:
                continue

        # 备用: 通过 AlienVault OTX
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

    # ── DNS 字典爆破 ─────────────────────────────

    def _dns_brute(self, domain: str, wordlist: list[str] = None) -> list[str]:
        """DNS 字典爆破"""
        if wordlist is None:
            wordlist = COMMON_SUBDOMAINS

        found = []
        for prefix in wordlist:
            target = f"{prefix}.{domain}"
            try:
                answers = self.resolver.resolve(target, "A")
                for a in answers:
                    found.append(target)
                    break  # 一个就够了
            except Exception:
                pass
        return found

    # ── 存活验证 ─────────────────────────────────

    async def _check_alive(self, subdomain: str, client: httpx.AsyncClient) -> Optional[Subdomain]:
        """异步检测子域名 http/https 是否存活"""
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                resp = await client.get(url, timeout=self.timeout)
                title = ""
                m = re.search(r"<title[^>]*>(.+?)</title>", resp.text, re.IGNORECASE)
                if m:
                    title = m.group(1).strip()

                # 解析 IP
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

        # 1. crt.sh
        if use_crtsh:
            crt_results = self._crt_sh(domain)
            for s in crt_results:
                all_subs.add(s)
                sources[s] = "crtsh"

        # 2. DNS 爆破
        if use_brute:
            brute_results = self._dns_brute(domain)
            for s in brute_results:
                if s not in all_subs:
                    all_subs.add(s)
                    sources[s] = "dns_brute"

        results = []

        # 3. 存活验证
        if check_alive and all_subs:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                sem = asyncio.Semaphore(10)

                async def verify(sub: str):
                    async with sem:
                        alive = await self._check_alive(sub, client)
                        if alive:
                            alive.source = sources.get(sub, "unknown")
                            return alive
                        return Subdomain(domain=sub, source=sources.get(sub, "unknown"))

                tasks = [verify(s) for s in all_subs]
                results = await asyncio.gather(*tasks)
        else:
            results = [
                Subdomain(domain=s, source=sources.get(s, "unknown"))
                for s in all_subs
            ]

        # 按存活优先排序
        results.sort(key=lambda x: (-x.alive, x.domain))
        return results

    def collect_sync(self, domain: str, **kwargs) -> list[Subdomain]:
        """同步版"""
        return asyncio.run(self.collect(domain, **kwargs))


# ── 命令行 ─────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python shuangyue.py <domain> [--no-alive]")
        sys.exit(1)

    domain = sys.argv[1]
    check = "--no-alive" not in sys.argv

    sy = ShuangYue()
    subs = asyncio.run(sy.collect(domain, check_alive=check))

    alive = [s for s in subs if s.alive]
    dead = [s for s in subs if not s.alive]

    print(f"\n{sys.argv[1]} — 共 {len(subs)} 个子域名")
    print(f"  存活: {len(alive)}")
    print(f"  未验证/不可达: {len(dead)}")
    print()

    for s in alive:
        print(f"  ✅ {s.domain:40s} [{s.status_code}] {s.title[:50]} ({s.source})")
    for s in dead[:10]:
        print(f"  ❌ {s.domain:40s} ({s.source})")
    if len(dead) > 10:
        print(f"  ... 共 {len(dead)} 个")
