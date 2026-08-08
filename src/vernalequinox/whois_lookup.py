"""
Whois 查询模块
==============
通过 RDAP/Whois 协议查询域名注册信息

数据源:
  - whois 库 (python-whois)
  - RDAP API (免费，无需 API Key)
  - whois.iana.org 作为 fallback
"""

import asyncio
import re
from dataclasses import dataclass, field, asdict


@dataclass
class WhoisResult:
    """Whois 查询结果"""
    domain: str
    registrar: str = ""               # 注册商
    creation_date: str = ""           # 创建时间
    expiration_date: str = ""         # 过期时间
    updated_date: str = ""            # 更新时间
    name_servers: list = field(default_factory=list)  # DNS 服务器
    registrant_name: str = ""         # 注册人
    registrant_org: str = ""          # 注册组织
    registrant_country: str = ""      # 注册国家
    registrant_email: str = ""        # 注册邮箱
    dnssec: str = ""                  # DNSSEC 状态
    status: list = field(default_factory=list)  # 域名状态
    raw_text: str = ""                # 原始 whois 文本
    source: str = ""                  # 数据来源
    error: str = ""

    def to_dict(self):
        return asdict(self)

    @property
    def has_info(self):
        return bool(self.registrar or self.creation_date)


class WhoisLookup:
    """Whois 信息查询"""

    # ── 常见 RDAP 服务 ──
    RDAP_BOOTSTRAP = "https://rdap.verisign.com/com/v1/domain/{domain}"
    RDAP_CN = "https://rdap.cnnic.cn/rdap/domain/{domain}"

    # ── Whois 正则 ──
    PATTERNS = {
        "registrar": [
            re.compile(r"Registrar:\s*(.+)", re.I),
            re.compile(r"Sponsoring Registrar:\s*(.+)", re.I),
            re.compile(r"注册商:\s*(.+)", re.I),
        ],
        "creation_date": [
            re.compile(r"Creat(?:ion|ed)\s*(?:Date)?:\s*(.+)", re.I),
            re.compile(r"Registration Time:\s*(.+)", re.I),
            re.compile(r"注册时间:\s*(.+)", re.I),
        ],
        "expiration_date": [
            re.compile(r"Expir(?:ation|y)\s*(?:Date)?:\s*(.+)", re.I),
            re.compile(r"到期时间:\s*(.+)", re.I),
        ],
        "updated_date": [
            re.compile(r"Updated?\s*(?:Date)?:\s*(.+)", re.I),
            re.compile(r"最后更新时间:\s*(.+)", re.I),
        ],
        "name_servers": [
            re.compile(r"Name Server:\s*(.+)", re.I),
            re.compile(r"nserver:\s*(.+)", re.I),
        ],
        "registrant_name": [
            re.compile(r"Registrant\s*Name:\s*(.+)", re.I),
            re.compile(r"Registrant:\s*(.+)", re.I),
        ],
        "registrant_org": [
            re.compile(r"Registrant\s*Organization:\s*(.+)", re.I),
            re.compile(r"Registrant Org:\s*(.+)", re.I),
        ],
        "registrant_country": [
            re.compile(r"Registrant\s*Country:\s*(.+)", re.I),
        ],
        "registrant_email": [
            re.compile(r"Registrant\s*Email:\s*(.+)", re.I),
            re.compile(r"Registrant Contact Email:\s*(.+)", re.I),
        ],
        "dnssec": [
            re.compile(r"DNSSEC:\s*(.+)", re.I),
        ],
    }

    STATUS_PATTERN = re.compile(r"Domain Status:\s*(\S+)", re.I)

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def query(self, domain: str) -> WhoisResult:
        """查询域名 Whois 信息"""
        result = WhoisResult(domain=domain)

        # 优先用 python-whois 库
        try:
            result = await self._query_whois_lib(domain)
            if result.has_info:
                return result
        except Exception as e:
            result.error = f"whois lib failed: {e}"

        # Fallback: 用 socket 直连 whois 服务器
        try:
            result = await self._query_raw_whois(domain)
            if result.has_info:
                return result
        except Exception as e:
            result.error += f" | raw whois failed: {e}"

        return result

    async def _query_whois_lib(self, domain: str) -> WhoisResult:
        """使用 python-whois 库"""
        import whois
        loop = asyncio.get_event_loop()

        def _sync_query():
            w = whois.whois(domain)
            return w

        w = await loop.run_in_executor(None, _sync_query)

        result = WhoisResult(domain=domain, source="python-whois")

        # python-whois 返回的对象属性
        def _get(attr, default=""):
            val = getattr(w, attr, default)
            if isinstance(val, list):
                return val
            if val is None:
                return default
            return str(val).strip()

        result.registrar = _get("registrar")
        result.dnssec = _get("dnssec")
        result.status = _get("status") if isinstance(_get("status"), list) else [_get("status")]

        # 日期处理
        for attr in ["creation_date", "expiration_date", "updated_date"]:
            val = _get(attr)
            if isinstance(val, list) and val:
                val = str(val[0])
            setattr(result, attr, str(val) if val else "")

        # Name servers
        ns = _get("name_servers")
        if isinstance(ns, str):
            ns = [ns]
        result.name_servers = [n.lower().strip(".") for n in ns if n]

        # 注册人
        result.registrant_name = _get("name")
        result.registrant_org = _get("org")
        result.registrant_country = _get("country")
        result.registrant_email = _get("emails") if isinstance(_get("emails"), str) else ""

        return result

    async def _query_raw_whois(self, domain: str) -> WhoisResult:
        """直接 socket 连接 whois 服务器查询"""
        import socket

        # 确定 whois 服务器
        tld = domain.split(".")[-1].lower()
        whois_servers = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "cn": "whois.cnnic.cn",
            "io": "whois.nic.io",
            "info": "whois.afilias.net",
            "me": "whois.nic.me",
            "co": "whois.nic.co",
            "cc": "whois.nic.cc",
            "tv": "whois.nic.tv",
            "biz": "whois.biz",
            "us": "whois.nic.us",
        }
        server = whois_servers.get(tld, f"whois.nic.{tld}")

        loop = asyncio.get_event_loop()

        def _sync_query():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))
            sock.sendall(f"{domain}\r\n".encode())
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
            sock.close()
            return response.decode("utf-8", errors="ignore")

        raw = await loop.run_in_executor(None, _sync_query)

        result = WhoisResult(domain=domain, raw_text=raw, source="raw-whois")

        # 解析字段
        for field_name, patterns in self.PATTERNS.items():
            for pat in patterns:
                m = pat.search(raw)
                if m:
                    val = m.group(1).strip()
                    if field_name == "name_servers":
                        result.name_servers.append(val.lower().strip("."))
                    else:
                        setattr(result, field_name, val)
                    break

        # 域名状态
        result.status = self.STATUS_PATTERN.findall(raw)

        return result

    @staticmethod
    def print_result(r: WhoisResult):
        """格式化打印 Whois 结果"""
        if r.error and not r.has_info:
            print(f"  ❌ Whois 查询失败: {r.error}")
            return

        print(f"  📋 Whois 信息 ({r.source})")
        print(f"  {'─' * 50}")
        if r.registrar:
            print(f"  注册商:     {r.registrar}")
        if r.creation_date:
            print(f"  创建时间:   {r.creation_date}")
        if r.expiration_date:
            print(f"  过期时间:   {r.expiration_date}")
        if r.registrant_org:
            print(f"  注册组织:   {r.registrant_org}")
        if r.registrant_name:
            print(f"  注册人:     {r.registrant_name}")
        if r.registrant_country:
            print(f"  注册国家:   {r.registrant_country}")
        if r.registrant_email:
            print(f"  注册邮箱:   {r.registrant_email}")
        if r.name_servers:
            print(f"  DNS 服务器: {', '.join(r.name_servers[:5])}")
        if r.dnssec:
            print(f"  DNSSEC:     {r.dnssec}")
        if r.status:
            print(f"  状态:       {', '.join(r.status[:3])}")
