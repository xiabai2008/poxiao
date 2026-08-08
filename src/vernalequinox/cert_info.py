"""
证书透明度深度分析模块
======================
从 SSL/TLS 证书中提取深度情报

数据源:
  - crt.sh (证书透明度日志)
  - 直接连接获取证书详情
  - Censys (需要 API Key, 可选)

功能:
  - 证书 SAN (Subject Alternative Names) 提取 → 发现更多子域名
  - 证书颁发历史 → 域名活跃时间线
  - 证书关联 → 同一组织的其他域名
  - 证书指纹 → JA3/SNI 指纹
  - 自签名证书检测
  - 证书过期提醒
"""

import asyncio
import ssl
import socket
import hashlib
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict


@dataclass
class CertInfo:
    """SSL 证书详细信息"""
    domain: str
    # 基本信息
    subject_cn: str = ""                 # Common Name
    issuer: str = ""                     # 颁发者
    issuer_org: str = ""                 # 颁发组织
    serial_number: str = ""
    not_before: str = ""                 # 生效时间
    not_after: str = ""                  # 过期时间
    is_expired: bool = False
    # SAN
    san_domains: List[str] = field(default_factory=list)   # 所有 SAN 域名
    san_ips: List[str] = field(default_factory=list)        # SAN 中的 IP
    # 指纹
    sha256_fingerprint: str = ""
    sha1_fingerprint: str = ""
    # 扩展信息
    key_type: str = ""                   # RSA / EC
    key_size: int = 0                    # 密钥长度
    signature_algorithm: str = ""
    is_self_signed: bool = False
    is_wildcard: bool = False
    protocol: str = ""                   # TLS 版本
    cipher: str = ""                     # 加密套件
    # crt.sh 历史
    crt_sh_count: int = 0               # crt.sh 中的证书数量
    crt_sh_certs: List[Dict] = field(default_factory=list)  # 历史证书列表
    crt_sh_all_domains: List[str] = field(default_factory=list)  # 所有历史子域名
    # 元数据
    source: str = ""
    error: str = ""

    def to_dict(self):
        return asdict(self)

    @property
    def days_until_expiry(self) -> int:
        """距离过期还有多少天"""
        if not self.not_after:
            return -1
        try:
            # 尝试多种日期格式
            for fmt in ["%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ",
                        "%b  %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S"]:
                try:
                    exp = datetime.strptime(self.not_after.strip(), fmt)
                    return (exp - datetime.now()).days
                except ValueError:
                    continue
        except Exception:
            pass
        return -1


class CertAnalyzer:
    """证书透明度深度分析器"""

    CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    async def analyze(self, domain: str, port: int = 443) -> CertInfo:
        """全面分析域名的 SSL 证书"""
        info = CertInfo(domain=domain)

        # 并发: 直连证书 + crt.sh 历史
        tasks = [
            self._get_live_cert(domain, port),
            self._query_crtsh(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 合并直连证书信息
        if isinstance(results[0], CertInfo):
            live_info = results[0]
            for fld in ["subject_cn", "issuer", "issuer_org", "serial_number",
                        "not_before", "not_after", "is_expired", "san_domains",
                        "san_ips", "sha256_fingerprint", "sha1_fingerprint",
                        "key_type", "key_size", "signature_algorithm",
                        "is_self_signed", "is_wildcard", "protocol", "cipher", "error"]:
                val = getattr(live_info, fld)
                if val:
                    setattr(info, fld, val)
            info.source = "live+history"

        # 合并 crt.sh 历史数据
        if isinstance(results[1], dict):
            crt_data = results[1]
            info.crt_sh_count = crt_data.get("count", 0)
            info.crt_sh_certs = crt_data.get("certs", [])
            info.crt_sh_all_domains = sorted(set(crt_data.get("all_domains", [])))

        return info

    async def _get_live_cert(self, domain: str, port: int = 443) -> CertInfo:
        """直连获取 SSL 证书信息"""
        info = CertInfo(domain=domain, source="live")

        loop = asyncio.get_event_loop()

        def _connect():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            try:
                with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        cert_text = ssock.getpeercert()
                        info.protocol = ssock.version()
                        cipher_info = ssock.cipher()
                        if cipher_info:
                            info.cipher = cipher_info[0]

                        # DER → 解析
                        # 从 DER 格式计算指纹
                        info.sha256_fingerprint = hashlib.sha256(cert).hexdigest()
                        info.sha1_fingerprint = hashlib.sha1(cert).hexdigest()

                        # 从文本格式解析
                        if cert_text:
                            self._parse_cert_text(cert_text, info)

                        return info
            except ssl.SSLCertVerificationError as e:
                # 证书验证失败（可能是自签名）
                info.is_self_signed = True
                info.error = f"SSL verification failed: {str(e)[:100]}"
                # 尝试不验证证书
                try:
                    ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx2.check_hostname = False
                    ctx2.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                        with ctx2.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert(binary_form=True)
                            cert_text = ssock.getpeercert()
                            info.sha256_fingerprint = hashlib.sha256(cert).hexdigest()
                            if cert_text:
                                self._parse_cert_text(cert_text, info)
                except Exception:
                    pass
                return info
            except Exception as e:
                info.error = f"Connection failed: {str(e)[:100]}"
                return info

        return await loop.run_in_executor(None, _connect)

    def _parse_cert_text(self, cert_text: dict, info: CertInfo):
        """解析证书文本格式"""
        # Subject
        subject = cert_text.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    info.subject_cn = attr_value
                elif attr_type == "organizationName":
                    info.issuer_org = attr_value

        # Issuer
        issuer = cert_text.get("issuer", ())
        issuer_parts = []
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                issuer_parts.append(f"{attr_type}={attr_value}")
                if attr_type == "organizationName":
                    info.issuer_org = attr_value
        info.issuer = ", ".join(issuer_parts)

        # 自签名检测
        if info.subject_cn and info.issuer_org:
            if info.subject_cn in info.issuer or info.issuer_org in str(subject):
                info.is_self_signed = True

        # SAN
        san = cert_text.get("subjectAltName", ())
        for san_type, san_value in san:
            if san_type == "DNS":
                info.san_domains.append(san_value)
                if "*" in san_value:
                    info.is_wildcard = True
            elif san_type == "IP":
                info.san_ips.append(san_value)

        # 有效期
        info.not_before = str(cert_text.get("notBefore", ""))
        info.not_after = str(cert_text.get("notAfter", ""))

        # 序列号
        info.serial_number = str(cert_text.get("serialNumber", ""))

        # 过期判断
        days = info.days_until_expiry
        if days >= 0:
            info.is_expired = False
        elif days < 0:
            info.is_expired = True

    async def _query_crtsh(self, domain: str) -> Dict:
        """查询 crt.sh 获取证书历史"""
        import httpx

        result = {"count": 0, "certs": [], "all_domains": []}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    self.CRT_SH_URL.format(domain=domain),
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["count"] = len(data)

                    all_domains = set()
                    certs = []

                    for entry in data[:50]:  # 最多处理 50 条
                        cert_data = {
                            "id": entry.get("id"),
                            "issuer_ca_id": entry.get("issuer_ca_id"),
                            "issuer_name": entry.get("issuer_name", ""),
                            "common_name": entry.get("common_name", ""),
                            "name_value": entry.get("name_value", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                        }
                        certs.append(cert_data)

                        # 提取所有域名
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name and "*" not in name:
                                all_domains.add(name)

                    result["certs"] = certs
                    result["all_domains"] = list(all_domains)

            except Exception as e:
                result["error"] = str(e)

        return result

    async def find_related_domains(self, domain: str) -> List[str]:
        """通过证书关联发现同一组织的其他域名"""
        info = await self.analyze(domain)

        related = set()

        # 1. SAN 中的域名
        for d in info.san_domains:
            if "*" not in d:
                related.add(d)

        # 2. crt.sh 历史域名
        for d in info.crt_sh_all_domains:
            if d != domain:
                related.add(d)

        # 3. 证书颁发者相同 (通过 crt.sh 的 issuer_ca_id)
        # 这里可以进一步查同 issuer 的其他证书

        return sorted(related)

    @staticmethod
    def print_result(info: CertInfo):
        """格式化打印证书信息"""
        if info.error and not info.sha256_fingerprint:
            print(f"  ❌ 证书获取失败: {info.error}")
            return

        print("  🔒 SSL 证书信息")
        print(f"  {'─' * 50}")

        if info.subject_cn:
            print(f"  CN:       {info.subject_cn}")
        if info.issuer:
            print(f"  颁发者:   {info.issuer[:80]}")
        if info.not_before:
            print(f"  生效:     {info.not_before}")
        if info.not_after:
            expiry_days = info.days_until_expiry
            exp_icon = "🔴" if info.is_expired else ("🟡" if expiry_days < 30 else "🟢")
            print(f"  过期:     {info.not_after} {exp_icon} {'已过期' if info.is_expired else f'{expiry_days}天后'}")
        if info.is_wildcard:
            print("  类型:     ⭐ 通配符证书")
        if info.is_self_signed:
            print("  ⚠️  自签名证书")

        # 密钥信息
        if info.key_type:
            print(f"  密钥:     {info.key_type} {info.key_size}bit")
        if info.signature_algorithm:
            print(f"  签名:     {info.signature_algorithm}")

        # 协议
        if info.protocol:
            print(f"  协议:     {info.protocol}")
        if info.cipher:
            print(f"  加密套件: {info.cipher}")

        # SAN
        if info.san_domains:
            print(f"\n  📋 SAN 域名 ({len(info.san_domains)} 个):")
            for d in info.san_domains[:10]:
                print(f"    {d}")
            if len(info.san_domains) > 10:
                print(f"    ... 共 {len(info.san_domains)} 个")
        if info.san_ips:
            print(f"  📋 SAN IP: {', '.join(info.san_ips)}")

        # 指纹
        if info.sha256_fingerprint:
            print(f"\n  SHA256:   {info.sha256_fingerprint[:64]}...")

        # crt.sh 历史
        if info.crt_sh_count:
            print(f"\n  📜 历史证书: {info.crt_sh_count} 个")
            print(f"  历史子域名: {len(info.crt_sh_all_domains)} 个")
