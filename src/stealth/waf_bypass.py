"""
WAF 绕过技术
============
各种 WAF/IDS 绕过策略

技术:
  - Header 伪装 (伪装来源)
  - 请求分块 (Chunked Transfer)
  - URL 编码变体
  - HTTP 参数污染
  - 请求节奏变化
  - 来源伪造
"""

import random
import urllib.parse
from typing import Dict, List, Optional


class WAFBypass:
    """WAF 绕过技术库"""

    # ── 常见 WAF 指纹 ──
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "akamai": ["x-akamai", "akamai-origin-hop"],
        "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
        "incapsula": ["x-iinfo", "incap_ses"],
        "sucuri": ["x-sucuri-id", "server: sucuri"],
        "mod_security": ["mod_security", "modsecurity"],
        "f5_bigip": ["server: bigip", "x-cnection"],
        "华为云waf": ["x-hw-waf"],
        "腾讯云waf": ["x-tw-waf"],
        "阿里云waf": ["eagleid"],
    }

    # ── 伪造来源 Header ──
    FAKE_ORIGINS = [
        "https://www.google.com",
        "https://www.bing.com",
        "https://www.baidu.com",
        "https://search.yahoo.com",
        "https://www.sogou.com",
        "https://www.so.com",
    ]

    FAKE_REFERERS = [
        "https://www.google.com/",
        "https://www.baidu.com/s?wd={query}",
        "https://www.bing.com/search?q={query}",
        "https://search.yahoo.com/search?p={query}",
        "https://www.sogou.com/web?query={query}",
    ]

    # ── 真实 Accept Header ──
    ACCEPT_HEADERS = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "application/json, text/plain, */*",
        "*/*",
    ]

    # ── Accept-Language ──
    ACCEPT_LANGUAGES = [
        "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "en-GB,en;q=0.9",
        "ja,en-US;q=0.9,en;q=0.8",
    ]

    def __init__(self):
        self._request_count = 0

    def detect_waf(self, headers: Dict[str, str], body: str = "") -> Optional[str]:
        """检测 WAF 类型"""
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
        body_lower = body.lower() if body else ""

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in header_str or sig in body_lower:
                    return waf_name

        # 检测通用 WAF 特征
        waf_block_keywords = [
            "access denied", "blocked", "forbidden", "request rejected",
            "security violation", "waf", "firewall", "security policy",
            "请完成安全验证", "访问被拒绝", "请求被拦截",
        ]
        for kw in waf_block_keywords:
            if kw in body_lower:
                return "generic_waf"

        return None

    def get_stealth_headers(self, domain: str = "") -> Dict[str, str]:
        """生成隐匿请求头"""
        from .user_agents import UserAgentPool
        ua_pool = UserAgentPool()

        ua = ua_pool.get("random")
        headers = ua_pool.get_matching_headers(ua)

        # 基础头
        headers.update({
            "Accept": random.choice(self.ACCEPT_HEADERS),
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        })

        # 随机添加一些可选头
        if random.random() < 0.3:
            headers["DNT"] = "1"

        if random.random() < 0.2:
            headers["Pragma"] = "no-cache"

        return headers

    def get_fake_referer(self, domain: str = "") -> str:
        """获取伪造 Referer"""
        if domain:
            # 30% 概率用同域 Referer
            if random.random() < 0.3:
                return f"https://{domain}/"

        # 70% 概率用搜索引擎 Referer
        referer = random.choice(self.FAKE_REFERERS)
        if "{query}" in referer:
            query = random.choice([
                "login", "home", "index", "search", "about",
                "contact", "help", "docs", "api", "admin",
            ])
            referer = referer.replace("{query}", query)
        return referer

    def encode_payload(self, payload: str, level: int = 1) -> str:
        """URL 编码负载 (多层编码绕过)"""
        encoded = payload
        for _ in range(level):
            encoded = urllib.parse.quote(encoded, safe="")
        return encoded

    def chunk_payload(self, payload: str) -> List[str]:
        """分块负载"""
        chunk_size = max(1, len(payload) // 3)
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunks.append(payload[i:i + chunk_size])
        return chunks

    def get_request_interval(self, base_interval: float = 1.0,
                             jitter: float = 0.5) -> float:
        """获取随机请求间隔 (模拟人类行为)"""
        # 基础间隔 + 随机抖动
        interval = base_interval + random.uniform(-jitter, jitter)
        # 偶尔长时间暂停 (模拟人类思考)
        if random.random() < 0.05:
            interval += random.uniform(2.0, 5.0)
        return max(0.1, interval)

    def should_pause(self, request_count: int) -> float:
        """判断是否需要暂停 (避免触发速率限制)"""
        self._request_count = request_count

        # 每 100 个请求暂停 5-15 秒
        if request_count > 0 and request_count % 100 == 0:
            return random.uniform(5.0, 15.0)

        # 每 50 个请求暂停 1-3 秒
        if request_count > 0 and request_count % 50 == 0:
            return random.uniform(1.0, 3.0)

        return 0.0

    @staticmethod
    def random_case(s: str) -> str:
        """随机大小写 (绕过关键词过滤)"""
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def insert_comments(s: str) -> str:
        """在 SQL 中插入注释 (绕过 SQL 注入过滤)"""
        # 在关键字前后插入注释
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT",
                     "UPDATE", "DELETE", "DROP", "TABLE", "ORDER", "GROUP"]
        result = s
        for kw in keywords:
            if kw in result.upper():
                # 在关键字前后插入注释
                idx = result.upper().find(kw)
                result = result[:idx] + "/**/" + result[idx:]
        return result
