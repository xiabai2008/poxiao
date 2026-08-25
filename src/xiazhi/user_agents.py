"""
User-Agent 池 & 轮换
====================
提供大量真实浏览器 User-Agent，支持按类型分类

分类:
  - chrome:  Chrome 浏览器 (桌面)
  - firefox: Firefox 浏览器 (桌面)
  - safari:  Safari 浏览器 (桌面)
  - edge:    Edge 浏览器 (桌面)
  - mobile:  移动端浏览器
  - bot:     爬虫/扫描器 UA
  - random:  随机选择
"""

import random
from typing import List


# ── 2024-2026 真实浏览器 UA ──

CHROME_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
]

FIREFOX_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
]

SAFARI_UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
]

EDGE_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]

MOBILE_UAS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.104 Mobile/15E148 Safari/604.1",
]

# 常见中文浏览器
CN_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36",
]


class UserAgentPool:
    """User-Agent 轮换池"""

    # 分类映射
    CATEGORIES = {
        "chrome": CHROME_UAS,
        "firefox": FIREFOX_UAS,
        "safari": SAFARI_UAS,
        "edge": EDGE_UAS,
        "mobile": MOBILE_UAS,
        "cn": CN_BROWSER_UAS,
    }

    def __init__(self):
        """初始化 UA 池（加载内置浏览器 UA 列表）"""
        self._used = set()  # 避免连续重复

    def get(self, category: str = "random") -> str:
        """获取随机 UA"""
        if category == "random":
            # 加权随机: Chrome 50%, Firefox 20%, Safari 15%, Edge 10%, Mobile 5%
            weights = {
                "chrome": 50,
                "firefox": 20,
                "safari": 15,
                "edge": 10,
                "mobile": 5,
            }
            categories = list(weights.keys())
            w = list(weights.values())
            category = random.choices(categories, weights=w, k=1)[0]

        pool = self.CATEGORIES.get(category, CHROME_UAS)

        # 避免连续重复
        for _ in range(10):
            ua = random.choice(pool)
            if ua not in self._used:
                self._used.add(ua)
                if len(self._used) > 50:
                    self._used.clear()
                return ua

        return random.choice(pool)

    def get_mobile(self) -> str:
        """获取移动端 UA"""
        return random.choice(MOBILE_UAS)

    def get_desktop(self) -> str:
        """获取桌面 UA"""
        all_desktop = CHROME_UAS + FIREFOX_UAS + SAFARI_UAS + EDGE_UAS
        return random.choice(all_desktop)

    def get_matching_headers(self, ua: str) -> dict:
        """根据 UA 生成匹配的请求头"""
        headers = {"User-Agent": ua}

        if "Chrome" in ua and "Edg" not in ua:
            headers["Sec-Ch-Ua"] = '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"'
            headers["Sec-Ch-Ua-Mobile"] = "?0" if "Mobile" not in ua else "?1"
            headers["Sec-Ch-Ua-Platform"] = self._extract_platform(ua)
        elif "Edg" in ua:
            headers["Sec-Ch-Ua"] = '"Chromium";v="131", "Microsoft Edge";v="131", "Not_A Brand";v="24"'
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = '"Windows"'
        elif "Firefox" in ua:
            pass  # Firefox 不发 Sec-Ch-Ua

        return headers

    def _extract_platform(self, ua: str) -> str:
        """从 UA 提取平台"""
        if "Windows" in ua:
            return '"Windows"'
        elif "Macintosh" in ua or "Mac OS" in ua:
            return '"macOS"'
        elif "Linux" in ua and "Android" not in ua:
            return '"Linux"'
        elif "Android" in ua:
            return '"Android"'
        elif "iPhone" in ua or "iPad" in ua:
            return '"iOS"'
        return '"Windows"'

    def all_uas(self) -> List[str]:
        """获取所有 UA"""
        all_ua = []
        for pool in self.CATEGORIES.values():
            all_ua.extend(pool)
        return list(set(all_ua))
