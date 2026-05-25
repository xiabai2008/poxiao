"""技术栈识别 — 通过响应头/HTML/路径特征识别目标技术栈"""

import re
from dataclasses import dataclass, field


@dataclass
class TechFingerprint:
    """技术识别结果"""
    server: str = ""
    language: str = ""
    cms: str = ""
    framework: str = ""
    cdn: str = ""
    waf: str = ""
    extras: dict = field(default_factory=dict)

    @property
    def known(self) -> dict:
        """只返回非空字段"""
        d = {
            "server": self.server,
            "language": self.language,
            "cms": self.cms,
            "framework": self.framework,
            "cdn": self.cdn,
            "waf": self.waf,
        }
        return {k: v for k, v in d.items() if v}


class TechStackDetector:
    """技术栈检测器"""

    # ── Server 指纹 ───────────────────────────────

    SERVER_PATTERNS = [
        ("nginx",     r"nginx[/\d.]*", "server"),
        ("apache",    r"apache[/\d.]*", "server"),
        ("iis",       r"microsoft-iis[/\d.]*", "server"),
        ("tomcat",    r"apache-coyote[/\d.]*|apache-tomcat", "server"),
        ("cloudflare",r"cloudflare", "server"),
        ("caddy",     r"caddy", "server"),
        ("lighttpd",  r"lighttpd[/\d.]*", "server"),
        ("openresty", r"openresty[/\d.]*", "server"),
        ("tengine",   r"tengine[/\d.]*", "server"),
    ]

    def detect_server(self, headers: dict) -> str:
        """从 Server 头识别 Web 服务器"""
        server_header = headers.get("server", "").lower()
        if not server_header:
            # 尝试 X-Powered-By
            server_header = headers.get("x-powered-by", "").lower()
        for name, pattern, _ in self.SERVER_PATTERNS:
            if re.search(pattern, server_header, re.IGNORECASE):
                return name
        return ""

    # ── 语言指纹 ──────────────────────────────────

    LANGUAGE_PATTERNS = [
        # (name, pattern, field)
        # field: "server" = only Server header
        #        "x-powered-by" = only X-Powered-By header
        #        "cookie" = only cookies
        #        "html" = only in HTML body
        #        "header" = any header (Server, X-Powered-By, Set-Cookie, etc.)
        ("php",     r"\bphp[/\d.]*\b", "x-powered-by"),
        ("java",    r"jsp\b|servlet\b|jsessionid", "header"),
        ("java",    r"jsessionid", "cookie"),
        ("python",  r"\bwsgi\b|\bdjango\b|\bflask\b|\btornado\b", "header"),
        ("asp.net", r"x-aspnet|__viewstate|\.aspx\b", "header"),
        ("node.js", r"\bexpress\b|\bkoa\b", "header"),
        # go only if Server header explicitly contains "go" (e.g., Caddy/Go-based)
        ("go",      r"\bgo[/\d.]+\b", "server"),
        ("ruby",    r"\brails\b|\brack\b", "header"),
        # supplement: check HTML for language hints
        ("php",     r"\.php\b|\bphp\b", "html"),
        ("asp.net", r"\.aspx\b", "html"),
    ]

    def detect_language(self, headers: dict, cookies: dict, html: str = "", url: str = "") -> str:
        """识别后端语言 — 优先 header 证据，html 仅作辅助"""
        clues = []
        for name, pattern, field in self.LANGUAGE_PATTERNS:
            if field == "server":
                v = headers.get("server", "")
                if re.search(pattern, v, re.IGNORECASE):
                    clues.append(name)
                    continue
            elif field == "x-powered-by":
                v = headers.get("x-powered-by", "")
                if re.search(pattern, v, re.IGNORECASE):
                    clues.append(name)
                    continue
            elif field == "cookie":
                if cookies:
                    for k in cookies:
                        if re.search(pattern, k, re.IGNORECASE):
                            clues.append(name)
                            break
                    continue
            elif field == "header":
                for h in ("server", "x-powered-by", "set-cookie", "x-aspnet-version"):
                    v = headers.get(h, "")
                    if re.search(pattern, v, re.IGNORECASE):
                        clues.append(name)
                        break
                continue
            elif field == "html":
                if html and re.search(pattern, html[:5000], re.IGNORECASE):
                    clues.append(name)
                    continue

        # HTML 匹配仅作为辅助（权重低于 header）
        return clues[0] if clues else ""

    # ── CMS 指纹 ──────────────────────────────────

    CMS_PATTERNS = [
        # PHP CMS 系
        ("dedecms",     r"dedecms|织梦", "html"),
        ("wordpress",   r"wp-content|wp-includes|wordpress", "any"),
        ("discuz",      r"discuz!|dzbbs|forum\.php", "any"),
        ("thinkphp",    r"thinkphp|think/", "any"),
        ("laravel",     r"laravel", "any"),
        ("yii",         r"yii", "any"),
        ("joomla",      r"joomla", "any"),
        ("drupal",      r"drupal", "any"),
        ("ecshop",      r"ecshop", "any"),
        ("phpcms",      r"phpcms", "any"),
        ("empirecms",   r"帝国cms|empire", "any"),
        ("zblog",       r"zblog|zb_system", "any"),
        ("typecho",     r"typecho", "any"),
        # 教育 CMS
        ("metinfo",     r"metinfo|米拓", "any"),
        # .NET CMS
        ("sitecore",    r"sitecore", "any"),
        ("umbraco",     r"umbraco", "any"),
    ]

    def detect_cms(self, html: str = "", headers: dict = None, url: str = "") -> str:
        """识别 CMS"""
        headers = headers or {}
        all_text = f"{html} {' '.join(headers.values())} {url}".lower()
        for name, pattern, scope in self.CMS_PATTERNS:
            if re.search(pattern, all_text, re.IGNORECASE):
                return name
        return ""

    # ── CDN/WAF 指纹 ──────────────────────────────

    CDN_HEADERS = [
        "x-cdn", "cf-cache-status", "x-amz-cf-id",
        "x-cache", "cdn-cache", "x-cdn-provider",
    ]

    WAF_HEADERS = [
        "x-waf", "x-firewall", "x-protected-by",
        "mod_security", "x-sucuri-id", "x-sucuri-cache",
    ]

    def detect_cdn(self, headers: dict) -> str:
        """检测 CDN"""
        for h in self.CDN_HEADERS:
            if h in headers:
                return "detected"
        # Cloudflare 特判
        if "cloudflare" in headers.get("server", "").lower():
            return "cloudflare"
        return ""

    def detect_waf(self, headers: dict) -> str:
        """检测 WAF"""
        for h in self.WAF_HEADERS:
            if h in headers:
                return headers.get(h, "detected")
        return ""

    # ── 综合检测 ──────────────────────────────────

    def detect(
        self,
        headers: dict = None,
        cookies: dict = None,
        html: str = "",
        url: str = "",
    ) -> TechFingerprint:
        """一次调用，全部检测"""
        headers = headers or {}
        cookies = cookies or {}

        return TechFingerprint(
            server=self.detect_server(headers),
            language=self.detect_language(headers, cookies, html, url),
            cms=self.detect_cms(html, headers, url),
            cdn=self.detect_cdn(headers),
            waf=self.detect_waf(headers),
        )

    def as_tags(self, fp: TechFingerprint) -> list[str]:
        """转为标签列表"""
        tags = []
        if fp.server:
            tags.append(fp.server)
        if fp.language:
            tags.append(fp.language)
        if fp.cms:
            tags.append(fp.cms)
        if fp.framework:
            tags.append(fp.framework)
        if fp.cdn:
            tags.append(f"cdn:{fp.cdn}")
        if fp.waf:
            tags.append(f"waf:{fp.waf}")
        return tags
