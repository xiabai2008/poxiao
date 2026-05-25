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
        ("php",     r"php[/\d.]*", "x-powered-by"),
        ("java",    r"jsp|servlet|jsessionid|jakarta", "any"),
        ("python",  r"python[/\d.]*|wsgi|django|flask|tornado", "any"),
        ("asp.net", r"asp\.net|x-aspnet|__viewstate|\.aspx", "any"),
        ("node.js", r"node\.js|express|koa|next\.js", "any"),
        ("go",      r"go[/\d.]*|gin[/\d.]*", "any"),
        ("ruby",    r"rails|rack|ruby[/\d.]*", "any"),
    ]

    def detect_language(self, headers: dict, cookies: dict, html: str = "", url: str = "") -> str:
        """识别后端语言"""
        clues = []
        for name, pattern, field in self.LANGUAGE_PATTERNS:
            # 检查 HTTP 头
            if field in ("any", "x-powered-by"):
                powered = headers.get("x-powered-by", "")
                server = headers.get("server", "")
                all_headers = " ".join([f"{k}: {v}" for k, v in headers.items()])
                if re.search(pattern, f"{powered} {server} {all_headers}", re.IGNORECASE):
                    clues.append(name)
                    continue
            # 检查 cookie
            if field == "any" and cookies:
                cookie_str = " ".join([f"{k}={v}" for k, v in cookies.items()])
                if re.search(pattern, cookie_str, re.IGNORECASE):
                    clues.append(name)
                    continue
            # 检查 HTML
            if field == "any" and html:
                if re.search(pattern, html, re.IGNORECASE):
                    clues.append(name)
                    continue
            # 检查 URL
            if field == "any" and url:
                if re.search(pattern, url, re.IGNORECASE):
                    clues.append(name)
                    continue
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
