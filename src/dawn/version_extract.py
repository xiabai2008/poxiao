"""版本号提取 — 从 HTTP 头、HTML、脚本路径和 Cookie 中提取精确版本"""

import re
from dataclasses import dataclass


@dataclass
class VersionInfo:
    """版本信息"""
    component: str      # nginx / php / wordpress / jquery
    version: str        # 1.24.0 / 7.4.33 / 6.2.2
    source: str = ""    # server-header / powered-by / meta / script / comment / cookie
    raw: str = ""       # 原始匹配文本

    def __str__(self):
        return f"{self.component}@{self.version}"


# ── 预编译正则缓存 ──────────────────────────────────

def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    """编译并缓存正则"""
    return re.compile(pattern, flags)


class VersionExtractor:
    """版本号提取器"""

    # ── HTTP 头版本 ──────────────────────────────

    HEADER_VERSION_PATTERNS = [
        # (header_name, component, regex)
        # Web servers
        ("server", "nginx",        r"nginx/([\d.]+)"),
        ("server", "apache",       r"apache[/\s]*([\d.]+)"),
        ("server", "iis",          r"microsoft-iis/([\d.]+)"),
        ("server", "tomcat",       r"apache-coyote/([\d.]+)"),
        ("server", "openresty",    r"openresty/([\d.]+)"),
        ("server", "tengine",      r"tengine/([\d.]+)"),
        ("server", "caddy",        r"caddy/([\d.]+)"),
        ("server", "caddy",        r"caddy"),           # 无版本号也标记
        ("server", "litespeed",    r"litespeed/([\d.]+)"),
        ("server", "litespeed",    r"openlitespeed/([\d.]+)"),
        ("server", "cloudflare",   r"cloudflare"),
        ("server", "gunicorn",     r"gunicorn/([\d.]+)"),
        ("server", "uvicorn",      r"uvicorn"),
        ("server", "aws",          r"amazons3"),
        ("server", "lighttpd",     r"lighttpd/([\d.]+)"),
        ("server", "cherokee",     r"cherokee/([\d.]+)"),
        ("server", "zeus",         r"zeus/([\d.]+)"),
        ("server", "bfe",          r"bfe/([\d.]+)"),

        # X-Powered-By
        ("x-powered-by", "php",        r"php/([\d.]+)"),
        ("x-powered-by", "asp.net",    r"asp\.net"),
        ("x-powered-by", "express",    r"express"),
        ("x-powered-by", "rails",      r"phusion\s*passenger|mod_rack"),
        ("x-powered-by", "servlet",    r"servlet"),
        ("x-powered-by", "java",       r"java"),
        ("x-powered-by", "perl",       r"mod_perl/([\d.]+)"),
        ("x-powered-by", "perl",       r"mod_perl"),
        ("x-powered-by", "python",     r"mod_python/([\d.]+)"),
        ("x-powered-by", "pjax",       r"pjax"),
        ("x-powered-by", "arr",        r"arr/([\d.]+)"),

        # ASP.NET
        ("x-aspnet-version",     "asp.net",     r"([\d.]+)"),
        ("x-aspnetmvc-version",  "asp.net-mvc", r"([\d.]+)"),

        # Drupal
        ("x-generator",    "drupal", r"drupal\s*([\d.]+)"),
        ("x-drupal-cache", "drupal", r"hit|miss"),

        # Spring Boot
        ("x-application-context", "spring-boot", r"(.+)"),

        # Django
        ("x-frame-options", "django", r"deny"),  # Django 默认 DENY, 不确定但可辅助

        # Cloud / CDN
        ("x-amz-cf-id",      "aws-cloudfront", r"([\w-]+)"),
        ("x-amz-cf-pop",     "aws-cloudfront", r"([\w]+)"),
        ("x-served-by",      "fastly",         r"([\w-]+)"),
        ("x-cache",          "cdn-cache",      r"hit|miss"),
        ("x-cdn",            "cdn",            r"([\w]+)"),
        ("via",              "cdn",            r"([\d.]+)\s+([\w]+)"),

        # Misc frameworks
        ("x-runtime",         "rack",      r"([\d.]+)"),
        ("x-request-id",      "rails",     r"([\w-]+)"),
        ("x-powered-cms",     "cms",       r"([\w]+)"),
    ]

    # ── HTML meta 版本 ───────────────────────────

    META_PATTERNS = [
        _compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']'),
    ]

    CMS_META_MAP = {
        "wordpress":  [_compile(r"wordpress\s*([\d.]+)")],
        "joomla":     [_compile(r"joomla!\s*([\d.]+)")],
        "drupal":     [_compile(r"drupal\s*([\d.]+)")],
        "discuz":     [_compile(r"discuz!\s*x?([\d.]+)")],
        "dedecms":    [_compile(r"dedecms\s*v?([\d.]+)")],
        "magento":    [_compile(r"magento\s*([\d.]+)")],
        "shopify":    [_compile(r"shopify")],
        "woocommerce":[_compile(r"woocommerce\s*([\d.]+)")],
        "ghost":      [_compile(r"ghost\s*([\d.]+)")],
        "hexo":       [_compile(r"hexo\s*([\d.]+)")],
        "hugo":       [_compile(r"hugo\s*([\d.]+)")],
        "jekyll":     [_compile(r"jekyll\s*([\d.]+)")],
        "mediawiki":  [_compile(r"mediawiki\s*([\d.]+)")],
        "phpbb":      [_compile(r"phpbb\s*([\d.]+)")],
        "vbulletin":  [_compile(r"vbulletin\s*([\d.]+)")],
        "moodle":     [_compile(r"moodle\s*([\d.]+)")],
        "canvas":     [_compile(r"canvas\s*(?:lms\s*)?([\d.]+)")],
        "opencart":   [_compile(r"opencart\s*([\d.]+)")],
        "prestashop": [_compile(r"prestashop\s*([\d.]+)")],
        "craft-cms":  [_compile(r"craft\s*cms\s*([\d.]+)")],
        "octobercms": [_compile(r"october\s*cms\s*([\d.]+)")],
        "typo3":      [_compile(r"typo3\s*([\d.]+)")],
        "blogger":    [_compile(r"blogger")],
        "wix":        [_compile(r"wix\.com")],
        "squarespace":[_compile(r"squarespace")],
        "dokuwiki":   [_compile(r"dokuwiki\s*([\d.]+)")],
        "twiki":      [_compile(r"twiki\s*([\d.]+)")],
        "confluence": [_compile(r"confluence\s*([\d.]+)")],
        "sharepoint": [_compile(r"sharepoint\s*([\d.]+)")],
        "sitecore":   [_compile(r"sitecore\s*([\d.]+)")],
        "adobe-experience": [_compile(r"adobe\s*experience\s*manager\s*([\d.]+)")],
    }

    # ── JavaScript 文件路径版本 ────────────────────

    JS_PATH_PATTERNS = [
        # WordPress jQuery
        (_compile(r"/wp-includes/js/jquery/jquery-([\d.]+)(?:\.min)?\.js"), "jquery", "script-path"),
        # 通用 jQuery
        (_compile(r"/(?:js|static|assets|vendor)[/\w-]*jquery[/-]v?([\d.]+)(?:\.min)?\.js"), "jquery", "script-path"),
        # Bootstrap
        (_compile(r"/(?:js|static|assets|vendor)[/\w-]*bootstrap[/-]v?([\d.]+)(?:\.min)?\.js"), "bootstrap", "script-path"),
        # Vue.js
        (_compile(r"/(?:js|static|assets)[/\w-]*vue[.-]v?([\d.]+)(?:\.min)?\.js"), "vue", "script-path"),
        # React
        (_compile(r"/(?:js|static|assets)[/\w-]*react[.-]v?([\d.]+)(?:\.min)?\.js"), "react", "script-path"),
        # Angular
        (_compile(r"/(?:js|static|assets)[/\w-]*angular[.-]v?([\d.]+)(?:\.min)?\.js"), "angular", "script-path"),
        # Lodash
        (_compile(r"/(?:js|static|assets)[/\w-]*lodash[.-]v?([\d.]+)(?:\.min)?\.js"), "lodash", "script-path"),
        # Webpack bundle hash: main.abc123.js or vendor.a1b2c3d4.js
        (_compile(r"/(?:js|static|assets)/([\w-]+)\.([a-f0-9]{6,20})\.js"), "webpack-bundle", "script-path"),
        # Vendor with semver: vendor-1.2.3.js
        (_compile(r"/(?:js|static|assets)/([\w-]+)-(\d+\.\d+\.\d+)\.js"), "js-bundle", "script-path"),
        # WP version in static assets: ?ver=6.2.2
        (_compile(r"[?&]ver=(\d+\.\d+(?:\.\d+)?)"), "wordpress-asset", "script-path"),
    ]

    # ── HTML 内联脚本版本检测 ──────────────────────

    INLINE_SCRIPT_PATTERNS = [
        # React version from meta or data attribute
        (_compile(r'data-reactroot[^>]*react[/@]v?([\d.]+)', re.IGNORECASE), "react"),
        # Vue devtools detection
        (_compile(r'Vue\.version\s*=\s*["\']([\d.]+)["\']'), "vue"),
        # Angular version
        (_compile(r'ng-version="([\d.]+)"'), "angular"),
        # Next.js
        (_compile(r'__NEXT_DATA__\s*='), "next.js"),
        (_compile(r'"next"\s*:\s*"([\d.]+)"'), "next.js"),
        # Nuxt.js
        (_compile(r'__NUXT__\s*='), "nuxt.js"),
        (_compile(r'"nuxt"\s*:\s*"([\d.]+)"'), "nuxt.js"),
        # Gatsby
        (_compile(r'___gatsby'), "gatsby"),
        # SvelteKit
        (_compile(r'data-sveltekit'), "sveltekit"),
    ]

    # ── HTML 注释版本检测 ──────────────────────────

    COMMENT_PATTERNS = [
        (_compile(r"<!--\s*(?:site|page)\s+version:\s*([\d.]+)"), "site-version"),
        (_compile(r"<!--\s*powered\s+by\s+wordpress\s*([\d.]*)", re.IGNORECASE), "wordpress"),
        (_compile(r"<!--\s*joomla!\s*([\d.]*)", re.IGNORECASE), "joomla"),
        (_compile(r"<!--\s*drupal\s*([\d.]*)", re.IGNORECASE), "drupal"),
        (_compile(r"<!--\s*(?:generated|powered)\s+by\s+next\.js", re.IGNORECASE), "next.js"),
        (_compile(r"<!--\s*generated\s+by\s+hexo\s*([\d.]*)", re.IGNORECASE), "hexo"),
        (_compile(r"<!--\s*generated\s+by\s+hugo\s*([\d.]*)", re.IGNORECASE), "hugo"),
        (_compile(r"<!--\s*powered\s+by\s+ghost\s*([\d.]*)", re.IGNORECASE), "ghost"),
        (_compile(r"<!--\s*(?:built|generated)\s+(?:with|by)\s+(?!(?:next|hexo|hugo|ghost|wordpress|joomla|drupal|magento|mediawiki|vbulletin)\b)([\w][\w\s]*?)\s*v?([\d.]+)", re.IGNORECASE), None),  # 通用(排除已知CMS)
        (_compile(r"<!--\s*magento\s*([\d.]*)", re.IGNORECASE), "magento"),
        (_compile(r"<!--\s*mediawiki\s*([\d.]*)", re.IGNORECASE), "mediawiki"),
        (_compile(r"<!--\s*vbulletin\s*([\d.]*)", re.IGNORECASE), "vbulletin"),
    ]

    # ── Cookie 版本检测 ───────────────────────────

    COOKIE_PATTERNS = [
        # (cookie_name_pattern, component, needs_version)
        (_compile(r"^laravel_session$"),    "laravel",       False),
        (_compile(r"^XSRF-TOKEN$"),         "laravel",       False),
        (_compile(r"^JSESSIONID$"),         "java-tomcat",   False),
        (_compile(r"^PHPSESSID$"),          "php",           False),
        (_compile(r"^ASP\.NET_SessionId$"), "asp.net",       False),
        (_compile(r"^connect\.sid$"),       "express",       False),
        (_compile(r"^rack\.session$"),      "ruby-rack",     False),
        (_compile(r"^_rails_session$"),     "rails",         False),
        (_compile(r"^csrftoken$"),          "django",        False),
        (_compile(r"^django_language$"),    "django",        False),
        (_compile(r"^symfony$"),            "symfony",       False),
        (_compile(r"^ci_session$"),         "codeigniter",   False),
        (_compile(r"^ci_csrf_token$"),       "codeigniter",   False),
        (_compile(r"^cakephp$"),            "cakephp",       False),
        (_compile(r"^wordpress_logged_in"), "wordpress",     False),
        (_compile(r"^wp-settings-"),        "wordpress",     False),
        (_compile(r"^Drupal\."),            "drupal",        False),
        (_compile(r"^SESS\w+"),             "drupal",        False),
        (_compile(r"^JEESESSIONID$"),       "java-ee",       False),
        (_compile(r"^PLAY_SESSION$"),       "play-framework", False),
        (_compile(r"^_gorilla_csrf$"),      "gorilla-csrf",  False),
        (_compile(r"^XSRF-TOKEN$"),         "angular",       False),
        (_compile(r"^io$"),                 "socketio",      False),
    ]

    def extract_from_headers(self, headers: dict) -> list[VersionInfo]:
        """从 HTTP 响应头提取版本"""
        results = []
        for header_name, component, pattern in self.HEADER_VERSION_PATTERNS:
            val = headers.get(header_name, "")
            if not val:
                continue
            m = re.search(pattern, val, re.IGNORECASE)
            if m:
                version = m.group(1) if m.groups() else "detected"
                results.append(VersionInfo(
                    component=component,
                    version=version,
                    source=header_name,
                    raw=m.group(0),
                ))
        return results

    def extract_from_meta(self, html: str) -> list[VersionInfo]:
        """从 HTML meta generator 提取版本，去重避免与通用正则重复"""
        results = []
        seen_components = set()

        for pattern in self.META_PATTERNS:
            for m in pattern.finditer(html):
                content = m.group(1)
                matched_specific = False

                # 先匹配具体的 CMS
                for cms, cms_patterns in self.CMS_META_MAP.items():
                    for pat in cms_patterns:
                        cm = pat.search(content)
                        if cm:
                            ver = cm.group(1) if cm.groups() else "detected"
                            results.append(VersionInfo(
                                component=cms,
                                version=ver,
                                source="meta",
                                raw=content,
                            ))
                            seen_components.add(cms)
                            matched_specific = True

                # 只有没匹配到具体 CMS 时，才用通用版本提取
                if not matched_specific:
                    ver_match = re.search(r"([\d]+\.[\d]+(?:\.[\d]+)?)", content)
                    if ver_match:
                        results.append(VersionInfo(
                            component="generator",
                            version=ver_match.group(1),
                            source="meta",
                            raw=content,
                        ))

        return results

    def extract_from_scripts(self, html: str) -> list[VersionInfo]:
        """从 JS 文件路径和内联脚本提取版本"""
        results = []
        seen = set()

        # 1. JS 文件路径中的版本
        for pat, component, source in self.JS_PATH_PATTERNS:
            for m in pat.finditer(html):
                version = m.group(1) if m.groups() else "detected"
                key = f"{component}@{version}"
                if key not in seen:
                    seen.add(key)
                    results.append(VersionInfo(
                        component=component,
                        version=version,
                        source=source,
                        raw=m.group(0),
                    ))

        # 2. 内联脚本中的框架版本
        for pat, component in self.INLINE_SCRIPT_PATTERNS:
            for m in pat.finditer(html):
                if m.groups():
                    version = m.group(1)
                else:
                    version = "detected"
                key = f"{component}@{version}"
                if key not in seen:
                    seen.add(key)
                    results.append(VersionInfo(
                        component=component,
                        version=version,
                        source="inline-script",
                        raw=m.group(0)[:120],
                    ))

        return results

    def extract_from_comments(self, html: str) -> list[VersionInfo]:
        """从 HTML 注释提取版本"""
        results = []
        seen = set()

        for pat, component in self.COMMENT_PATTERNS:
            for m in pat.finditer(html):
                if component is None:
                    # 通用 "built with XXX v1.2" 模式
                    if m.lastindex and m.lastindex >= 2:
                        comp = m.group(1).strip().lower()
                        ver = m.group(2).strip() if m.group(2) else "detected"
                    elif m.lastindex and m.lastindex >= 1:
                        comp = m.group(1).strip().lower()
                        ver = "detected"
                    else:
                        continue
                else:
                    comp = component
                    ver = m.group(1).strip() if m.groups() and m.group(1).strip() else "detected"

                key = f"{comp}@{ver}"
                if key not in seen:
                    seen.add(key)
                    results.append(VersionInfo(
                        component=comp,
                        version=ver,
                        source="comment",
                        raw=m.group(0)[:120],
                    ))

        return results

    def extract_from_cookies(self, cookie_header: str) -> list[VersionInfo]:
        """从 Cookie 头提取版本/框架信息"""
        results = []
        if not cookie_header:
            return results

        # 解析 cookie 字符串: "name1=val1; name2=val2"
        cookie_names = []
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                cookie_names.append(part.split("=", 1)[0].strip())

        seen = set()
        for name in cookie_names:
            for pat, component, needs_version in self.COOKIE_PATTERNS:
                if pat.search(name):
                    ver = "detected"
                    key = f"{component}@{ver}"
                    if key not in seen:
                        seen.add(key)
                        results.append(VersionInfo(
                            component=component,
                            version=ver,
                            source="cookie",
                            raw=name,
                        ))

        return results

    # ── 综合 ─────────────────────────────────────

    def extract(self, headers: dict, html: str = "") -> list[VersionInfo]:
        """从 headers + html + cookies 提取所有版本"""
        results = []

        # 1. HTTP 头
        results.extend(self.extract_from_headers(headers))

        if html:
            # 2. meta generator (去重逻辑已内置)
            results.extend(self.extract_from_meta(html))
            # 3. JS 文件路径 + 内联脚本
            results.extend(self.extract_from_scripts(html))
            # 4. HTML 注释
            results.extend(self.extract_from_comments(html))

        # 5. Cookie
        cookie_val = headers.get("cookie", headers.get("set-cookie", ""))
        if cookie_val:
            results.extend(self.extract_from_cookies(cookie_val))

        # 去重: 同一 component@version 只保留第一个（按 source 优先级）
        SOURCE_PRIORITY = {
            "server": 0, "x-powered-by": 1, "meta": 2,
            "script": 3, "script-path": 4, "inline-script": 5,
            "comment": 6, "cookie": 7,
        }
        results.sort(key=lambda r: SOURCE_PRIORITY.get(r.source, 99))
        seen = set()
        unique = []
        for r in results:
            key = f"{r.component}@{r.version}"
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def extract_as_dict(self, headers: dict, html: str = "") -> dict:
        """版本 → 字典"""
        vlist = self.extract(headers, html)
        return {v.component: v.version for v in vlist}

    def as_strings(self, headers: dict, html: str = "") -> list[str]:
        """版本 → 字符串列表"""
        return [str(v) for v in self.extract(headers, html)]
