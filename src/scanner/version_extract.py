"""版本号提取 — 从 HTTP 头和 HTML 中提取精确版本"""

import re
from dataclasses import dataclass, field


@dataclass
class VersionInfo:
    """版本信息"""
    component: str      # nginx / php / wordpress / jquery
    version: str        # 1.24.0 / 7.4.33 / 6.2.2
    source: str = ""    # server-header / powered-by / meta / script / comment
    raw: str = ""       # 原始匹配文本

    def __str__(self):
        return f"{self.component}@{self.version}"


class VersionExtractor:
    """版本号提取器"""

    # ── HTTP 头版本 ──────────────────────────────

    HEADER_VERSION_PATTERNS = [
        # (header_name, component, regex)
        ("server", "nginx",      r"nginx/([\d.]+)"),
        ("server", "apache",     r"apache[/\s]*([\d.]+)"),
        ("server", "iis",        r"microsoft-iis/([\d.]+)"),
        ("server", "tomcat",     r"apache-coyote/([\d.]+)"),
        ("server", "openresty",  r"openresty/([\d.]+)"),
        ("server", "tengine",    r"tengine/([\d.]+)"),
        ("server", "caddy",      r"caddy"),
        ("server", "cloudflare", r"cloudflare"),
        ("x-powered-by", "php",  r"php/([\d.]+)"),
        ("x-powered-by", "asp.net", r"asp\.net"),
        ("x-generator", "drupal",   r"drupal\s*([\d.]+)"),
        ("x-drupal-cache", "drupal", r"hit|miss"),
        ("x-aspnet-version", "asp.net", r"([\d.]+)"),
        ("x-aspnetmvc-version", "asp.net-mvc", r"([\d.]+)"),
    ]

    def extract_from_headers(self, headers: dict) -> list[VersionInfo]:
        """从 HTTP 响应头提取版本"""
        results = []
        for header_name, component, pattern in self.HEADER_VERSION_PATTERNS:
            val = headers.get(header_name, "")
            if not val:
                continue
            if pattern:
                m = re.search(pattern, val, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.groups() else "detected"
                    results.append(VersionInfo(
                        component=component,
                        version=version,
                        source=header_name,
                        raw=m.group(0),
                    ))
            else:
                # 无版本号，仅标记存在
                results.append(VersionInfo(
                    component=component,
                    version="detected",
                    source=header_name,
                    raw=val,
                ))
        return results

    # ── HTML meta 版本 ───────────────────────────

    META_PATTERNS = [
        (r'<meta\s+name="generator"\s+content="([^"]+)"', "generator"),
        (r'<meta\s+name="generator"\s+content=\'([^\']+)\'', "generator"),
    ]

    CMS_META_MAP = {
        "wordpress": [(r"wordpress\s*([\d.]+)", "wordpress")],
        "joomla":    [(r"joomla!\s*([\d.]+)", "joomla")],
        "drupal":    [(r"drupal\s*([\d.]+)", "drupal")],
        "discuz":    [(r"discuz!\s*x?([\d.]+)", "discuz")],
        "dedecms":   [(r"dedecms\s*v?([\d.]+)", "dedecms")],
    }

    def extract_from_html(self, html: str) -> list[VersionInfo]:
        """从 HTML 中提取版本"""
        results = []

        # 1. meta generator
        for pattern, source_type in self.META_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for content in matches:
                # 尝试识别 CMS
                for cms, cms_patterns in self.CMS_META_MAP.items():
                    for pat, component in cms_patterns:
                        m = re.search(pat, content, re.IGNORECASE)
                        if m:
                            ver = m.group(1) if m.groups() else "detected"
                            results.append(VersionInfo(
                                component=component,
                                version=ver,
                                source="meta",
                                raw=content,
                            ))
                # 通用版本提取
                ver_match = re.search(r"([\d]+\.[\d]+(?:\.[\d]+)?)", content)
                if ver_match:
                    results.append(VersionInfo(
                        component=source_type,
                        version=ver_match.group(1),
                        source="meta",
                        raw=content,
                    ))

        # 2. JavaScript 库版本
        js_patterns = [
            (r"jquery[/\s]*v?([\d.]+)", "jquery"),
            (r"jquery[/\s]*@([\d.]+)", "jquery"),
            (r"bootstrap[/\s]*v?([\d.]+)", "bootstrap"),
            (r"vue[/\s]*@?v?([\d.]+)", "vue"),
            (r"react[/\s]*@?v?([\d.]+)", "react"),
            (r"angular[/\s]*v?([\d.]+)", "angular"),
            (r"lodash[/\s]*v?([\d.]+)", "lodash"),
        ]
        for pattern, component in js_patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                version = m.group(1)
                if version:
                    results.append(VersionInfo(
                        component=component,
                        version=version,
                        source="script",
                        raw=m.group(0),
                    ))

        # 3. HTML 注释中的版本
        comment_patterns = [
            (r"<!--\s*(?:site|page)\s+version:\s*([\d.]+)", "site-version"),
        ]
        for pattern, component in comment_patterns:
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                results.append(VersionInfo(
                    component=component,
                    version=m.group(1),
                    source="comment",
                    raw=m.group(0),
                ))

        return results

    # ── 综合 ─────────────────────────────────────

    def extract(self, headers: dict, html: str = "") -> list[VersionInfo]:
        """从 headers + html 提取所有版本"""
        results = []
        results.extend(self.extract_from_headers(headers))
        if html:
            results.extend(self.extract_from_html(html))
        # 去重
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
