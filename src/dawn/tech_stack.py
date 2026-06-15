"""技术栈识别 — 通过响应头/HTML/路径特征识别目标技术栈

指纹数据库覆盖 60+ 组件：Web 服务器、语言、CMS、框架、CDN/WAF、数据库、
分析工具、云平台等。所有正则在模块加载时预编译为 re.Pattern 对象。
"""

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
    platform: str = ""
    database: str = ""
    analytics: str = ""
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
            "platform": self.platform,
            "database": self.database,
            "analytics": self.analytics,
        }
        return {k: v for k, v in d.items() if v}


def _compile_patterns(patterns: list[tuple[str, str, str]]) -> list[tuple[str, re.Pattern, str]]:
    """批量预编译正则模式，返回 (name, compiled_pattern, field) 列表"""
    return [(name, re.compile(pattern, re.IGNORECASE), fld) for name, pattern, fld in patterns]


def _compile_simple(patterns: list[tuple[str, str]]) -> list[tuple[str, re.Pattern]]:
    """批量预编译简单 (name, pattern) 对"""
    return [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in patterns]


class TechStackDetector:
    """技术栈检测器"""

    # ── Server 指纹 ───────────────────────────────────────────
    # 扩展：LiteSpeed, H2O, Tengine, IIS 各版本, Jetty, Undertow, etc.

    _SERVER_RAW = [
        ("nginx",       r"nginx[/\d.]*"),
        ("apache",      r"apache[/\d.]*"),
        ("iis",         r"microsoft-iis[/\d.]*"),
        ("iis/10.0",    r"microsoft-iis/10[\d.]*"),
        ("iis/8.5",     r"microsoft-iis/8\.5"),
        ("iis/8.0",     r"microsoft-iis/8\.0"),
        ("iis/7.5",     r"microsoft-iis/7\.5"),
        ("iis/7.0",     r"microsoft-iis/7\.0"),
        ("iis/6.0",     r"microsoft-iis/6\.0"),
        ("tomcat",      r"apache-coyote[/\d.]*|apache-tomcat"),
        ("cloudflare",  r"cloudflare"),
        ("caddy",       r"caddy"),
        ("lighttpd",    r"lighttpd[/\d.]*"),
        ("openresty",   r"openresty[/\d.]*"),
        ("tengine",     r"tengine[/\d.]*"),
        ("litespeed",   r"litespeed|lsws"),
        ("h2o",         r"\bh2o[/\d.]*"),
        ("jetty",       r"jetty[/\d.]*"),
        ("undertow",    r"undertow[/\d.]*"),
        ("gunicorn",    r"gunicorn[/\d.]*"),
        ("uvicorn",     r"uvicorn"),
        ("werkzeug",    r"werkzeug[/\d.]*"),
        ("weblogic",    r"weblogic"),
        ("jboss",       r"jboss|wildfly"),
        ("resin",       r"resin[/\d.]*"),
        ("zeus",        r"zeus"),
        ("boa",         r"\bboa[/\d.]*"),
        ("yaws",        r"\byaws[/\d.]*"),
        ("barracuda",   r"barracudaserver"),
        ("aolserver",   r"aolserver"),
        ("oracle-http", r"oracle-http-server|ohs"),
        ("glassfish",   r"glassfish"),
        ("aws-s3",      r"amazons3|amazon-s3"),
        ("amazon-elb",  r"awselb|amazonelb"),
    ]

    SERVER_PATTERNS = _compile_patterns(
        [(n, p, "server") for n, p in _SERVER_RAW]
    )

    def detect_server(self, headers: dict) -> str:
        """从 Server / X-Powered-By 头识别 Web 服务器"""
        server_header = headers.get("server", "").lower()
        if not server_header:
            server_header = headers.get("x-powered-by", "").lower()
        for name, pattern, _ in self.SERVER_PATTERNS:
            if pattern.search(server_header):
                return name
        return ""

    # ── 语言指纹 ──────────────────────────────────────────────
    # 扩展：Ruby, Go, Rust, Perl, Scala, ColdFusion, Erlang/Elixir

    _LANGUAGE_RAW = [
        # PHP
        ("php",       r"\bphp[/\d.]*\b", "x-powered-by"),
        ("php",       r"\.php\b|\bphp\b", "html"),
        # Java
        ("java",      r"jsp\b|servlet\b|jsessionid", "header"),
        ("java",      r"jsessionid", "cookie"),
        ("java",      r"\.jsp\b|\.do\b|\.action\b", "html"),
        # Python
        ("python",    r"\bwsgi\b|\bdjango\b|\bflask\b|\btornado\b|\bpython\b", "header"),
        ("python",    r"\.py\b|\bmod_wsgi\b|\buvicorn\b|\bgunicorn\b", "html"),
        # ASP.NET
        ("asp.net",   r"x-aspnet|__viewstate|\.aspx\b|asp\.net", "header"),
        ("asp.net",   r"\.aspx\b|\.ashx\b|\.asmx\b|__viewstate", "html"),
        # Node.js
        ("node.js",   r"\bexpress\b|\bkoa\b|\bnode\.?js\b", "header"),
        ("node.js",   r"\.js\b.*node|node_modules|__next|_nuxt", "html"),
        # Go
        ("go",        r"\bgo[/\d.]+\b", "server"),
        ("go",        r"\bgin-gonic\b|\becho\b|\bbeego\b", "html"),
        # Ruby
        ("ruby",      r"\brails\b|\brack\b|\bruby\b|\bpassenger\b", "header"),
        ("ruby",      r"\.rb\b|ruby|rails|phusion.passenger", "html"),
        # Perl
        ("perl",      r"\bperl\b|\bmodperl\b|\bcgi-perl\b", "header"),
        ("perl",      r"\.pl\b|\.cgi\b.*perl|\bperl\.?cgi\b", "html"),
        # Scala
        ("scala",     r"\bscala\b|\bplay-framework\b|\bakka\b", "header"),
        # Rust
        ("rust",      r"\bactix\b|\brocket\b|\baxum\b", "html"),
        # ColdFusion
        ("coldfusion", r"\bcoldfusion\b|\bcfml\b|\blucee\b", "header"),
        # Erlang/Elixir
        ("erlang",    r"\berlang\b|\bbeam\b|\bcowboy\b", "header"),
        ("elixir",    r"\belixir\b|\bphoenix\b", "header"),
    ]

    LANGUAGE_PATTERNS = _compile_patterns(_LANGUAGE_RAW)

    def detect_language(self, headers: dict, cookies: dict, html: str = "", url: str = "") -> str:
        """识别后端语言 — 优先 header 证据，html 仅作辅助"""
        clues = []
        for name, pattern, fld in self.LANGUAGE_PATTERNS:
            if fld == "server":
                v = headers.get("server", "")
                if pattern.search(v):
                    clues.append(name)
                    continue
            elif fld == "x-powered-by":
                v = headers.get("x-powered-by", "")
                if pattern.search(v):
                    clues.append(name)
                    continue
            elif fld == "cookie":
                if cookies:
                    for k in cookies:
                        if pattern.search(k):
                            clues.append(name)
                            break
                    continue
            elif fld == "header":
                for h in ("server", "x-powered-by", "set-cookie", "x-aspnet-version"):
                    v = headers.get(h, "")
                    if pattern.search(v):
                        clues.append(name)
                        break
                continue
            elif fld == "html":
                if html and pattern.search(html[:8000]):
                    clues.append(name)
                    continue

        return clues[0] if clues else ""

    # ── CMS 指纹 ──────────────────────────────────────────────
    # 扩展：Magento, Shopify, Typo3, Craft CMS, Ghost, Hexo, Hugo,
    #        Jekyll, MediaWiki, phpBB, vBulletin, Moodle, OpenCart,
    #        PrestaShop, WooCommerce, October CMS, Squarespace, Wix, etc.

    _CMS_RAW = [
        # 中国 CMS
        ("dedecms",       r"dedecms|织梦"),
        ("discuz",        r"discuz!|dzbbs|forum\.php"),
        ("thinkphp",      r"thinkphp|think/"),
        ("ecshop",        r"ecshop"),
        ("phpcms",        r"phpcms"),
        ("empirecms",     r"帝国cms|empire"),
        ("zblog",         r"zblog|zb_system"),
        ("typecho",       r"typecho"),
        ("metinfo",       r"metinfo|米拓"),
        ("seacms",        r"seacms"),
        ("cmseasy",       r"cmseasy"),
        ("beescms",       r"beescms"),
        ("foosun",        r"foosun|风讯"),
        ("southidc",      r"southidc|南方数据"),
        ("74cms",         r"74cms|骑士cms"),
        ("phpyun",        r"phpyun"),
        ("eyoucms",       r"eyoucms|易优"),
        ("pbootcms",      r"pbootcms"),
        ("youzend",       r"youzend"),
        ("aspcms",        r"aspcms"),
        ("siteserver",    r"siteserver"),
        ("jiuycms",       r"jiuycms"),
        # PHP CMS / 框架
        ("wordpress",     r"wp-content|wp-includes|wordpress|wp-login\.php"),
        ("joomla",        r"joomla|/components/com_|/modules/mod_"),
        ("drupal",        r"drupal|sites/default/files|drupal\.js"),
        ("laravel",       r"laravel|laravel_session"),
        ("yii",           r"yii|YII_CSRF_TOKEN"),
        ("craft-cms",     r"craftcms|craft_session|CraftSession"),
        ("october-cms",   r"october|oc-page-loader"),
        ("magento",       r"magento|mage/|skin/frontend|catalog/product"),
        ("prestashop",    r"prestashop|/themes/.*prestashop"),
        ("opencart",      r"opencart|route=common"),
        ("woocommerce",   r"woocommerce|wc-|wp-content/plugins/woocommerce"),
        # 静态站点生成器
        ("ghost",         r"ghost|ghost-theme|content/themes/.*ghost"),
        ("hexo",          r"hexo|hexo-theme|powered-by-hexo"),
        ("hugo",          r"\bhugo\b|hugo-theme|isHugo"),
        ("jekyll",        r"jekyll|jekyll-theme|powered.by.jekyll"),
        ("gatsby",        r"gatsby|___gatsby"),
        ("hugo",          r"layouts/.*hugo|hugo_stats"),
        # SaaS / 建站平台
        ("shopify",       r"shopify|cdn\.shopify\.com|myshopify\.com"),
        ("wix",           r"wix\.com|wixsite|x-wix-"),
        ("squarespace",   r"squarespace|sqsp|static\.squarespace"),
        ("weebly",        r"weebly|weeblycloud"),
        ("webflow",       r"webflow|wf-canvas"),
        # .NET CMS
        ("sitecore",      r"sitecore|sc_mode"),
        ("umbraco",       r"umbraco|umb-|Umbraco"),
        ("dnn",           r"dotnetnuke|dnn_|DesktopModules"),
        ("kentico",       r"kentico|CMSPages"),
        ("orchard",       r"orchard|orchardcore"),
        # Wiki / 论坛 / 教育
        ("mediawiki",     r"mediawiki|wikibase|mw-content|Powered by MediaWiki"),
        ("phpbb",         r"phpbb|phpBB|viewforum\.php"),
        ("vbulletin",     r"vbulletin|vBulletin"),
        ("moodle",        r"moodle|theme/.*moodle"),
        ("canvas-lms",    r"canvas-lms|instructure"),
        ("confluence",    r"confluence|atlassian"),
        ("dokuwiki",      r"dokuwiki|doku\.php"),
        ("twiki",         r"twiki"),
        # 电商
        ("ecshop",        r"ecshop|ECSHOP"),
        ("zen-cart",      r"zen-cart|zencart"),
        ("oscommerce",    r"oscommerce|osCommerce"),
        ("cscart",        r"cscart|cs-cart"),
        # 其他
        ("sharepoint",    r"sharepoint|/_layouts/"),
        ("salesforce",    r"salesforce|force\.com"),
        ("hubspot",       r"hubspot|hs-scripts"),
        ("webgui",        r"webgui"),
    ]

    CMS_PATTERNS = _compile_simple(_CMS_RAW)

    def detect_cms(self, html: str = "", headers: dict = None, url: str = "") -> str:
        """识别 CMS"""
        headers = headers or {}
        all_text = f"{html} {' '.join(headers.values())} {url}".lower()
        for name, pattern in self.CMS_PATTERNS:
            if pattern.search(all_text):
                return name
        return ""

    # ── 框架指纹 ──────────────────────────────────────────────
    # 新增方法：前端框架 + 后端框架检测

    _FRAMEWORK_RAW = [
        # 前端框架 / SPA
        ("next.js",       r"__next|_next/.*\.js|next\.js|nextjs|__NEXT_DATA__"),
        ("nuxt.js",       r"__nuxt|_nuxt/|nuxt\.js|nuxtjs"),
        ("gatsby",        r"___gatsby|gatsby-|gatsby\.js"),
        ("sveltekit",     r"svelte|sveltekit|__svelte"),
        ("angular",       r"ng-version|ng-app|angular\.js|angular\.min\.js|ng-controller|ng-view"),
        ("react",         r"react\.production|react\.development|reactjs|_reactRoot|data-reactroot|__REACT_DEVTOOLS"),
        ("vue.js",        r"vue\.js|vue\.min\.js|vue-router|vuex|v-cloak|v-bind|data-v-|__vue__|Vue\.config"),
        ("ember.js",      r"ember\.js|ember\.min\.js|ember-app|Ember\.ENV"),
        ("backbone.js",   r"backbone\.js|backbone\.min\.js"),
        ("knockout.js",   r"knockout|knockoutjs|data-bind"),
        ("preact",        r"preact\.js|preact/"),
        ("alpine.js",     r"alpinejs|alpine\.js|x-data|Alpine\.data"),
        ("htmx",          r"htmx\.js|htmx\.min\.js|hx-get|hx-post|hx-target"),
        # JS 运行时
        ("deno",          r"\bdeno\b|denoland"),
        ("bun",           r"\bbun\b.*js|bun\.js|oven-sh"),
        # 后端 Python 框架
        ("fastapi",       r"fastapi|swagger-ui|openapi\.json|/docs|/redoc"),
        ("tornado",       r"\btornado\b"),
        ("pyramid",       r"pyramid|pylons"),
        ("bottle",        r"\bbottle\.py\b|bottle\.py"),
        ("django",        r"django|csrfmiddlewaretoken|__admin_media|admin/.*login"),
        ("flask",         r"flask|werkzeug|flask-session|flask_session"),
        ("sanic",         r"\bsanic\b"),
        ("starlette",     r"\bstarlette\b"),
        # 后端 Ruby 框架
        ("rails",         r"rails|rack|rake|ruby.on.rails|csrf-token|action_dispatch"),
        ("sinatra",       r"sinatra|sinatra\.rb"),
        ("padrino",       r"padrino"),
        # 后端 Go 框架
        ("gin",           r"gin-gonic|gin\.go|Gin-gonic"),
        ("echo",          r"echo-framework|labstack/echo"),
        ("beego",         r"beego|astaxie/beego"),
        ("fiber",         r"gofiber|fiber\.go"),
        # 后端 Rust 框架
        ("actix",         r"actix|actix-web|actix_web"),
        ("rocket",        r"rocket\.rs|rocket\.toml"),
        ("axum",          r"axum|tokio/axum"),
        # 后端 Perl 框架
        ("mason",         r"\bmason\b|mason\.pl"),
        ("catalyst",      r"catalyst|catalyst\.pm"),
        ("dancer",        r"\bdancer\b|dancer\.pm"),
        ("mojolicious",   r"mojolicious|mojo\.pm"),
        # 后端 Scala 框架
        ("play",          r"play-framework|play\.framework|playframework"),
        ("akka-http",     r"akka-http|akka\.http"),
        # Java 框架
        ("spring",        r"spring|spring-boot|springframework|spring-mvc|spring_boot"),
        ("spring-boot",   r"spring-boot|spring\.boot|X-Application-Context"),
        ("micronaut",     r"micronaut"),
        ("quarkus",       r"quarkus|io\.quarkus"),
        ("struts",        r"struts|struts2|\.action\b|\.do\b"),
        ("grails",        r"grails"),
        # .NET 框架
        ("asp.net-core",  r"aspnetcore|asp\.net.core|x-powered-by.*asp\.net"),
        ("blazor",        r"blazor|_framework/blazor"),
        ("nancy",         r"nancy\.fx|nancyfx"),
        # Node.js 框架
        ("express",       r"express|X-Powered-By.*Express"),
        ("koa",           r"koa|X-Powered-By.*Koa"),
        ("fastify",       r"fastify|X-Powered-By.*Fastify"),
        ("nestjs",        r"nestjs|nest\.js|@nestjs"),
        ("next.js-node",  r"next\.js|nextjs|_next/"),
        ("hapi",          r"\bhapi\b|hapijs"),
        ("meteor",        r"meteor|__meteor_runtime_config__"),
        ("adonis",        r"adonis|adonisjs"),
        ("loopback",      r"loopback|loopbackjs"),
        # PHP 框架（补充）
        ("symfony",       r"symfony|sf_session"),
        ("codeigniter",   r"codeigniter|ci_session"),
        ("cakephp",       r"cakephp|cake_"),
        ("slim",          r"slim-framework|slimframework"),
        ("phalcon",       r"phalcon"),
        ("zend",          r"zend|zend-framework|laminas"),
        ("lumen",         r"lumen|laravel/lumen"),
        ("yiisoft",       r"yiisoft|yii2"),
        ("fuelphp",       r"fuelphp"),
    ]

    FRAMEWORK_PATTERNS = _compile_simple(_FRAMEWORK_RAW)

    def detect_framework(self, html: str = "", headers: dict = None, url: str = "") -> str:
        """识别前端/后端框架"""
        headers = headers or {}
        # 组合搜索文本：html + headers values + url
        header_vals = " ".join(headers.values())
        all_text = f"{html[:15000]} {header_vals} {url}"
        for name, pattern in self.FRAMEWORK_PATTERNS:
            if pattern.search(all_text):
                return name
        return ""

    # ── CDN 指纹 ──────────────────────────────────────────────
    # 扩展：Sucuri, Imperva, StackPath, KeyCDN, BunnyCDN,
    #        CloudFront, Azure CDN, Google Cloud CDN, etc.

    CDN_HEADERS = [
        "x-cdn", "cf-cache-status", "x-amz-cf-id",
        "x-cache", "cdn-cache", "x-cdn-provider",
        "x-fastly-request-id", "x-served-by", "x-cache-hits",
        "x-bcdn-request-id", "x-shield-request-id",
        "x-stackpath-cdn", "x-keycdn-c",
    ]

    # 头名到 CDN 名称的直接映射（当头值不含特征时使用）
    _CDN_HEADER_NAME_MAP = {
        "cf-cache-status": "cloudflare",
        "x-amz-cf-id": "cloudfront",
        "x-fastly-request-id": "fastly",
        "x-served-by": "fastly",        # Fastly 的标志性头
        "x-cache-hits": "fastly",
        "x-bcdn-request-id": "bunnycdn",
        "x-stackpath-cdn": "stackpath",
        "x-keycdn-c": "keycdn",
    }

    _CDN_SERVER_PATTERNS = [
        ("cloudflare",    r"cloudflare"),
        ("cloudfront",    r"cloudfront|amazons3|aws.*cdn"),
        ("akamai",        r"akamai|akamaighost"),
        ("fastly",        r"fastly|varnish"),
        ("stackpath",     r"stackpath"),
        ("keycdn",        r"keycdn"),
        ("bunnycdn",      r"bunnycdn|b-cdn"),
        ("azure-cdn",     r"azurecdn|azure.*cdn|frontdoor"),
        ("google-cdn",    r"google.*cdn|gstatic"),
        ("incapsula",     r"incapsula|imperva"),
        ("sucuri",        r"sucuri"),
        ("maxcdn",        r"maxcdn|bootstrapcdn"),
        ("cdn77",         r"cdn77"),
        ("quantil",       r"quantil"),
        ("wangsu",        r"wangsu|网宿"),
        ("chinacache",    r"chinacache|蓝汛"),
        ("yunjiasu",      r"yunjiasu|百度加速"),
        ("cdn-union",     r"cdn-union"),
    ]

    CDN_SERVER_PATTERNS = _compile_simple(_CDN_SERVER_PATTERNS)

    def detect_cdn(self, headers: dict) -> str:
        """检测 CDN"""
        server_val = headers.get("server", "").lower()
        via_val = headers.get("via", "").lower()
        combined_server = f"{server_val} {via_val}"

        # 先检查 Server / Via 头中的 CDN 签名（优先，最可靠）
        for name, pattern in self.CDN_SERVER_PATTERNS:
            if pattern.search(combined_server):
                return name

        # 收集所有匹配的 CDN 特征头，优先返回能识别具体 CDN 的结果
        fallback_generic = ""
        fallback_named = ""
        for h in self.CDN_HEADERS:
            if h in headers:
                # 尝试从头值中识别具体 CDN
                hval = headers.get(h, "").lower()
                for name, pattern in self.CDN_SERVER_PATTERNS:
                    if pattern.search(hval):
                        return name
                # 头值不匹配时，用头名映射表
                h_lower = h.lower()
                if h_lower in self._CDN_HEADER_NAME_MAP:
                    if not fallback_named:
                        fallback_named = self._CDN_HEADER_NAME_MAP[h_lower]
                elif not fallback_generic:
                    fallback_generic = "detected"

        # 优先返回具体 CDN 名称，其次返回 "detected"
        if fallback_named:
            return fallback_named
        if fallback_generic:
            return fallback_generic

        # 检查所有头 key+value 中的 CDN 签名（兜底）
        header_blob = " ".join(f"{k.lower()}={v.lower()}" for k, v in headers.items())
        for name, pattern in self.CDN_SERVER_PATTERNS:
            if pattern.search(header_blob):
                return name

        return ""

    # ── WAF 指纹 ──────────────────────────────────────────────
    # 扩展：ModSecurity, FortiWeb, SonicWall, F5 BIG-IP, Citrix ADC, etc.

    WAF_HEADERS = [
        "x-waf", "x-firewall", "x-protected-by",
        "mod_security", "x-sucuri-id", "x-sucuri-cache",
        "x-cdn-waf", "x-sucuri-waf",
        "x-amzn-waf-id",
    ]

    # 头名到 WAF 名称的直接映射（当头值不含特征时使用）
    _WAF_HEADER_NAME_MAP = {
        "x-sucuri-id": "sucuri-waf",
        "x-sucuri-cache": "sucuri-waf",
        "x-sucuri-waf": "sucuri-waf",
        "mod_security": "mod-security",
        "x-amzn-waf-id": "aws-waf",
        "x-incap-ses": "incapsula-waf",
    }

    _WAF_SERVER_PATTERNS = [
        ("cloudflare-waf",  r"cloudflare.*waf|__cfduid|cf-ray"),
        ("mod-security",    r"mod_security|modsecurity|NOYB"),
        ("sucuri-waf",      r"sucuri|sucuri.*waf"),
        ("incapsula-waf",   r"incapsula|imperva|x-incap-ses"),
        ("fortiweb",        r"fortiweb|fortinet"),
        ("f5-bigip",        r"f5|bigip|big-ip|BIGipServer"),
        ("citrix-adc",      r"citrix|netscaler|ns_af|citrix.*adc"),
        ("barracuda-waf",   r"barracuda|barra"),
        ("sonicwall",       r"sonicwall|sonic.*wall"),
        ("denyall",         r"denyall|denial"),
        ("dotdefender",     r"dotdefender"),
        ("webknight",       r"webknight"),
        ("urlscan",         r"urlscan|microsoft.*urlscan"),
        ("aws-waf",         r"aws.*waf|x-amzn-waf"),
        ("azure-waf",       r"azure.*waf|application-gateway"),
        ("fortify",         r"fortify"),
        ("radware",         r"radware"),
        ("nsfocus",         r"nsfocus|绿盟"),
        ("safe3",           r"safe3"),
        ("360waf",          r"360waf|360.*waf"),
        ("chuangyu",        r"chuangyu|创宇"),
        ("anquanbao",       r"anquanbao|安全宝"),
        ("yundun",          r"yundun|云盾"),
    ]

    WAF_SERVER_PATTERNS = _compile_simple(_WAF_SERVER_PATTERNS)

    def detect_waf(self, headers: dict) -> str:
        """检测 WAF"""
        # 先检查显式 WAF 头
        for h in self.WAF_HEADERS:
            if h in headers:
                hval = headers.get(h, "").lower()
                for name, pattern in self.WAF_SERVER_PATTERNS:
                    if pattern.search(hval):
                        return name
                # 头值不匹配时，用头名映射表兜底
                if h.lower() in self._WAF_HEADER_NAME_MAP:
                    return self._WAF_HEADER_NAME_MAP[h.lower()]
                return "detected"

        # 检查 Server 头中的 WAF 签名
        server_val = headers.get("server", "").lower()
        for name, pattern in self.WAF_SERVER_PATTERNS:
            if pattern.search(server_val):
                return name

        # 检查所有头 key 中的 WAF 签名 (如 x-amzn-waf-id 等)
        header_keys = " ".join(k.lower() for k in headers.keys())
        for name, pattern in self.WAF_SERVER_PATTERNS:
            if pattern.search(header_keys):
                return name

        # 检查 Set-Cookie 中的 WAF 签名 (如 F5 BIG-IP 的 cookie)
        cookie_str = " ".join(
            f"{k}={v}" for k, v in headers.items()
            if k.lower() == "set-cookie"
        ).lower()
        if cookie_str:
            for name, pattern in self.WAF_SERVER_PATTERNS:
                if pattern.search(cookie_str):
                    return name

        return ""

    # ── 云平台检测 ────────────────────────────────────────────
    # 新增方法：从 HTTP 头识别云平台

    _PLATFORM_HEADER_PATTERNS = [
        ("aws",     r"x-amz-|amazonaws\.com|amazons3|awselb|x-amzn-"),
        ("azure",   r"x-azure|x-ms-|azurewebsites\.net|azure.*cdn|azure.*blob"),
        ("gcp",     r"x-goog-|google-cloud|appspot\.com|x-cloud-trace"),
        ("alibaba", r"aliyun|ali-cdn|x-oss-|oss-cn-|alicdn"),
        ("tencent", r"qcloud|tencent-cdn|cos\..*myqcloud"),
        ("huawei",  r"huaweicloud|obs\.myhuaweicloud"),
        ("cloudflare-workers", r"cf-worker|cloudflare-workers"),
        ("vercel",  r"vercel|x-vercel|x-vercel-id"),
        ("netlify", r"netlify|x-nf-|netlify\.com"),
        ("heroku",  r"heroku|x-request-id.*heroku|via.*vegur"),
        ("digitalocean", r".digitalocean"),
        ("linode",  r"linode"),
        ("docker",  r"\bdocker\b|x-docker"),
        ("kubernetes", r"\bkubernetes\b|x-k8s-|k8s"),
    ]

    PLATFORM_PATTERNS = _compile_simple(_PLATFORM_HEADER_PATTERNS)

    def detect_platform(self, headers: dict) -> str:
        """从 HTTP 头识别云平台 / 部署环境"""
        # 收集所有头的 key 和 value
        header_blob = " ".join(
            f"{k.lower()}={v.lower()}" for k, v in headers.items()
        )
        for name, pattern in self.PLATFORM_PATTERNS:
            if pattern.search(header_blob):
                return name
        return ""

    # ── 数据库指纹 ────────────────────────────────────────────
    # 新增：从错误页面 / 头部特征检测数据库类型

    _DATABASE_RAW = [
        ("mysql",         r"mysql|mysql_|mysqldb|mysqli|MariaDB|mariadb"),
        ("postgresql",    r"postgresql|postgres|pg_|psql|PgSQL"),
        ("mongodb",       r"mongodb|mongo|MongoDB|MongoClient"),
        ("redis",         r"redis|Redis|redis-server"),
        ("elasticsearch", r"elasticsearch|elastic\.co|elasticsearch\.yml|kibana"),
        ("oracle",        r"oracle|ORA-\d{5}|oracledb|oracle\.jdbc"),
        ("sql-server",    r"mssql|sqlserver|sql.server|microsoft sql|sqldriver|ODBC SQL Server"),
        ("sqlite",        r"sqlite|SQLite|\.sqlite3?\b|sqlalchemy.*sqlite"),
        ("cassandra",     r"cassandra|DataStax"),
        ("couchdb",       r"couchdb|couch_db|couchbase"),
        ("memcached",     r"memcached|memcache"),
        ("neo4j",         r"neo4j|neo4j\.db|graph\.db"),
        ("influxdb",      r"influxdb|influx"),
        ("clickhouse",    r"clickhouse|yandex.*clickhouse"),
        ("cockroachdb",   r"cockroachdb|cockroach"),
        ("tidb",          r"tidb|pingcap"),
    ]

    DATABASE_PATTERNS = _compile_simple(_DATABASE_RAW)

    def detect_database(self, html: str = "", headers: dict = None) -> str:
        """从错误页面 / 头部特征检测数据库类型"""
        headers = headers or {}
        header_vals = " ".join(headers.values())
        # 只在错误页面或 debug 信息中检测，避免误报
        error_text = html[:5000]  # 前 5KB 通常包含错误信息
        combined = f"{error_text} {header_vals}"
        for name, pattern in self.DATABASE_PATTERNS:
            if pattern.search(combined):
                return name
        return ""

    # ── 分析/追踪工具 ─────────────────────────────────────────
    # 新增：从 HTML 中检测分析和追踪脚本

    _ANALYTICS_RAW = [
        ("google-analytics",    r"google-analytics\.com|googletagmanager\.com|ga\.js|analytics\.js|gtag/js|UA-\d+-\d+|G-[A-Z0-9]+"),
        ("google-tag-manager",  r"googletagmanager\.com|gtm\.js|GTM-[A-Z0-9]+"),
        ("matomo",              r"matomo|piwik|_paq\.push|matomo\.js|piwik\.js"),
        ("hotjar",              r"hotjar|hj\(|_hjSettings"),
        ("mixpanel",            r"mixpanel\.com|mixpanel\.js|mp\.js"),
        ("segment",             r"segment\.com|analytics\.js.*segment|segment\.io"),
        ("amplitude",           r"amplitude\.com|amplitude\.js"),
        ("heap",                r"heap-analytics|heap\.js|heap\.load"),
        ("plausible",           r"plausible\.io|plausible\.js"),
        ("umami",               r"umami\.js|umami\.is"),
        ("clarity",             r"clarity\.ms|clarity\.js"),
        ("baidu-tongji",        r"baidu\.com/hm\.js|hm\.js|百度统计"),
        ("cnzz",                r"cnzz\.com|cnzz\.js"),
        ("51la",                r"51\.la|51la\.js"),
        ("growingio",           r"growingio|gio"),
        ("sensors",             r"sensorsdata|sensors\.js|神策"),
    ]

    ANALYTICS_PATTERNS = _compile_simple(_ANALYTICS_RAW)

    def detect_analytics(self, html: str = "") -> str:
        """从 HTML 中检测分析/追踪工具"""
        if not html:
            return ""
        for name, pattern in self.ANALYTICS_PATTERNS:
            if pattern.search(html[:20000]):
                return name
        return ""

    # ── 综合检测 ──────────────────────────────────────────────

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
            framework=self.detect_framework(html, headers, url),
            cdn=self.detect_cdn(headers),
            waf=self.detect_waf(headers),
            platform=self.detect_platform(headers),
            database=self.detect_database(html, headers),
            analytics=self.detect_analytics(html),
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
        if fp.platform:
            tags.append(f"platform:{fp.platform}")
        if fp.database:
            tags.append(f"db:{fp.database}")
        if fp.analytics:
            tags.append(f"analytics:{fp.analytics}")
        return tags
