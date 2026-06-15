"""敏感路径/文件发现 — 带 CDN/CloudFront 假阳性降噪 (6层降噪)"""

import asyncio
import hashlib
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class PathFind:
    """路径发现结果"""
    url: str
    status: int
    size: int = 0
    content_type: str = ""
    category: str = ""          # config/backup/debug/git/admin/api/source/db
    content_preview: str = ""   # 响应体前 200 字节，用于内容相似度检测
    is_catchall: bool = False   # CDN/WAF 假阳性标记
    response_headers: dict = field(default_factory=dict)  # 响应头 (用于 CDN/WAF 检测)
    response_time: float = 0.0  # 响应耗时 (秒)
    content_hash: str = ""      # 响应体 hash (用于行为分析)

    @property
    def is_interesting(self) -> bool:
        if self.category == "info":
            return False
        if self.is_catchall:
            return False
        if self.status == 200 and self.size > 100:
            return True
        if self.status == 403:
            return True
        return False


# ── 通用敏感路径字典 ──────────────────────────────

COMMON_PATHS = [
    # 配置文件
    (".env", "config"),
    ("config.json", "config"),
    ("config.yaml", "config"),
    ("config.yml", "config"),
    ("settings.py", "config"),
    ("application.properties", "config"),
    ("web.config", "config"),
    # Git 泄露
    (".git/config", "git"),
    (".git/HEAD", "git"),
    (".gitignore", "git"),
    # 备份文件
    ("index.php.bak", "backup"),
    ("index.html.bak", "backup"),
    ("backup.zip", "backup"),
    ("backup.sql", "backup"),
    ("wwwroot.zip", "backup"),
    # 调试页面
    ("phpinfo.php", "debug"),
    ("info.php", "debug"),
    ("phpinfo", "debug"),
    ("test.php", "debug"),
    ("debug", "debug"),
    ("trace.axd", "debug"),
    # API / 文档
    ("swagger.json", "api"),
    ("openapi.json", "api"),
    ("api-docs", "api"),
    ("api/docs", "api"),
    ("swagger-ui.html", "api"),
    ("actuator/health", "api"),
    ("actuator/info", "api"),
    # 管理后台
    ("admin", "admin"),
    ("admin/login", "admin"),
    ("login", "admin"),
    ("manage", "admin"),
    ("manager", "admin"),
    ("admin.php", "admin"),
    ("admin.aspx", "admin"),
    # 常用路径
    ("robots.txt", "info"),
    ("sitemap.xml", "info"),
    ("crossdomain.xml", "info"),
    # 源码泄露
    ("index.php~", "source"),
    ("index.php.swp", "source"),
    (".DS_Store", "source"),
    ("readme.md", "info"),
    ("README.md", "info"),
    # 数据库管理
    ("phpmyadmin", "db"),
    ("pma", "db"),
    ("adminer", "db"),
    ("phpmyadmin/index.php", "db"),
]

# ── 技术栈特定路径 ────────────────────────────────

TECH_PATHS = {
    "thinkphp": [
        ("runtime/", "debug"),
        ("runtime/logs/", "debug"),
        ("thinkphp/", "config"),
        ("application/", "config"),
    ],
    "wordpress": [
        ("wp-config.php.bak", "config"),
        ("wp-content/uploads/", "info"),
        ("wp-json/", "api"),
        ("xmlrpc.php", "api"),
    ],
    "dedecms": [
        ("data/", "config"),
        ("data/common.inc.php", "config"),
        ("include/", "config"),
        ("plus/", "info"),
    ],
    "laravel": [
        (".env", "config"),
        ("storage/logs/laravel.log", "debug"),
        ("storage/", "debug"),
    ],
    "discuz": [
        ("config/config_global.php.bak", "config"),
        ("uc_server/", "admin"),
        ("member.php", "admin"),
    ],
    "java": [
        ("WEB-INF/web.xml", "config"),
        ("WEB-INF/", "config"),
        ("META-INF/", "config"),
        ("actuator/", "api"),
    ],
    "asp.net": [
        ("web.config", "config"),
        ("trace.axd", "debug"),
        ("elmah.axd", "debug"),
    ],
}


class SensitivePathDetector:
    """敏感路径检测器"""

    def __init__(self, timeout: float = 3.0, concurrency: int = 8):
        self.timeout = timeout
        self.concurrency = concurrency

    def get_paths(self, tech: str = "") -> list[tuple[str, str]]:
        """获取要检测的路径列表（通用 + 技术栈特定）"""
        paths = list(COMMON_PATHS)
        if tech and tech in TECH_PATHS:
            paths.extend(TECH_PATHS[tech])
        return paths

    async def _check_one(
        self, base_url: str, path: str, category: str,
        client: httpx.AsyncClient,
    ) -> Optional[PathFind]:
        """检测单个路径 — 不做单点判断，把原始数据返回，统一在 scan() 里降噪"""
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            t0 = time.monotonic()
            resp = await client.get(full_url, timeout=self.timeout)
            elapsed = time.monotonic() - t0

            if resp.status_code in (200, 301, 302, 303, 307, 308, 401, 403, 500):
                size = len(resp.content)
                # 捕获前 200 字节用于内容相似度分析
                preview = ""
                try:
                    preview = resp.content[:200].decode("utf-8", errors="ignore")
                except Exception:
                    pass

                # 内容 hash — 用于行为分析 (仅取前 4KB 避免大文件拖慢)
                content_hash = hashlib.md5(resp.content[:4096]).hexdigest()

                # 复制响应头为小写 dict 便于后续匹配
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                return PathFind(
                    url=full_url,
                    status=resp.status_code,
                    size=size,
                    content_type=resp.headers.get("content-type", ""),
                    category=category,
                    content_preview=preview,
                    is_catchall=False,
                    response_headers=headers_lower,
                    response_time=elapsed,
                    content_hash=content_hash,
                )
        except Exception:
            pass
        return None

    # ── CDN/WAF 关键字 ─────────────────────────────────
    _CDN_SERVER_KEYWORDS = (
        "cloudflare", "cloudfront", "akamai", "fastly",
        "incapsula", "sucuri", "yunjiasu", "cdn",
        "yun-cdn", "wangsu", "chinanetcenter",
    )
    _CDN_HEADER_MARKERS = (
        "cf-ray", "x-amz-cf-id", "x-cdn", "x-cache",
        "x-served-by", "x-fastly-request-id", "cf-cache-status",
        "x-cdn-provider", "via",
    )
    # ── 错误/停放页面关键词 ────────────────────────────
    _CATCHALL_CONTENT_PATTERNS = (
        "404 not found", "403 forbidden", "access denied",
        "this domain is for sale", "domain is for sale",
        "coming soon", "under construction",
        "error 1020", "error 1015", "error 1009",
        "error 1016", "error 1018", "error 1006",
        "please contact your hosting provider",
        "default web site page", "default page",
        "cpanel", "plesk", "directadmin",
        "it works!", "apache default page",
        "nginx default page", "welcome to nginx",
        "is proud to be hosted by",
        "this page is parked",
        "buy this domain", "domain expired",
        "suspended domain", "account suspended",
    )

    async def scan(self, base_url: str, tech: str = "") -> list[PathFind]:
        """扫描目标 — 六层降噪"""
        paths = self.get_paths(tech)
        sem = asyncio.Semaphore(self.concurrency)
        results: list[PathFind] = []

        # 多条随机探测路径 (Layer 3 增强: 多探针校准)
        _probe_suffixes = [
            "_poxiao_no_such_8472_test_",
            "_poxiao_calibration_zz99_probe_",
            "_poxiao_catchall_xk33_check_",
        ]

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # ── Layer 3 增强: 多探针校准 ──
            probe_results: list[tuple[int, float, str]] = []  # (size, elapsed, preview)
            probe_status_counts: dict[int, int] = {}
            for suffix in _probe_suffixes:
                try:
                    t0 = time.monotonic()
                    probe = await client.get(
                        f"{base_url.rstrip('/')}/{suffix}"
                    )
                    elapsed = time.monotonic() - t0
                    size = len(probe.content)
                    preview = ""
                    try:
                        preview = probe.content[:200].decode("utf-8", errors="ignore")
                    except Exception:
                        pass
                    probe_results.append((size, elapsed, preview))
                    probe_status_counts[probe.status_code] = \
                        probe_status_counts.get(probe.status_code, 0) + 1
                except Exception:
                    pass

            # 汇总探针结果
            catchall_sizes = [pr[0] for pr in probe_results if pr[0] > 0]
            catchall_previews = [pr[2] for pr in probe_results if pr[2]]
            probe_times = [pr[1] for pr in probe_results]
            # 若多数探针返回 200 且有内容 → 确定 catchall
            catchall_200_count = sum(
                1 for _, _, p in probe_results if True  # 200 的都已在 probe_results 里
            )
            # 用中位数尺寸做校准
            catchall_median_size = int(statistics.median(catchall_sizes)) if catchall_sizes else 0
            catchall_avg_time = statistics.mean(probe_times) if probe_times else 0.0

            async def _worker(p: str, cat: str):
                async with sem:
                    found = await self._check_one(base_url, p, cat, client)
                    if found:
                        results.append(found)

            tasks = [_worker(p, cat) for p, cat in paths]
            await asyncio.gather(*tasks)

        # ═══════════════════════════════════════════════════════
        # 降噪层 1: 内容特征 — 不该返回 HTML 但返回了 HTML (增强版)
        # ═══════════════════════════════════════════════════════
        html_categories = {"config", "backup", "git", "source", "api", "db"}
        for r in results:
            if r.status == 200 and r.category in html_categories:
                preview = r.content_preview.lower().lstrip()
                ct_lower = r.content_type.lower()

                # 基础: 配置文件不应该以 <html / <!doctype / <script 开头
                if (preview.startswith("<!doctype") or
                    preview.startswith("<html") or
                    preview.startswith("<script")):
                    r.is_catchall = True
                    continue

                # 增强 1: 配置/备份路径返回 text/html 且 > 1KB → 假阳性
                if r.category in ("config", "backup", "git", "source", "db"):
                    if "text/html" in ct_lower and r.size > 1024:
                        r.is_catchall = True
                        continue

                # 增强 2: API 路径返回 text/html 而非 application/json → 假阳性
                if r.category == "api":
                    if "text/html" in ct_lower:
                        r.is_catchall = True
                        continue

                # 增强 3: 备份文件 (.sql, .tar.gz 等) 返回 HTML → 假阳性
                if r.category == "backup":
                    if "text/html" in ct_lower:
                        r.is_catchall = True
                        continue

                # 增强 4: .env 返回 HTML → 绝对假阳性
                url_lower = r.url.lower()
                if "/.env" in url_lower and "text/html" in ct_lower:
                    r.is_catchall = True
                    continue

        # ═══════════════════════════════════════════════════════
        # 降噪层 2: 尺寸聚类 — 增强: 中位数 + header 相似度
        # ═══════════════════════════════════════════════════════
        active = [r for r in results if not r.is_catchall
                  and r.status in (200, 403) and r.category != "info"]

        # 2a: 经典尺寸聚类 (基于中位数)
        if len(active) >= 4:
            sizes = sorted(r.size for r in active)
            median_size = statistics.median(sizes)
            tol = max(80, int(median_size * 0.08))
            cluster = [
                r for r in active
                if abs(r.size - median_size) <= tol
            ]
            if len(cluster) >= 3:
                for r in cluster:
                    r.is_catchall = True

        # 2b: 单点尺寸匹配 (原有逻辑，保持向后兼容)
        for r in results:
            if r.is_catchall:
                continue
            if r.status not in (200, 403) or r.category == "info":
                continue

            tol = max(80, int(r.size * 0.08))
            similar = sum(
                1 for other in results
                if other is not r
                and other.status == r.status
                and other.category != "info"
                and not other.is_catchall
                and abs(other.size - r.size) <= tol
            )
            if similar >= 3:
                r.is_catchall = True

        # 2c: 响应头相似度 — 3+ 路径的响应头完全一致 → catchall
        non_catchall = [r for r in results if not r.is_catchall
                        and r.status in (200, 403) and r.category != "info"]
        if len(non_catchall) >= 3:
            # 取关键头做指纹 (排除逐请求变化的头)
            _skip_headers = {"date", "set-cookie", "x-request-id",
                             "x-trace-id", "age", "expires"}
            header_sigs: dict[str, list[PathFind]] = {}
            for r in non_catchall:
                sig_parts = []
                for hk, hv in sorted(r.response_headers.items()):
                    if hk not in _skip_headers:
                        sig_parts.append(f"{hk}={hv}")
                sig = "|".join(sig_parts)
                header_sigs.setdefault(sig, []).append(r)
            for sig, group in header_sigs.items():
                if len(group) >= 3:
                    for r in group:
                        r.is_catchall = True

        # ═══════════════════════════════════════════════════════
        # 降噪层 3: 校准路径匹配 — 增强: 多探针 + 响应时间
        # ═══════════════════════════════════════════════════════
        if catchall_median_size > 0:
            for r in results:
                if r.status == 200 and r.category != "info" and not r.is_catchall:
                    if abs(r.size - catchall_median_size) <= max(100, catchall_median_size * 0.12):
                        r.is_catchall = True

            # 响应时间匹配: CDN catch-all 通常响应时间非常一致
            if catchall_avg_time > 0:
                for r in results:
                    if r.status == 200 and not r.is_catchall and r.category != "info":
                        if abs(r.response_time - catchall_avg_time) < 0.05:
                            # 响应时间几乎一样 + 尺寸接近 → catchall
                            if abs(r.size - catchall_median_size) <= max(200, catchall_median_size * 0.2):
                                r.is_catchall = True

            # 内容前缀匹配
            for preview in catchall_previews:
                if not preview:
                    continue
                for r in results:
                    if r.status == 200 and not r.is_catchall:
                        common_len = min(len(preview), len(r.content_preview), 80)
                        if common_len > 30 and preview[:common_len] == r.content_preview[:common_len]:
                            r.is_catchall = True

            # 多数探针返回 200 且有内容 → 所有 200 路径全部可疑
            if len(probe_results) >= 2:
                probes_with_content = sum(1 for s, _, _ in probe_results if s > 200)
                if probes_with_content >= 2:
                    for r in results:
                        if r.status == 200 and r.category != "info":
                            r.is_catchall = True

        # ═══════════════════════════════════════════════════════
        # 降噪层 4: 响应头分析 — CDN/WAF 指标检测
        # ═══════════════════════════════════════════════════════
        self._reduce_noise_header_analysis(results)

        # ═══════════════════════════════════════════════════════
        # 降噪层 5: 内容模式匹配 — 错误/停放页面检测
        # ═══════════════════════════════════════════════════════
        self._reduce_noise_content_patterns(results)

        # ═══════════════════════════════════════════════════════
        # 降噪层 6: 行为分析 — 跨路径模式检测
        # ═══════════════════════════════════════════════════════
        self._reduce_noise_behavioral(results)

        return [r for r in results if r.is_interesting]

    # ── Layer 4: 响应头分析 ─────────────────────────────
    def _reduce_noise_header_analysis(self, results: list[PathFind]) -> None:
        """检查响应头中的 CDN/WAF 指标，结合内容特征标记 catchall"""
        for r in results:
            if r.is_catchall:
                continue
            headers = r.response_headers
            has_cdn_header = False

            # 检查 Server 头
            server = headers.get("server", "").lower()
            if any(kw in server for kw in self._CDN_SERVER_KEYWORDS):
                has_cdn_header = True

            # 检查 X-Cache 头
            xcache = headers.get("x-cache", "").lower()
            if "hit" in xcache:
                has_cdn_header = True

            # 检查其他 CDN 标记头
            for marker in self._CDN_HEADER_MARKERS:
                if marker in headers:
                    has_cdn_header = True
                    break

            # CDN 头 + 内容是通用 HTML (无 JSON/API 特征) → catchall
            if has_cdn_header and r.status == 200 and r.category != "info":
                ct = r.content_type.lower()
                preview_lower = r.content_preview.lower()
                # 如果返回的是 JSON 或有 API 特征，不算 catchall
                if "application/json" in ct or "application/xml" in ct:
                    continue
                if any(kw in preview_lower for kw in ("{", '"api"', '"data"', '"result"')):
                    # 可能是真实 API 响应
                    if r.content_preview.lstrip().startswith("{"):
                        continue
                # 通用 HTML 且有 CDN 标记 → catchall
                if "text/html" in ct and r.size > 1024:
                    r.is_catchall = True

    # ── Layer 5: 内容模式匹配 ───────────────────────────
    def _reduce_noise_content_patterns(self, results: list[PathFind]) -> None:
        """检测常见的错误页面/停放页面/托管商默认页面"""
        for r in results:
            if r.is_catchall or r.category == "info":
                continue
            if r.status not in (200, 403, 404):
                continue

            preview_lower = r.content_preview.lower()

            # 匹配 catchall 内容关键词
            for pattern in self._CATCHALL_CONTENT_PATTERNS:
                if pattern in preview_lower:
                    r.is_catchall = True
                    break

            if r.is_catchall:
                continue

            # 检测 Cloudflare 错误页 (Error XXXX 模式)
            if re.search(r"error\s+10\d{2}", preview_lower):
                r.is_catchall = True
                continue

            # 检测标准 404 模板 (title 里有 404 且内容很短)
            if "404" in preview_lower and r.size < 3000:
                if re.search(r"<title>[^<]*404[^<]*</title>", preview_lower):
                    r.is_catchall = True
                    continue

            # 检测 "default page" / "it works" 等默认页面
            if r.status == 200 and r.size < 2000:
                if any(kw in preview_lower for kw in (
                    "it works", "default page", "welcome to",
                    "apache2 ubuntu default", "nginx default",
                )):
                    r.is_catchall = True

    # ── Layer 6: 行为分析 ───────────────────────────────
    def _reduce_noise_behavioral(self, results: list[PathFind]) -> None:
        """跨路径行为模式分析 — 统计同一目标的响应一致性"""
        active = [r for r in results if not r.is_catchall and r.category != "info"]
        if len(active) < 3:
            return

        # 6a: 状态码一致性 — 90%+ 返回同一状态码 → 可疑
        status_counts: dict[int, int] = {}
        for r in active:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
        total = len(active)
        for status, count in status_counts.items():
            if count / total >= 0.9 and count >= 3:
                # 该状态码的路径全部标记 (但不标记 403 — 403 可能是真实行为)
                if status != 403:
                    for r in active:
                        if r.status == status:
                            r.is_catchall = True

        # 重新统计未标记的
        active = [r for r in active if not r.is_catchall]
        if len(active) < 2:
            return

        # 6b: 内容 hash 一致性 — 所有路径返回完全相同的响应体 → 确定 catchall
        hash_counts: dict[str, list[PathFind]] = {}
        for r in active:
            if r.content_hash:
                hash_counts.setdefault(r.content_hash, []).append(r)
        for h, group in hash_counts.items():
            if len(group) >= 3:
                for r in group:
                    r.is_catchall = True

        # 6c: 响应时间一致性 — ±5ms 的均匀时间 → CDN 缓存
        active = [r for r in active if not r.is_catchall]
        if len(active) >= 3:
            times = [r.response_time for r in active]
            if len(times) >= 3:
                try:
                    stddev = statistics.stdev(times)
                    mean_t = statistics.mean(times)
                    # 标准差极小且均值合理 → CDN cache
                    if stddev < 0.005 and mean_t > 0.01:
                        for r in active:
                            r.is_catchall = True
                except statistics.StatisticsError:
                    pass

    def scan_sync(self, base_url: str, tech: str = "") -> list[PathFind]:
        """同步版"""
        return asyncio.run(self.scan(base_url, tech))
