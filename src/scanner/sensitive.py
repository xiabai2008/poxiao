"""敏感路径/文件发现 — 带 CDN/CloudFront 假阳性降噪"""

import asyncio
from dataclasses import dataclass
from itertools import groupby
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
            resp = await client.get(full_url, timeout=self.timeout)
            if resp.status_code in (200, 301, 302, 403):
                size = len(resp.content)
                # 捕获前 200 字节用于内容相似度分析
                preview = ""
                try:
                    preview = resp.content[:200].decode("utf-8", errors="ignore")
                except Exception:
                    pass

                return PathFind(
                    url=full_url,
                    status=resp.status_code,
                    size=size,
                    content_type=resp.headers.get("content-type", ""),
                    category=category,
                    content_preview=preview,
                    is_catchall=False,  # 扫描阶段不判定，留到降噪
                )
        except Exception:
            pass
        return None

    async def scan(self, base_url: str, tech: str = "") -> list[PathFind]:
        """扫描目标 — 三层降噪"""
        paths = self.get_paths(tech)
        sem = asyncio.Semaphore(self.concurrency)
        results: list[PathFind] = []

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # ── 校准探测器: 访问一个不可能存在的随机路径 ──
            catchall_preview = ""
            catchall_size = 0
            try:
                probe = await client.get(
                    f"{base_url.rstrip('/')}/_poxiao_no_such_8472_test_"
                )
                if probe.status_code == 200:
                    catchall_size = len(probe.content)
                    try:
                        catchall_preview = probe.content[:200].decode("utf-8", errors="ignore")
                    except Exception:
                        pass
            except Exception:
                pass

            async def _worker(p: str, cat: str):
                async with sem:
                    found = await self._check_one(base_url, p, cat, client)
                    if found:
                        results.append(found)

            tasks = [_worker(p, cat) for p, cat in paths]
            await asyncio.gather(*tasks)

        # ═══════════════════════════════════════════════════════
        # 降噪层 1: 内容特征 — 不该返回 HTML 但返回了 HTML
        # ═══════════════════════════════════════════════════════
        html_categories = {"config", "backup", "git", "source", "api", "db"}
        for r in results:
            if r.status == 200 and r.category in html_categories:
                preview = r.content_preview.lower().lstrip()  # 去掉前导空白
                # 配置文件不应该以 <html / <!doctype / <script 开头
                if (preview.startswith("<!doctype") or
                    preview.startswith("<html") or
                    preview.startswith("<script")):
                    r.is_catchall = True

        # ═══════════════════════════════════════════════════════
        # 降噪层 2: 尺寸聚类 — 多个同状态路径尺寸高度相似
        # ═══════════════════════════════════════════════════════
        # 按 (status, category_group) 分组
        # group: "data" = config/backup/git/source — 这些不可能同尺寸
        # group: "web" = admin/login/api — 这些有相似尺寸也算可疑
        for r in results:
            if r.is_catchall:
                continue
            # 只有 200/403 做聚类
            if r.status not in (200, 403):
                continue
            # 排除正常类别
            if r.category == "info":
                continue

            # 统计与当前路径 size 接近（±8% 或 ±80 字节）的同状态结果数
            tol = max(80, int(r.size * 0.08))
            similar = sum(
                1 for other in results
                if other.status == r.status
                and other.category != "info"
                and abs(other.size - r.size) <= tol
            )
            # 3+ 个不同路径返回同尺寸 → 几乎确定是统一错误页
            if similar >= 3:
                r.is_catchall = True

        # ═══════════════════════════════════════════════════════
        # 降噪层 3: 校准路径匹配 — 如果探测路径返回 200 且有内容
        #           所有与它尺寸接近的 200 路径都标记
        # ═══════════════════════════════════════════════════════
        if catchall_size > 0:
            for r in results:
                if r.status == 200 and r.category != "info":
                    if abs(r.size - catchall_size) <= max(100, catchall_size * 0.12):
                        r.is_catchall = True
            # 额外检查：如果探测路径的内容前缀跟其他路径一致
            if catchall_preview:
                for r in results:
                    if r.status == 200 and not r.is_catchall:
                        # 简单内容相似度：前 80 字符一致
                        common_len = min(len(catchall_preview), len(r.content_preview), 80)
                        if common_len > 30 and catchall_preview[:common_len] == r.content_preview[:common_len]:
                            r.is_catchall = True

        return [r for r in results if r.is_interesting]

    def scan_sync(self, base_url: str, tech: str = "") -> list[PathFind]:
        """同步版"""
        return asyncio.run(self.scan(base_url, tech))
