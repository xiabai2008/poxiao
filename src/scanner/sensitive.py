"""敏感路径/文件发现"""

import asyncio
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class PathFind:
    """路径发现结果"""
    url: str
    status: int
    size: int = 0
    content_type: str = ""
    category: str = ""  # config/backup/debug/git/admin/api
    is_catchall: bool = False  # CDN/WAF 把所有请求都返回 200

    @property
    def is_interesting(self) -> bool:
        """判断是否值得关注"""
        # 跳过信息类（robots.txt 等在大多数网站都有）
        if self.category == "info":
            return False
        # 跳过 CDN 假阳性
        if self.is_catchall:
            return False
        # 200 + 有实际内容（非空页面）才值得关注
        if self.status == 200 and self.size > 100:
            return True
        # 403 可能有价值（目录存在但被拒绝）
        if self.status == 403:
            return True
        # 301/302 redirect 到明显非预期位置的不算
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
        client: httpx.AsyncClient, known_catchall_size: int = -1,
    ) -> Optional[PathFind]:
        """检测单个路径"""
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            resp = await client.get(full_url, timeout=self.timeout)
            if resp.status_code in (200, 301, 302, 403):
                size = len(resp.content)
                # 检测 CDN catch-all: 如果状态码是 200 但内容是 HTML 页面
                # 且篇幅与已知 catch-all 一样或相近，标记为假阳性
                is_catch = False
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "html" in ct.lower() and category in ("config", "backup", "debug"):
                        # 如果 body 包含 <html> 标签，几乎确定是 catch-all
                        body = resp.content[:200].decode("utf-8", errors="ignore").lower()
                        if "<html" in body or "<!doctype" in body:
                            is_catch = True
                    # 如果大小跟已知 catchall 接近（±20%），也标记
                    if known_catchall_size > 0 and abs(size - known_catchall_size) < size * 0.3:
                        is_catch = True

                return PathFind(
                    url=full_url,
                    status=resp.status_code,
                    size=size,
                    content_type=resp.headers.get("content-type", ""),
                    category=category,
                    is_catchall=is_catch,
                )
        except Exception:
            pass
        return None

    async def scan(self, base_url: str, tech: str = "") -> list[PathFind]:
        """扫描目标"""
        paths = self.get_paths(tech)
        sem = asyncio.Semaphore(self.concurrency)
        results: list[PathFind] = []

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # 先探测一个不可能存在的路径来校准 catch-all
            catchall_size = -1
            try:
                probe = await client.get(
                    f"{base_url.rstrip('/')}/_poxiao_no_such_8472_test_"
                )
                if probe.status_code == 200:
                    ct = probe.headers.get("content-type", "")
                    if "html" in ct.lower():
                        catchall_size = len(probe.content)
            except Exception:
                pass

            async def _worker(p: str, cat: str):
                async with sem:
                    found = await self._check_one(base_url, p, cat, client, catchall_size)
                    if found:
                        results.append(found)

            tasks = [_worker(p, cat) for p, cat in paths]
            await asyncio.gather(*tasks)

        # 过滤噪声：相同尺寸+状态码聚类
        from collections import Counter
        # 403 聚类 — 同一尺寸出现 3+ 次，或尺寸在 ±5% 范围内合并计数
        sizes_403 = [r.size for r in results if r.status == 403]
        for r in results:
            if r.status == 403:
                similar = sum(1 for s in sizes_403 if abs(s - r.size) < max(50, r.size * 0.05))
                if similar >= 3:
                    r.is_catchall = True

        # 200 聚类 — 多个配置/备份/源码路径都返回 200 且同尺寸 → CDN catch-all
        sizes_200 = Counter(r.size for r in results if r.status == 200 and r.category in ("config","backup","source","git"))
        for r in results:
            if r.status == 200 and r.category in ("config","backup","source","git"):
                if sizes_200.get(r.size, 0) >= 2:
                    r.is_catchall = True

        # 只返回 interesting 的
        return [r for r in results if r.is_interesting]

    def scan_sync(self, base_url: str, tech: str = "") -> list[PathFind]:
        """同步版"""
        return asyncio.run(self.scan(base_url, tech))
