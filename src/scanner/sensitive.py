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
        self, base_url: str, path: str, category: str, client: httpx.AsyncClient
    ) -> Optional[PathFind]:
        """检测单个路径"""
        full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            resp = await client.get(full_url, timeout=self.timeout)
            if resp.status_code in (200, 301, 302, 403):
                return PathFind(
                    url=full_url,
                    status=resp.status_code,
                    size=len(resp.content),
                    content_type=resp.headers.get("content-type", ""),
                    category=category,
                )
        except Exception:
            pass
        return None

    async def scan(self, base_url: str, tech: str = "") -> list[PathFind]:
        """扫描目标"""
        paths = self.get_paths(tech)
        sem = asyncio.Semaphore(self.concurrency)
        results: list[PathFind] = []

        async def _worker(p: str, cat: str):
            async with sem:
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                    found = await self._check_one(base_url, p, cat, client)
                    if found:
                        results.append(found)

        tasks = [_worker(p, cat) for p, cat in paths]
        await asyncio.gather(*tasks)
        return results

    def scan_sync(self, base_url: str, tech: str = "") -> list[PathFind]:
        """同步版"""
        return asyncio.run(self.scan(base_url, tech))
