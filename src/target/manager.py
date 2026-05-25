"""目标管理 — 加载、去重、存活检测、分类"""

import asyncio
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx


@dataclass
class Target:
    """扫描目标"""
    url: str
    host: str = ""
    is_alive: bool = False
    status_code: int = 0
    redirect_url: str = ""
    category: str = "unknown"  # gov/edu/bank/insurance/ecommerce/enterprise

    def __post_init__(self):
        if not self.host:
            parsed = urlparse(self.url)
            self.host = parsed.netloc or parsed.path.split("/")[0]

    @property
    def normalized(self) -> str:
        """规范化 URL，去掉尾部斜杠"""
        return self.url.rstrip("/")

    @property
    def domain_key(self) -> str:
        """用于去重的域名 key"""
        return self.host.lower().replace("www.", "")

    @property
    def fingerprint(self) -> str:
        """目标唯一标识"""
        return hashlib.md5(self.domain_key.encode()).hexdigest()[:12]


class TargetManager:
    """目标管理器"""

    def __init__(self, timeout: float = 5.0, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = concurrency

    # ── 加载 ──────────────────────────────────────

    def load_from_file(self, path: str) -> list[Target]:
        """从文件加载目标（支持 # 注释）"""
        filepath = Path(path)
        if not filepath.exists():
            raise FileNotFoundError(f"目标文件不存在: {path}")

        targets = []
        for line in filepath.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 去掉行内注释（URL 后面的 # 注释）
            if " #" in line:
                line = line.split(" #")[0].strip()
            # 自动补全协议
            if not line.startswith("http"):
                line = f"https://{line}"
            targets.append(Target(url=line))
        return targets

    def load_from_list(self, urls: list[str]) -> list[Target]:
        """从列表加载"""
        return [Target(url=u) for u in urls if u.strip()]

    # ── 去重 ──────────────────────────────────────

    def deduplicate(self, targets: list[Target]) -> list[Target]:
        """按域名去重，保留首次出现"""
        seen = set()
        result = []
        for t in targets:
            key = t.domain_key
            if key not in seen:
                seen.add(key)
                result.append(t)
        return result

    # ── 存活检测 ──────────────────────────────────

    async def _check_one(self, target: Target, client: httpx.AsyncClient) -> Target:
        """检测单个目标是否存活"""
        try:
            resp = await client.head(
                target.url,
                follow_redirects=True,
                timeout=self.timeout,
            )
            target.status_code = resp.status_code
            if resp.status_code < 500:
                target.is_alive = True
            # 记录跳转
            if resp.history:
                target.redirect_url = str(resp.url)
        except httpx.ConnectError:
            target.is_alive = False
        except httpx.TimeoutException:
            target.is_alive = False
        except Exception:
            target.is_alive = False
        return target

    async def check_alive(self, targets: list[Target]) -> list[Target]:
        """并发存活检测"""
        sem = asyncio.Semaphore(self.concurrency)

        async def _bounded(t: Target) -> Target:
            async with sem:
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                    return await self._check_one(t, client)

        tasks = [_bounded(t) for t in targets]
        return await asyncio.gather(*tasks)

    def check_alive_sync(self, targets: list[Target]) -> list[Target]:
        """同步版存活检测"""
        return asyncio.run(self.check_alive(targets))

    # ── 分类 ──────────────────────────────────────

    CATEGORY_RULES = {
        "gov":     [".gov.cn"],
        "edu":     [".edu.cn", ".edu", "edu.cn"],
        "bank":    ["bank", "ccb.com", "icbc.com", "abchina.com", "boc.cn"],
        "insurance": ["life.com", "insurance", "ins.com"],
        "ecommerce": ["shop", "mall", "buy", "store"],
    }

    def classify(self, targets: list[Target]) -> list[Target]:
        """按域名后缀自动分类"""
        for t in targets:
            host = t.host.lower()
            for cat, patterns in self.CATEGORY_RULES.items():
                if any(p in host for p in patterns):
                    t.category = cat
                    break
            else:
                t.category = "enterprise"
        return targets

    # ── 汇总 ──────────────────────────────────────

    def summary(self, targets: list[Target]) -> dict:
        """生成目标汇总"""
        alive = [t for t in targets if t.is_alive]
        return {
            "total": len(targets),
            "alive": len(alive),
            "dead": len(targets) - len(alive),
            "categories": {
                cat: len([t for t in targets if t.category == cat])
                for cat in sorted(set(t.category for t in targets))
            },
            "targets": [
                {
                    "url": t.url,
                    "host": t.host,
                    "alive": t.is_alive,
                    "status": t.status_code,
                    "category": t.category,
                }
                for t in targets
            ],
        }
