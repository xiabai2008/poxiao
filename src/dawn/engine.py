"""扫描引擎 — 编排完整的信息收集流程"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

from .tech_stack import TechStackDetector, TechFingerprint
from .sensitive import SensitivePathDetector, PathFind
from .version_extract import VersionExtractor, VersionInfo
from .cve_match import CVEMatcher, VulnMatch

logger = logging.getLogger("poxiao.scanner.engine")


def normalize_tech_tag(tag: str) -> tuple[str, str]:
    """技术栈标签 → (组件名, 版本)

    标签可能带类别前缀或版本后缀:
      "iis/10.0"        → ("iis", "10.0")
      "nginx/1.18.0"    → ("nginx", "1.18.0")
      "db:mysql"        → ("mysql", "")
      "cdn:cloudflare"  → ("cloudflare", "")
      "asp.net"         → ("asp.net", "")
    返回空组件表示该标签不可用于 CVE 匹配（如 analytics 类）。
    """
    t = tag.strip()
    for prefix in ("cdn:", "waf:", "platform:", "db:", "analytics:"):
        if t.lower().startswith(prefix):
            t = t[len(prefix):]
            break
    if "/" in t:
        comp, _, ver = t.partition("/")
        return comp.strip(), ver.strip()
    return t, ""


@dataclass
class ScanResult:
    """单目标扫描结果"""
    target_url: str
    host: str = ""
    alive: bool = False
    status_code: int = 0
    redirect_url: str = ""
    duration_sec: float = 0.0
    # 信息收集
    tech: TechFingerprint = field(default_factory=TechFingerprint)
    tech_tags: list[str] = field(default_factory=list)
    versions: list[VersionInfo] = field(default_factory=list)
    cve_matches: list[VulnMatch] = field(default_factory=list)
    sensitive_paths: list[PathFind] = field(default_factory=list)
    # 摘要
    error: str = ""

    def to_dict(self) -> dict:
        """扫描结果序列化为字典（供报告/JSON 输出）"""
        return {
            "target_url": self.target_url,
            "host": self.host,
            "alive": self.alive,
            "status_code": self.status_code,
            "redirect_url": self.redirect_url,
            "duration_sec": round(self.duration_sec, 1),
            "tech": self.tech.known,
            "tech_tags": self.tech_tags,
            "versions": {v.component: v.version for v in self.versions},
            "cve_matches": [
                {
                    "cve": m.cve_id,
                    "severity": m.severity,
                    "description": m.description[:150],
                }
                for m in self.cve_matches
            ],
            "sensitive_paths": [
                {
                    "url": p.url,
                    "status": p.status,
                    "size": p.size,
                    "category": p.category,
                }
                for p in self.sensitive_paths
            ],
            "sensitive_count": len(self.sensitive_paths),
            "error": self.error,
        }

    @property
    def interesting_count(self) -> int:
        """真正有意思的发现数"""
        return len([p for p in self.sensitive_paths if p.is_interesting])

    @property
    def summary_line(self) -> str:
        """一行摘要"""
        parts = [
            self.target_url,
            f"status={self.status_code}" if self.alive else "DEAD",
        ]
        if self.tech.known:
            tags = self.tech_tags[:3]
            parts.append(f"tech={'+'.join(tags)}")
        good = self.interesting_count
        if good:
            parts.append(f"found={good}")
        if self.versions:
            parts.append(f"v={len(self.versions)}")
        if self.cve_matches:
            crit = len([m for m in self.cve_matches if m.is_critical])
            parts.append(f"cve={len(self.cve_matches)}c/{crit}")
        return "  ".join(parts)


def _dedupe_cve_matches(matches: list[VulnMatch]) -> list[VulnMatch]:
    """Deduplicate CVE matches by CVE ID, preferring local over NVD."""
    seen: dict[str, VulnMatch] = {}
    for m in matches:
        key = m.cve_id
        if key in seen:
            # Prefer local matches (they have better metadata)
            existing = seen[key]
            if existing.match_type == "local" and m.match_type == "nvd":
                continue
            if existing.match_type == "nvd" and m.match_type == "local":
                seen[key] = m
                continue
            # Same type: keep higher CVSS
            if m.cvss_score > existing.cvss_score:
                seen[key] = m
        else:
            seen[key] = m
    return list(seen.values())


class ScanEngine:
    """扫描引擎"""

    def __init__(
        self,
        timeout: float = 5.0,
        concurrency: int = 5,
        enable_sensitive: bool = True,
        enable_nvd: bool = False,
    ):
        """初始化扫描引擎（超时/并发/敏感检测开关/NVD 增强）"""
        self.timeout = timeout
        self.concurrency = concurrency
        self.enable_sensitive = enable_sensitive
        self.enable_nvd = enable_nvd
        self.tech_detector = TechStackDetector()
        self.version_extractor = VersionExtractor()
        self.sensitive_detector = SensitivePathDetector(timeout=timeout)
        # E3: 懒创建共享 HTTP 客户端（连接池复用 + 默认浏览器 UA），
        # 由 aclose()/context manager 统一释放
        self._client: Optional[httpx.AsyncClient] = None
        self._default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/126.0.0.0 Safari/537.36",
        }

        # Load NVD API key from config system if available
        nvd_api_key = ""
        try:
            from src.config import get_config
            nvd_api_key = get_config().get("cve", "nvd_api_key", "")
        except Exception:
            pass
        self.cve_matcher = CVEMatcher(nvd_api_key=nvd_api_key)

    async def _get_client(self) -> httpx.AsyncClient:
        """获取共享客户端（首次调用时创建）"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                headers=self._default_headers,
            )
        return self._client

    async def aclose(self) -> None:
        """释放共享客户端连接池（任务结束必须调用）"""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "ScanEngine":
        """异步上下文管理器进入（支持 async with ScanEngine() 用法）"""
        return self

    async def __aexit__(self, *exc) -> None:
        """异步上下文管理器退出（释放共享 HTTP 连接池）"""
        await self.aclose()

    def _enrich_with_nvd(self, versions: dict) -> list[VulnMatch]:
        """
        Query NVD API for each component+version pair.
        Returns deduplicated results merged with existing matches.
        Only called when enable_nvd is True.
        """
        if not self.enable_nvd or not versions:
            return []
        try:
            nvd_results = self.cve_matcher.query_nvd_batch(versions)
            logger.info("NVD query returned %d results for %d components",
                        len(nvd_results), len(versions))
            return nvd_results
        except Exception as e:
            logger.warning("NVD query failed: %s", e)
            return []

    async def scan_one(self, url: str) -> ScanResult:
        """扫描单个目标 — 渐进式输出基础"""
        start = time.perf_counter()
        result = ScanResult(target_url=url)

        from urllib.parse import urlparse
        result.host = urlparse(url).netloc

        try:
            # Step 1: HTTP GET 获取基础信息（复用共享客户端/连接池）
            client = await self._get_client()
            resp = await client.get(url, follow_redirects=True)
            result.alive = True
            result.status_code = resp.status_code

            if resp.history:
                result.redirect_url = str(resp.url)

            headers = dict(resp.headers)
            cookies = dict(resp.cookies)
            html = resp.text

            # Step 2: 技术栈识别
            result.tech = self.tech_detector.detect(
                headers=headers,
                cookies=cookies,
                html=html,
                url=url,
            )
            result.tech_tags = self.tech_detector.as_tags(result.tech)

            # Step 3: 版本号提取 + CVE 匹配 (local + NVD)
            result.versions = self.version_extractor.extract(headers, html)
            all_cve_matches: list[VulnMatch] = []

            if result.versions:
                ver_dict = {v.component: v.version for v in result.versions}
                # Local database match
                all_cve_matches.extend(self.cve_matcher.match_batch(ver_dict))

                # NVD API enrichment (if enabled)
                nvd_matches = self._enrich_with_nvd(ver_dict)
                all_cve_matches.extend(nvd_matches)

            # 即使没有精确版本，也根据识别的技术栈做本地匹配
            # 技术栈标签可能带类别前缀 (cdn:/waf:/platform:/db:) 或版本 (iis/10.0)，
            # 归一化为 (组件名, 版本) 后再匹配，避免 `match("iis/10.0")` 静默 0 命中。
            for tag in result.tech_tags:
                comp, ver = normalize_tech_tag(tag)
                if not comp:
                    continue
                all_cve_matches.extend(self.cve_matcher.match(comp, ver))

            # Deduplicate and set
            result.cve_matches = _dedupe_cve_matches(all_cve_matches)

            # Step 4: 敏感路径检测（可选；复用共享客户端连接池）
            if self.enable_sensitive:
                tech_key = result.tech.cms or result.tech.language or ""
                result.sensitive_paths = await self.sensitive_detector.scan(
                    url, tech=tech_key, client=client
                )

        except httpx.ConnectError:
            result.alive = False
            result.error = "connection failed"
        except httpx.TimeoutException:
            result.alive = False
            result.error = "timeout"
        except Exception as e:
            result.error = str(e)[:200]

        result.duration_sec = time.perf_counter() - start
        return result

    async def scan_batch(self, urls: list[str]) -> list[ScanResult]:
        """批量扫描（并发）"""
        sem = asyncio.Semaphore(self.concurrency)

        async def _worker(u: str) -> ScanResult:
            """并发工作协程：扫描单目标（信号量限流）"""
            async with sem:
                return await self.scan_one(u)

        tasks = [_worker(u) for u in urls]
        return await asyncio.gather(*tasks)

    def scan_batch_sync(self, urls: list[str]) -> list[ScanResult]:
        """同步版批量扫描"""
        return asyncio.run(self.scan_batch(urls))
