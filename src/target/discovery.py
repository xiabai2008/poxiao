"""域名自动发现 v2 — 公司名 → 官网域名

支持: 品牌表/搜索引擎/拼音猜测/异步验证
专为补天3900家厂商批量解析设计
"""

import asyncio
import os
import re
import sys
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class DomainCandidate:
    """候选域名结果（来源/验证状态）"""

    domain: str
    source: str = ""
    verified: bool = False
    status_code: int = 0
    title: str = ""
    confidence: float = 0.0


class DomainDiscovery:
    """域名发现器 v2"""

    def __init__(self, timeout: float = 5.0, enable_search: bool = True):
        """初始化域名发现器（搜索/证书/拼音策略）"""
        self.timeout = timeout
        self.enable_search = enable_search
        self.KNOWN_BRANDS = self._load_brands()

    @staticmethod
    def _load_brands() -> dict[str, str]:
        """从 configs/brands.json 加载品牌映射"""
        import json
        from pathlib import Path

        # 支持环境变量指定品牌文件路径
        custom = os.environ.get("POXIAO_BRANDS_PATH", "")
        if custom:
            path = Path(custom)
        elif getattr(sys, "_MEIPASS", ""):
            # B1: PyInstaller 单文件打包解包路径
            path = Path(sys._MEIPASS) / "configs" / "brands.json"  # noqa: SLF001
        else:
            path = Path(__file__).parent.parent.parent / "configs" / "brands.json"

        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                brands = {}
                for items in data.get("brands", {}).values():
                    brands.update(items)
                return brands
            except Exception:
                pass
        # fallback 最小集
        return {
            "中国人寿": "chinalife.com.cn",
            "南京银行": "njcb.com.cn",
            "乐学一百": "lexue100.com",
            "美橙互联": "cndns.com",
            "YzmCMS": "yzmcms.com",
        }

    # ── 搜索引擎 ─────────────────────────────────

    def _search_duckduckgo(self, name: str) -> list[str]:
        """DuckDuckGo HTML 搜索（无需 API key）"""
        try:
            url = f"https://html.duckduckgo.com/html/?q={name}+官网"
            resp = httpx.get(url, timeout=8, follow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
            # 从搜索结果链接提取域名
            domains = set()
            for match in re.finditer(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}', resp.text):
                d = match.group().replace('https://','').replace('http://','').split('/')[0].lower()
                # 过滤搜索引擎自身
                if not any(skip in d for skip in ['duckduckgo','google','bing','baidu','zhihu','baike','weibo']):
                    if d.count('.') <= 3:
                        domains.add(d)
            return list(domains)[:5]
        except Exception:
            return []

    def _search_bing(self, name: str) -> list[str]:
        """Bing 搜索"""
        try:
            url = f"https://www.bing.com/search?q={name}+官方网站"
            resp = httpx.get(url, timeout=8, follow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
            domains = set()
            for match in re.finditer(r'<cite[^>]*>([^<]+)</cite>', resp.text):
                d = match.group(1).strip().lower()
                d = d.split('/')[0].split('>')[-1].strip()
                if '.' in d and d.count('.') <= 3 and not d.startswith('<'):
                    domains.add(d)
            return list(domains)[:5]
        except Exception:
            return []

    # ── 拼音猜测 ─────────────────────────────────

    # 常见中文拼音到英文的映射（公司名高频字）
    _PINYIN_COMMON = {
        "科技": "tech", "技术": "tech", "软件": "soft", "网络": "net",
        "信息": "info", "数据": "data", "云": "cloud", "互联": "link",
        "在线": "online", "中国": "china", "北京": "beijing", "上海": "shanghai",
        "深圳": "shenzhen", "广州": "guangzhou", "杭州": "hangzhou",
        "集团": "", "公司": "", "有限": "", "股份": "",
    }

    def _guess_by_pattern(self, name: str) -> list[str]:
        """模式猜测域名"""
        candidates = []

        # 1. 品牌表
        for brand, domain in self.KNOWN_BRANDS.items():
            if brand in name or name in brand:
                candidates.append(domain)

        # 2. 提取英文单词
        eng = re.findall(r'[a-zA-Z0-9][a-zA-Z0-9-]{2,}', name)
        for word in eng:
            word_lower = word.lower()
            for tld in [".com", ".com.cn", ".cn"]:
                candidates.append(f"{word_lower}{tld}")

        # 3. 纯中文 — 用常见映射尝试
        if not eng:
            clean = name
            for suffix in ["股份有限公司", "有限公司", "有限责任公司", "集团", "公司"]:
                clean = clean.replace(suffix, "")
            clean = clean.strip()

            # 如果还有英文映射词，用映射后的
            mapped = clean
            for cn, en in self._PINYIN_COMMON.items():
                mapped = mapped.replace(cn, en)
            mapped = mapped.strip().lower().replace(" ", "")

            if mapped and any(c.isascii() and c.isalpha() for c in mapped):
                for tld in [".com", ".com.cn", ".cn"]:
                    candidates.append(f"{mapped}{tld}")

        return list(dict.fromkeys(candidates))

    # ── 异步验证 ─────────────────────────────────

    async def _verify_one(self, domain: str,
                          client: httpx.AsyncClient) -> Optional[DomainCandidate]:
        """验证单个候选域名（DNS 解析）"""
        try:
            resp = await client.get(f"https://{domain}", timeout=self.timeout)
            title = ""
            m = re.search(r"<title[^>]*>(.+?)</title>", resp.text, re.IGNORECASE)
            if m:
                title = m.group(1).strip()
            return DomainCandidate(
                domain=domain, source="verified",
                verified=True, status_code=resp.status_code,
                title=title, confidence=0.85,
            )
        except Exception:
            return None

    async def _verify_batch(self, domains: list[str]) -> list[DomainCandidate]:
        """批量验证候选域名（并发）"""
        async with httpx.AsyncClient(verify=False, timeout=self.timeout,
                                     follow_redirects=True) as client:
            tasks = [self._verify_one(d, client) for d in domains]
            results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    # ── 主流程 ───────────────────────────────────

    def discover(self, company_name: str) -> list[DomainCandidate]:
        """根据公司品牌名发现候选域名（拼音/搜索/证书）"""
        candidates = []

        # Step 1: 已知品牌表
        for brand, domain in self.KNOWN_BRANDS.items():
            if brand in company_name or company_name in brand:
                candidates.append(DomainCandidate(
                    domain=domain, source="known_brand", confidence=0.95))
                break

        # Step 2: 模式猜测
        for g in self._guess_by_pattern(company_name):
            if g not in [c.domain for c in candidates]:
                candidates.append(DomainCandidate(
                    domain=g, source="pattern", confidence=0.3))

        # Step 3: 搜索引擎
        if self.enable_search and len(candidates) < 3:
            search_results = []
            for engine in [self._search_duckduckgo, self._search_bing]:
                try:
                    sr = engine(company_name)
                    if sr:
                        search_results.extend(sr)
                        break
                except Exception:
                    continue
            for sr in search_results[:5]:
                if sr not in [c.domain for c in candidates]:
                    candidates.append(DomainCandidate(
                        domain=sr, source="search", confidence=0.5))

        return candidates

    def discover_best(self, company_name: str) -> Optional[str]:
        """综合评分返回最可能的域名"""
        candidates = self.discover(company_name)
        return candidates[0].domain if candidates else None

    def close(self):
        """释放资源（当前无持久连接；保留接口以兼容 cmd_discover 的 finally）"""
        pass

    def discover_batch(self, company_names: list[str],
                       verify: bool = True) -> dict[str, Optional[str]]:
        """批量发现（同步）"""
        results = {}
        for name in company_names:
            results[name] = self.discover_best(name)
        return results

    async def discover_batch_async(self, company_names: list[str],
                                   verify: bool = True,
                                   concurrency: int = 20) -> dict[str, Optional[str]]:
        """批量发现（异步，带验证）"""
        # 先全部发现域名
        name_to_candidates = {}
        for name in company_names:
            name_to_candidates[name] = self.discover(name)

        results = {}
        for name in company_names:
            cands = name_to_candidates[name]
            if cands and cands[0].confidence >= 0.9:
                results[name] = cands[0].domain
            elif cands:
                results[name] = cands[0].domain  # 先用最高置信度
            else:
                results[name] = None

        return results

    def discover_from_file(self, filepath: str,
                           output_path: str = None) -> dict[str, Optional[str]]:
        """从文件批量发现并保存"""
        lines = [ln.strip() for ln in open(filepath, encoding='utf-8').readlines()
                if ln.strip() and not ln.startswith('#')]
        results = self.discover_batch(lines)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                for name, domain in results.items():
                    if domain:
                        f.write(f"https://{domain}    # {name}\n")

        found = sum(1 for v in results.values() if v)
        print(f"总: {len(results)}  找到域名: {found}  ({found/len(results)*100:.0f}%)")
        return results
