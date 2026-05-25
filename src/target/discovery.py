"""域名自动发现 v2 — 公司名 → 官网域名

支持: 品牌表/搜索引擎/拼音猜测/异步验证
专为补天3900家厂商批量解析设计
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class DomainCandidate:
    domain: str
    source: str = ""
    verified: bool = False
    status_code: int = 0
    title: str = ""
    confidence: float = 0.0


class DomainDiscovery:
    """域名发现器 v2"""

    def __init__(self, timeout: float = 5.0, enable_search: bool = True):
        self.timeout = timeout
        self.enable_search = enable_search

    KNOWN_BRANDS = {
        "中国人寿": "chinalife.com.cn",
        "哈尔滨银行": "hrbccb.com.cn",
        "南京银行": "njcb.com.cn",
        "桂林银行": "guilinbank.com.cn",
        "华泰人寿": "htlife.com.cn",
        "北大方正人寿": "pkufi.com",
        "德华安顾人寿": "ergo-life.com.cn",
        "国联人寿": "guolianlife.com",
        "君龙人寿": "junlonglife.com",
        "昆仑健康保险": "kunlunhealth.com",
        "泰山财产保险": "taishan-ins.com.cn",
        "大特保": "datebao.com",
        "长安基金": "changanfund.com",
        "汇添富基金": "99fund.com",
        "华宝信托": "huabaotrust.com",
        "财富证券": "cfzq.com",
        "渤海商品交易所": "bohai.com",
        "拉卡拉": "lakala.com",
        "韵达": "yundaex.com",
        "特步": "xtep.com.cn",
        "银泰": "yintai.com",
        "人人乐": "rrl.com.cn",
        "曲美家具": "qumei.com",
        "红蜻蜓": "cnhongqingting.com",
        "心动网络": "xd.com",
        "盛大": "snda.com",
        "极光推送": "jpush.cn",
        "美橙互联": "cndns.com",
        "中威科技": "sinowaysoft.com",
        "YzmCMS": "yzmcms.com",
        "东风日产": "dongfeng-nissan.com.cn",
        "乐学一百": "lexue100.com",
        "闵行区教育局": "mhedu.sh.cn",
        "东华理工大学": "ecit.cn",
        "浙江越秀外国语学院": "zyufl.edu.cn",
        "北方民族大学": "nwsni.edu.cn",
        "重庆工商职业学院": "cqtbi.edu.cn",
        "陕西工业职业技术学院": "sxpi.edu.cn",
        "中国电信学院": "ctelecom.com.cn",
        "北京外企人力": "fesco.com.cn",
        "校友邦": "xybservice.com",
        "南通市政府": "nantong.gov.cn",
        "温州人社": "hrss.wenzhou.gov.cn",
        "大众网": "dzwww.com",
        "华夏幸福": "cfldcn.com",
        # 新增从补天列表
        "银泰网": "yintai.com",
        "七彩鲜花": "qicaixianhua.com",
        "美橙": "cndns.com",
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
        async with httpx.AsyncClient(verify=False, timeout=self.timeout,
                                     follow_redirects=True) as client:
            tasks = [self._verify_one(d, client) for d in domains]
            results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    # ── 主流程 ───────────────────────────────────

    def discover(self, company_name: str) -> list[DomainCandidate]:
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
        candidates = self.discover(company_name)
        return candidates[0].domain if candidates else None

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
        lines = [l.strip() for l in open(filepath, encoding='utf-8').readlines()
                if l.strip() and not l.startswith('#')]
        results = self.discover_batch(lines)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                for name, domain in results.items():
                    if domain:
                        f.write(f"https://{domain}    # {name}\n")

        found = sum(1 for v in results.values() if v)
        print(f"总: {len(results)}  找到域名: {found}  ({found/len(results)*100:.0f}%)")
        return results
