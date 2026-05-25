"""域名自动发现 — 公司名 → 官网域名

用于补天厂商列表批量解析
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx


@dataclass
class DomainCandidate:
    """域名候选"""
    domain: str
    source: str = ""          # pattern/search/icp
    verified: bool = False
    status_code: int = 0
    title: str = ""
    confidence: float = 0.0   # 0-1


class DomainDiscovery:
    """域名发现器"""

    def __init__(self, timeout: float = 5.0, enable_search: bool = True):
        self.timeout = timeout
        self.enable_search = enable_search
        self.session = httpx.Client(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        )

    # ── 中方域名模式 ─────────────────────────────

    # 常见的中国公司域名后缀
    CN_TLDS = [".com.cn", ".cn", ".com", ".net", ".org.cn"]

    # 品牌名 → 域名映射（手动积累的常见映射，加速匹配）
    KNOWN_BRANDS = {
        # 银行
        "中国人寿": "chinalife.com.cn",
        "哈尔滨银行": "hrbccb.com.cn",
        "南京银行": "njcb.com.cn",
        "桂林银行": "guilinbank.com.cn",
        # 保险
        "华泰人寿": "htlife.com.cn",
        "北大方正人寿": "pkufi.com",
        "德华安顾人寿": "ergo-life.com.cn",
        "国联人寿": "guolianlife.com",
        "君龙人寿": "junlonglife.com",
        "昆仑健康保险": "kunlunhealth.com",
        "泰山财产保险": "taishan-ins.com.cn",
        "大特保": "datebao.com",
        # 基金/金融
        "长安基金": "changanfund.com",
        "汇添富基金": "99fund.com",
        "华宝信托": "huabaotrust.com",
        "财富证券": "cfzq.com",
        "渤海商品交易所": "bohai.com",
        # 电商/零售
        "拉卡拉": "lakala.com",
        "韵达": "yundaex.com",
        "特步": "xtep.com.cn",
        "银泰": "yintai.com",
        "人人乐": "rrl.com.cn",
        "曲美家具": "qumei.com",
        "红蜻蜓": "cnhongqingting.com",
        # IT/科技
        "心动网络": "xd.com",
        "盛大": "snda.com",
        "极光推送": "jpush.cn",
        "美橙互联": "cndns.com",
        "中威科技": "sinowaysoft.com",
        "YzmCMS": "yzmcms.com",
        # 汽车
        "东风日产": "dongfeng-nissan.com.cn",
        # 教育
        "乐学一百": "lexue100.com",
        "闵行区教育局": "mhedu.sh.cn",
        "东华理工大学": "ecit.cn",
        "浙江越秀外国语学院": "zyufl.edu.cn",
        "北方民族大学": "nwsni.edu.cn",
        "重庆工商职业学院": "cqtbi.edu.cn",
        "陕西工业职业技术学院": "sxpi.edu.cn",
        "中国电信学院": "ctelecom.com.cn",
        # 人力
        "北京外企人力": "fesco.com.cn",
        "校友邦": "xybservice.com",
        # 政府
        "南通市政府": "nantong.gov.cn",
        "温州人社": "hrss.wenzhou.gov.cn",
        # 媒体
        "大众网": "dzwww.com",
        "ChinaJoy": "chinajoy.net",
        # 地产
        "华夏幸福": "cfldcn.com",
    }

    def _guess_by_pattern(self, name: str) -> list[str]:
        """基于常见模式猜测域名"""
        candidates = []

        # 1. 先查已知品牌表
        for brand, domain in self.KNOWN_BRANDS.items():
            if brand in name or name in brand:
                candidates.append(domain)

        # 2. 提取可能的英文/拼音部分
        # 移除常见后缀词
        clean = name
        for suffix in ["股份有限公司", "有限公司", "集团", "公司", "（中国）", "(中国)"]:
            clean = clean.replace(suffix, "")

        clean = clean.strip()

        # 3. 如果包含纯英文单词，直接拼接
        eng_words = re.findall(r"[a-zA-Z0-9-]{3,}", name)
        for word in eng_words:
            for tld in [".com", ".com.cn", ".cn"]:
                candidates.append(f"{word}{tld}")

        return list(dict.fromkeys(candidates))  # 去重保序

    # ── 搜索引擎发现 ─────────────────────────────

    def _search_baidu(self, name: str) -> list[str]:
        """通过百度搜索找官网"""
        results = []
        try:
            query = f"{name} 官网"
            url = f"https://www.baidu.com/s?wd={query}"
            resp = self.session.get(url)
            # 从百度搜索结果提取域名
            # 百度结果中的 cite 标签包含域名
            pattern = re.compile(r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}")
            matches = pattern.findall(resp.text)
            # 提取完整域名
            for m in matches:
                domain = m.rstrip("/")
                if not any(skip in domain for skip in ["baidu.com", "zhidao.baidu", "baike.baidu"]):
                    results.append(domain)
        except Exception:
            pass
        return list(dict.fromkeys(results))

    def _search_bing(self, name: str) -> list[str]:
        """通过Bing搜索找官网"""
        results = []
        try:
            query = f"{name} 官方网站"
            url = f"https://www.bing.com/search?q={query}"
            resp = self.session.get(url)
            pattern = re.compile(r'<cite[^>]*>([^<]+)</cite>')
            matches = pattern.findall(resp.text)
            for m in matches:
                domain = m.strip().lower()
                if not any(skip in domain for skip in ["bing.com", "microsoft.com"]):
                    results.append(domain)
        except Exception:
            pass
        return list(dict.fromkeys(results))

    # ── 验证 ─────────────────────────────────────

    def _verify_domain(self, domain: str) -> Optional[DomainCandidate]:
        """验证域名是否可访问并获取标题"""
        try:
            resp = self.session.get(f"https://{domain}")
            title = ""
            m = re.search(r"<title[^>]*>(.+?)</title>", resp.text, re.IGNORECASE)
            if m:
                title = m.group(1).strip()

            return DomainCandidate(
                domain=domain,
                source="verified",
                verified=True,
                status_code=resp.status_code,
                title=title,
                confidence=0.9 if resp.status_code == 200 else 0.5,
            )
        except Exception:
            return None

    # ── 主流程 ───────────────────────────────────

    def discover(self, company_name: str) -> list[DomainCandidate]:
        """
        根据公司名发现域名
        返回按置信度排序的候选列表
        """
        candidates: list[DomainCandidate] = []

        # Step 1: 已知品牌表
        for brand, domain in self.KNOWN_BRANDS.items():
            if brand in company_name or company_name in brand:
                candidates.append(DomainCandidate(
                    domain=domain, source="known_brand", confidence=0.95
                ))
                break

        # Step 2: 模式猜测
        guessed = self._guess_by_pattern(company_name)
        for g in guessed:
            if g not in [c.domain for c in candidates]:
                candidates.append(DomainCandidate(
                    domain=g, source="pattern", confidence=0.3
                ))

        # Step 3: 搜索引擎（仅在需要时且开启）
        if self.enable_search and len(candidates) < 2:
            try:
                search_results = self._search_baidu(company_name)
                if not search_results:
                    search_results = self._search_bing(company_name)
                for sr in search_results[:5]:
                    if sr not in [c.domain for c in candidates]:
                        candidates.append(DomainCandidate(
                            domain=sr, source="search", confidence=0.5
                        ))
            except Exception:
                pass  # 搜索不可用时静默跳过

        # Step 4: 验证候选域名（高置信度来源即使验证失败也保留）
        verified = []
        for c in candidates:
            if c.confidence >= 0.9:  # known_brand 等可信来源，直接通过
                c.verified = True
                verified.append(c)
                continue

            v = self._verify_domain(c.domain)
            if v:
                v.source = c.source
                v.confidence = max(v.confidence * 0.5 + 0.4, c.confidence)
                verified.append(v)
            elif c.confidence >= 0.5:  # search 结果验证失败也保留
                verified.append(c)

        # 按置信度排序
        verified.sort(key=lambda x: -x.confidence)
        return verified

    def discover_best(self, company_name: str) -> Optional[str]:
        """只返回最佳域名"""
        results = self.discover(company_name)
        return results[0].domain if results else None

    def discover_batch(self, company_names: list[str]) -> dict[str, Optional[str]]:
        """批量发现"""
        results = {}
        for name in company_names:
            results[name] = self.discover_best(name)
        return results

    def close(self):
        self.session.close()


# ── 命令行入口 ──────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python discovery.py <公司名>")
        print("      python discovery.py --file <公司名单文件>")
        sys.exit(1)

    dd = DomainDiscovery()

    if sys.argv[1] == "--file" and len(sys.argv) > 2:
        with open(sys.argv[2], "r", encoding="utf-8") as f:
            names = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        print(f"发现 {len(names)} 家公司的域名...\n")
        for i, name in enumerate(names):
            best = dd.discover_best(name)
            status = best or "未找到"
            print(f"  [{i+1}/{len(names)}] {name} → {status}")
    else:
        name = sys.argv[1]
        candidates = dd.discover(name)
        print(f"\n{name} 的域名候选:")
        for c in candidates:
            icon = "✓" if c.verified else "?"
            print(f"  {icon} {c.domain} [{c.source}] ({c.status_code}) {c.title[:40]}")

    dd.close()
