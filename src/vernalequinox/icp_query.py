"""
ICP 备案查询模块
================
查询域名在中国工信部的备案信息

数据源:
  - ICP 备案查询 API (备案管理系统公开接口)
  - 备案查询网站 (beian.miit.gov.cn)
  - 第三方备案查询 API

注意: ICP 备案仅针对 .cn 和在中国境内运营的网站
"""

import asyncio
import re
from dataclasses import dataclass, field, asdict
from typing import Optional, List


@dataclass
class ICPResult:
    """ICP 备案查询结果"""
    domain: str
    has_record: bool = False            # 是否有备案
    icp_number: str = ""                # 备案号 (如: 京ICP备12345678号)
    company_name: str = ""              # 主办单位名称
    company_type: str = ""              # 主办单位性质 (企业/个人/政府/事业单位)
    website_name: str = ""              # 网站名称
    website_url: str = ""               # 网站首页
    domain_type: str = ""               # 域名类型
    review_date: str = ""               # 审核时间
    province: str = ""                  # 所在省
    status: str = ""                    # 备案状态
    raw_data: dict = field(default_factory=dict)
    source: str = ""
    error: str = ""

    def to_dict(self):
        return asdict(self)

    @property
    def is_enterprise(self):
        return "企业" in self.company_type or "公司" in self.company_name

    @property
    def icp_province_code(self):
        """从备案号提取省份代码"""
        m = re.match(r"(\w+)ICP", self.icp_number)
        return m.group(1) if m else ""


class ICPQuery:
    """ICP 备案查询"""

    # ── 省份代码映射 ──
    PROVINCE_CODES = {
        "京": "北京", "沪": "上海", "津": "天津", "渝": "重庆",
        "冀": "河北", "豫": "河南", "云": "云南", "辽": "辽宁",
        "黑": "黑龙江", "湘": "湖南", "皖": "安徽", "鲁": "山东",
        "新": "新疆", "苏": "江苏", "浙": "浙江", "赣": "江西",
        "鄂": "湖北", "桂": "广西", "甘": "甘肃", "晋": "山西",
        "蒙": "内蒙古", "陕": "陕西", "吉": "吉林", "闽": "福建",
        "贵": "贵州", "粤": "广东", "川": "四川", "藏": "西藏",
        "琼": "海南", "宁": "宁夏", "青": "青海",
    }

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def query(self, domain: str) -> ICPResult:
        """查询域名 ICP 备案信息"""
        result = ICPResult(domain=domain)

        # 清理域名
        clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        # 优先尝试 API 查询
        try:
            result = await self._query_api(clean_domain)
            if result.has_record:
                return result
        except Exception as e:
            result.error = f"API query failed: {e}"

        # Fallback: 解析备案号模式
        try:
            result = await self._query_fallback(clean_domain)
        except Exception as e:
            result.error += f" | fallback failed: {e}"

        return result

    async def _query_api(self, domain: str) -> ICPResult:
        """通过公开 API 查询备案"""
        import httpx

        result = ICPResult(domain=domain, source="icp-api")

        # 尝试多个备案查询 API
        apis = [
            # API 1: icpapi.com
            f"https://icpapi.com/api/icp?domain={domain}",
            # API 2: 备案查询 (备用)
            f"https://api.vvhan.com/api/icp?url={domain}",
        ]

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for api_url in apis:
                try:
                    resp = await client.get(api_url, headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    })
                    if resp.status_code == 200:
                        data = resp.json()
                        parsed = self._parse_api_response(data, domain)
                        if parsed and parsed.has_record:
                            return parsed
                except Exception:
                    continue

        return result

    def _parse_api_response(self, data: dict, domain: str) -> Optional[ICPResult]:
        """解析 API 返回的备案数据"""
        result = ICPResult(domain=domain, raw_data=data, source="icp-api")

        # 不同 API 的字段映射
        # icpapi.com 格式
        if "icp" in data or "domain" in data:
            info = data if "icp" not in data else data["icp"]
            result.icp_number = info.get("icp", info.get("IcpNum", info.get("beian", "")))
            result.company_name = info.get("unitName", info.get("company", info.get("name", "")))
            result.company_type = info.get("unitNature", info.get("type", ""))
            result.website_name = info.get("webName", info.get("siteName", ""))
            result.review_date = info.get("auditDate", info.get("date", ""))
            result.status = info.get("status", info.get("state", ""))

        # vvhan API 格式
        if "info" in data and isinstance(data["info"], dict):
            info = data["info"]
            result.icp_number = info.get("icp", info.get("record", ""))
            result.company_name = info.get("name", info.get("unitName", ""))
            result.website_name = info.get("siteName", "")
            result.status = info.get("status", "")

        # 判断是否有备案
        if result.icp_number and "ICP" in result.icp_number.upper():
            result.has_record = True
            # 解析省份
            m = re.match(r"(\w)ICP", result.icp_number)
            if m:
                result.province = self.PROVINCE_CODES.get(m.group(1), m.group(1))

        return result if result.has_record else None

    async def _query_fallback(self, domain: str) -> ICPResult:
        """Fallback: 通过 WHOIS 判断是否有 ICP 备案线索"""
        result = ICPResult(domain=domain, source="heuristic")

        # .cn 域名必然需要备案
        if domain.endswith(".cn") or domain.endswith(".com.cn") or domain.endswith(".net.cn"):
            result.has_record = True
            result.icp_number = "(需查询具体备案号)"
            result.source = "tld-heuristic"

        return result

    async def batch_query(self, domains: List[str], concurrency: int = 3) -> List[ICPResult]:
        """批量查询备案"""
        sem = asyncio.Semaphore(concurrency)

        async def _query_one(d):
            async with sem:
                return await self.query(d)

        tasks = [_query_one(d) for d in domains]
        return await asyncio.gather(*tasks)

    @staticmethod
    def print_result(r: ICPResult):
        """格式化打印备案结果"""
        if r.error and not r.has_record:
            print(f"  ❌ 备案查询失败: {r.error}")
            return

        if not r.has_record:
            print("  ℹ️  无 ICP 备案 (可能是境外域名)")
            return

        print(f"  📋 ICP 备案信息 ({r.source})")
        print(f"  {'─' * 50}")
        if r.icp_number:
            print(f"  备案号:     {r.icp_number}")
        if r.company_name:
            print(f"  主办单位:   {r.company_name}")
        if r.company_type:
            print(f"  单位性质:   {r.company_type}")
        if r.website_name:
            print(f"  网站名称:   {r.website_name}")
        if r.province:
            print(f"  所在地:     {r.province}")
        if r.review_date:
            print(f"  审核时间:   {r.review_date}")
        if r.status:
            print(f"  状态:       {r.status}")

        # 安全提示: 企业备案意味着国内运营，更容易提交 SRC
        if r.is_enterprise:
            print("  🔥 企业备案 — 国内运营目标，SRC 价值高")
