"""
POC 执行引擎
=============
执行模板扫描，支持:
  - 并发扫描
  - 变量替换
  - 多请求链
  - 结果汇总
"""

import asyncio
import base64
import json
import random
import string
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

import httpx

from .template import (
    Template, HTTPRequest, Matcher, Extractor,
    MatchResult,
)
from .matcher import MatcherEngine
from .extractor import ExtractorEngine
from .loader import TemplateLoader


class POCEngine:
    """POC 模板扫描引擎"""

    def __init__(self, timeout: float = 10.0, concurrency: int = 10,
                 follow_redirects: bool = True, verify_ssl: bool = False,
                 stealth: bool = False, proxy_file: str = "",
                 proxy_list: list = None, qps: float = 10.0,
                 per_domain_qps: float = 3.0):
        self.timeout = timeout
        self.concurrency = concurrency
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.matcher_engine = MatcherEngine()
        self.extractor_engine = ExtractorEngine()
        self.loader = TemplateLoader()
        self.stealth = stealth
        self._stealth_client = None

        if stealth:
            from src.xiazhi.stealth_client import StealthClient
            self._stealth_client = StealthClient(
                proxy_file=proxy_file,
                proxy_list=proxy_list,
                qps=qps,
                per_domain_qps=per_domain_qps,
                timeout=timeout,
                verify_ssl=verify_ssl,
                follow_redirects=follow_redirects,
            )

    async def scan_target(self, target_url: str,
                          templates: List[Template],
                          tags: List[str] = None,
                          severity: List[str] = None,
                          client: httpx.AsyncClient = None) -> List[MatchResult]:
        """
        用所有模板扫描单个目标

        Args:
            target_url: 目标 URL
            templates: 模板列表
            client: 可选的外部 httpx client（复用连接池）

        Returns:
            List[MatchResult] (只返回匹配的结果)
        """
        # 过滤
        if tags:
            templates = [t for t in templates if any(tag in t.info.tags for tag in tags)]
        if severity:
            templates = [t for t in templates if t.info.severity in severity]

        if not templates:
            return []

        sem = asyncio.Semaphore(self.concurrency)
        all_results = []

        async def _collect(client: httpx.AsyncClient):
            async def _run_template(tmpl: Template):
                async with sem:
                    return await self._execute_template(client, target_url, tmpl)

            tasks = [_run_template(tmpl) for tmpl in templates]
            return await asyncio.gather(*tasks, return_exceptions=True)

        if client:
            results = await _collect(client)
        else:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
            ) as new_client:
                results = await _collect(new_client)

        # 收集匹配结果
        for r in results:
            if isinstance(r, list):
                all_results.extend(r)
            elif isinstance(r, MatchResult):
                all_results.append(r)

        return all_results

    async def scan_targets(self, targets: List[str],
                           templates: List[Template],
                           concurrency: int = 5,
                           tags: List[str] = None,
                           severity: List[str] = None) -> Dict[str, List[MatchResult]]:
        """扫描多个目标"""
        sem = asyncio.Semaphore(concurrency)
        all_results = {}

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=self.follow_redirects,
        ) as client:
            async def _scan_one(target: str):
                async with sem:
                    return target, await self.scan_target(target, templates, tags, severity, client=client)

            tasks = [_scan_one(t) for t in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, tuple):
                target, matches = r
                if matches:
                    all_results[target] = matches

        return all_results

    async def _execute_template(self, client: httpx.AsyncClient,
                                target_url: str,
                                tmpl: Template) -> List[MatchResult]:
        """执行单个模板"""
        results = []

        # 全局变量
        variables = {
            "BaseURL": target_url.rstrip("/"),
            "Hostname": target_url.split("//")[-1].split("/")[0].split(":")[0],
            "Scheme": target_url.split("://")[0],
            "Port": self._extract_port(target_url),
            **tmpl.variables,
        }

        # 判断模板中是否有任何请求需要 cookie_reuse
        need_cookie_reuse = any(req.cookie_reuse for req in tmpl.requests)

        # 如果需要 cookie_reuse，使用独立的带 cookie jar 的客户端
        if need_cookie_reuse and not self._stealth_client:
            cookie_client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                max_redirects=max(r.max_redirects for r in tmpl.requests),
                cookies=httpx.Cookies(),
            )
            active_client = cookie_client
        else:
            active_client = client

        try:
            template_matched = False  # 跟踪模板是否已匹配（用于跨请求 stop_at_first_match）

            for req in tmpl.requests:
                if template_matched:
                    break

                # 展开多路径：每个 path 生成独立请求
                urls = req.path if req.path else [f"{target_url.rstrip('/')}"]
                for raw_url in urls:
                    try:
                        result = await self._execute_request(
                            active_client, target_url, tmpl, req, variables, raw_url
                        )
                        if result and result.matched:
                            results.append(result)

                            # 将提取的值注入变量，供后续请求使用 {{name}} 语法
                            if result.extracted:
                                variables.update(result.extracted)

                            if req.stop_at_first_match:
                                template_matched = True
                                break
                    except Exception as e:
                        # 单个请求失败不影响其他请求
                        err_result = MatchResult(
                            template_id=tmpl.id,
                            template_name=tmpl.info.name,
                            severity=tmpl.info.severity,
                            url=target_url,
                            matched=False,
                            error=str(e)[:100],
                            tags=tmpl.info.tags,
                            description=tmpl.info.description,
                        )
                        results.append(err_result)
        finally:
            # 关闭我们自己创建的 cookie 客户端
            if need_cookie_reuse and not self._stealth_client:
                await cookie_client.aclose()

        return results

    async def _execute_request(self, client: httpx.AsyncClient,
                               target_url: str,
                               tmpl: Template,
                               req: HTTPRequest,
                               variables: Dict[str, str],
                               raw_url: str = "") -> Optional[MatchResult]:
        """执行单个 HTTP 请求"""
        # 构建请求 URL
        url = self._expand_variables(raw_url, variables) if raw_url else target_url.rstrip("/")

        # 如果路径不是完整 URL，拼接到 base URL
        if not url.startswith("http"):
            url = f"{target_url.rstrip('/')}/{url.lstrip('/')}"

        # 构建 Headers
        headers = {}
        for k, v in req.headers.items():
            headers[self._expand_variables(k, variables)] = self._expand_variables(str(v), variables)

        # 构建 Body
        body = self._expand_variables(req.body, variables) if req.body else None

        if req.content_type:
            headers["Content-Type"] = req.content_type

        t0 = time.perf_counter()

        try:
            # 发送请求 (使用隐匿客户端或普通客户端)
            if self._stealth_client:
                resp = await self._stealth_client.request(
                    req.method, url, headers=headers,
                    content=body, timeout=req.timeout,
                )
            else:
                # 使用模板定义的 follow_redirects / max_redirects
                resp = await client.request(
                    req.method, url, headers=headers,
                    content=body, timeout=req.timeout,
                    follow_redirects=req.follow_redirects,
                )
        except httpx.TimeoutException:
            return None
        except Exception as e:
            return None

        elapsed = time.perf_counter() - t0

        # 响应数据
        status_code = resp.status_code
        resp_headers = dict(resp.headers)
        resp_body = resp.text
        resp_body_bytes = resp.content

        # 执行匹配
        matched, match_desc = self.matcher_engine.match_all(
            req.matchers, req.matchers_condition,
            status_code, resp_headers, resp_body, resp_body_bytes
        )

        if not matched:
            return None

        # 执行提取
        extracted = {}
        if req.extractors:
            extracted = self.extractor_engine.extract(
                req.extractors, status_code, resp_headers, resp_body
            )

        # 构建结果
        result = MatchResult(
            template_id=tmpl.id,
            template_name=tmpl.info.name,
            severity=tmpl.info.severity,
            url=target_url,
            matched=True,
            matcher_name=match_desc,
            extracted=extracted,
            response_status=status_code,
            response_size=len(resp_body_bytes),
            response_time=elapsed,
            request_url=url,
            request_method=req.method,
            tags=tmpl.info.tags,
            description=tmpl.info.description,
        )

        return result

    def _expand_variables(self, text: str, variables: Dict[str, str]) -> str:
        """替换模板变量 {{VariableName}}"""
        if not text or "{{" not in text:
            return text

        for name, value in variables.items():
            text = text.replace(f"{{{{{name}}}}}", str(value))

        # 运行时变量 (randstr, randbase64 等)
        text = self._resolve_runtime_vars(text)

        return text

    def _resolve_runtime_vars(self, text: str) -> str:
        """解析运行时变量"""
        # {{randstr}} — 随机字符串
        if "{{randstr}}" in text:
            rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            text = text.replace("{{randstr}}", rand)

        # {{randbase64}} — 随机 base64
        if "{{randbase64}}" in text:
            rand = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            text = text.replace("{{randbase64}}", base64.b64encode(rand.encode()).decode())

        # {{timestamp}} — 当前时间戳
        if "{{timestamp}}" in text:
            text = text.replace("{{timestamp}}", str(int(time.time())))

        return text

    def _extract_port(self, url: str) -> str:
        """从 URL 中提取端口"""
        try:
            parts = url.split("://")
            if len(parts) > 1:
                host_part = parts[1].split("/")[0]
                if ":" in host_part:
                    return host_part.split(":")[1]
            return "443" if url.startswith("https") else "80"
        except Exception:
            return "80"

    # ── 结果输出 ──────────────────────────────────────

    def print_results(self, results: List[MatchResult], target: str = ""):
        """格式化打印扫描结果"""
        if not results:
            print(f"  ℹ️  未发现漏洞")
            return

        # 按严重级别排序
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda r: sev_order.get(r.severity, 5))

        print(f"\n  🔥 发现 {len(results)} 个漏洞:")
        print(f"  {'─' * 60}")

        for r in results:
            if r.error and not r.matched:
                continue

            icon = r.severity_icon
            print(f"\n  {icon} [{r.severity.upper()}] {r.template_name}")
            print(f"    ID:     {r.template_id}")
            print(f"    URL:    {r.request_url}")
            print(f"    Status: {r.response_status} | Size: {r.response_size} | Time: {r.response_time:.2f}s")
            if r.matcher_name:
                print(f"    Match:  {r.matcher_name[:80]}")
            if r.extracted:
                print(f"    Extract:")
                for k, v in r.extracted.items():
                    print(f"      {k}: {v[:100]}")
            if r.description:
                print(f"    Desc:   {r.description[:80]}")
            if r.tags:
                print(f"    Tags:   {', '.join(r.tags)}")

    def save_results(self, results: List[MatchResult], output_path: str) -> str:
        """保存结果为 JSON"""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(results),
            "by_severity": self._count_by_severity(results),
            "findings": [r.to_dict() for r in results if r.matched],
        }

        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8"
        )
        return str(path)

    def _count_by_severity(self, results: List[MatchResult]) -> Dict[str, int]:
        """按严重级别统计"""
        counts = {}
        for r in results:
            if r.matched:
                counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts
