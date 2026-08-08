"""惊蛰 — 漏洞自动验证器

从破晓扫描结果中提取可疑发现，自动验证是否可实际利用。

验证模块:
  1. DefaultCreds  — 常见默认口令测试
  2. DirListing    — 目录遍历检测
  3. SwaggerSpec   — API 文档提取
  4. GitAccess     — Git 仓库可访问性
  5. ConfigLeak    — 配置文件内容检测
  6. ActuatorCheck — Spring Boot Actuator 端点检测
"""

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx


@dataclass
class VerifiedFinding:
    """已验证的发现"""
    url: str
    finding_type: str         # admin / api / git / config / debug / backup
    exploitable: bool = False
    confidence: str = "LOW"   # HIGH / MEDIUM / LOW
    evidence: str = ""
    detail: str = ""


# ── 默认口令字典 ─────────────────────────────────

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "admin888"),
    ("admin", "12345678"),
    ("admin", "1234"),
    ("tomcat", "tomcat"),
    ("tomcat", "s3cret"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("test", "test"),
    ("guest", "guest"),
    ("admin", ""),
    ("sa", "sa"),
    ("manager", "manager"),
    ("deployer", "deployer"),
    ("user", "user"),
    ("operator", "operator"),
    ("system", "system"),
    ("superadmin", "superadmin"),
    ("webadmin", "webadmin"),
    ("administrator", "administrator"),
    ("demo", "demo"),
    ("monitor", "monitor"),
    ("backup", "backup"),
    ("postgres", "postgres"),
    ("oracle", "oracle"),
]


class JingZhe:
    """惊蛰 — 漏洞自动验证器"""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    # ═══════════════════════════════════════════════
    # 模块 1: 默认口令
    # ═══════════════════════════════════════════════

    async def _check_default_creds(
        self, url: str, client: httpx.AsyncClient
    ) -> list[VerifiedFinding]:
        """尝试常见默认口令"""
        results = []

        # 常见的登录请求参数名
        param_sets = [
            {"username": "{u}", "password": "{p}"},
            {"user": "{u}", "pass": "{p}"},
            {"name": "{u}", "pwd": "{p}"},
            {"loginName": "{u}", "loginPwd": "{p}"},
            {"account": "{u}", "password": "{p}"},
        ]

        for username, password in DEFAULT_CREDS[:15]:
            for params in param_sets[:3]:
                data = {k: v.format(u=username, p=password) for k, v in params.items()}
                try:
                    resp = await client.post(url, data=data, timeout=self.timeout)

                    # 判断是否登录成功
                    # 失败特征: 包含 "密码错误" / "用户名不存在" / "invalid" / "error"
                    fail_keywords = ["密码错误", "用户名", "不存在", "验证码",
                                     "captcha", "invalid", "incorrect", "错误"]
                    text_lower = resp.text.lower()
                    is_fail = any(kw in text_lower for kw in fail_keywords)

                    if not is_fail and resp.status_code in (200, 302):
                        # 可能成功 — 检查是否有登录成功特征
                        success_keywords = ["welcome", "dashboard", "后台", "管理",
                                            "logout", "退出", "欢迎"]
                        is_success = any(kw in text_lower for kw in success_keywords)

                        if is_success and not is_fail:
                            results.append(VerifiedFinding(
                                url=url,
                                finding_type="admin",
                                exploitable=True,
                                confidence="HIGH",
                                evidence=f"默认口令: {username}/{password}",
                                detail=f"POST {url} → 可能登录成功",
                            ))
                            return results  # 找到一个就够

                except Exception:
                    continue

        return results

    # ═══════════════════════════════════════════════
    # 模块 2: 目录遍历
    # ═══════════════════════════════════════════════

    async def _check_dir_listing(
        self, url: str, client: httpx.AsyncClient
    ) -> Optional[VerifiedFinding]:
        """检测是否开启目录列表"""
        try:
            resp = await client.get(url, timeout=self.timeout)
            text = resp.text[:500].lower()

            listing_indicators = [
                "index of /",
                "parent directory",
                "directory listing",
                "<title>index of",
                "last modified</a>",
            ]
            if any(ind in text for ind in listing_indicators):
                return VerifiedFinding(
                    url=url,
                    finding_type="dir_listing",
                    exploitable=True,
                    confidence="HIGH",
                    evidence="服务器开启了目录列表功能",
                    detail=f"访问 {url} 返回目录索引页面",
                )
        except Exception:
            pass
        return None

    # ═══════════════════════════════════════════════
    # 模块 3: API 文档提取
    # ═══════════════════════════════════════════════

    async def _check_swagger(
        self, base_url: str, client: httpx.AsyncClient
    ) -> Optional[VerifiedFinding]:
        """尝试提取 Swagger/OpenAPI 规范"""
        spec_paths = [
            "/v2/api-docs", "/v3/api-docs", "/swagger.json",
            "/api/swagger.json", "/api-docs", "/swagger-resources",
        ]

        for path in spec_paths:
            try:
                full = f"{base_url.rstrip('/')}{path}"
                resp = await client.get(full, timeout=self.timeout)

                if resp.status_code == 200:
                    text = resp.text.strip()
                    # 检查是否是有效 JSON 且包含 API 定义
                    if text.startswith("{") and ("paths" in text or "swagger" in text):
                        try:
                            spec = json.loads(text)
                            paths_count = len(spec.get("paths", {}))
                            if paths_count > 0:
                                return VerifiedFinding(
                                    url=full,
                                    finding_type="api",
                                    exploitable=True,
                                    confidence="HIGH",
                                    evidence=f"Swagger 规范泄露: {paths_count} 个 API 端点",
                                    detail=f"API 规范可从 {full} 直接访问",
                                )
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue
        return None

    # ═══════════════════════════════════════════════
    # 模块 4: Git 泄露
    # ═══════════════════════════════════════════════

    async def _check_git(
        self, base_url: str, client: httpx.AsyncClient
    ) -> Optional[VerifiedFinding]:
        """检测 Git 仓库是否可访问"""
        git_files = ["/.git/HEAD", "/.git/config", "/.git/index",
                     "/.git/refs/heads/master", "/.git/refs/heads/main"]

        accessible = []
        for path in git_files:
            try:
                resp = await client.get(
                    f"{base_url.rstrip('/')}{path}", timeout=self.timeout
                )
                if resp.status_code != 200:
                    continue
                content = resp.content
                if len(content) < 20:
                    continue
                # 排除 HTML/JS 假阳性（CDN、反爬、验证码页面）
                preview = content[:200].decode('utf-8', errors='ignore').lower()
                if any(preview.startswith(t) for t in
                       ("<!doctype", "<html", "<script", "<?xml")):
                    continue
                if "x5secdata" in preview or "tmd" in preview:
                    continue
                accessible.append(path)
            except Exception:
                pass

        if accessible:
            return VerifiedFinding(
                url=base_url,
                finding_type="git",
                exploitable=True,
                confidence="HIGH" if len(accessible) >= 2 else "MEDIUM",
                evidence=f"Git 文件可访问: {', '.join(accessible)}",
                detail="Git 仓库泄露，可通过 git-dumper 等工具提取完整源码",
            )
        return None

    # ═══════════════════════════════════════════════
    # 模块 5: 配置文件泄露
    # ═══════════════════════════════════════════════

    async def _check_config(
        self, url: str, client: httpx.AsyncClient
    ) -> Optional[VerifiedFinding]:
        """检测配置文件是否泄露真实内容"""
        # 检查是否返回了真实的配置内容而非空页面/HTML
        try:
            resp = await client.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return None

            text = resp.text.strip()
            size = len(resp.content)

            # 排除 HTML 响应
            if text.lower().startswith("<!doctype") or text.lower().startswith("<html"):
                return None

            # 配置文件特征
            config_indicators = [
                "<?php", "<?=", "define(", "$_", "DB_",
                "database", "localhost", "password", "username",
                "jdbc:", "mysql://", "connectionString",
                "DB_CONNECTION", "APP_KEY", "APP_SECRET",
                "access_key", "secret_key", "api_key",
            ]
            matches = [i for i in config_indicators if i.lower() in text.lower()]
            if matches and size > 50:
                return VerifiedFinding(
                    url=url,
                    finding_type="config",
                    exploitable=True,
                    confidence="HIGH",
                    evidence=f"包含敏感配置关键词: {matches[:5]}",
                    detail=f"配置文件 {url} 返回了真实的配置内容 ({size}B)",
                )
        except Exception:
            pass
        return None

    # ═══════════════════════════════════════════════
    # 模块 6: Actuator
    # ═══════════════════════════════════════════════

    async def _check_actuator(
        self, base_url: str, client: httpx.AsyncClient
    ) -> Optional[VerifiedFinding]:
        """检测 Spring Boot Actuator 端点"""
        endpoints = ["/actuator", "/actuator/health", "/actuator/env",
                     "/actuator/info", "/actuator/mappings", "/actuator/heapdump"]

        accessible = []
        for ep in endpoints:
            try:
                resp = await client.get(
                    f"{base_url.rstrip('/')}{ep}", timeout=self.timeout
                )
                if resp.status_code not in (200, 401, 403):
                    continue
                # 200 时排除 HTML/CDN/反爬 假阳性
                if resp.status_code == 200:
                    preview = resp.text[:200].lower()
                    if any(preview.startswith(t) for t in
                           ("<!doctype", "<html", "<script", "<?xml")):
                        continue
                    if "x5secdata" in preview or "tmd" in preview:
                        continue
                    if len(resp.content) < 20:
                        continue
                accessible.append(f"{ep} [{resp.status_code}]")
            except Exception:
                pass

        if len(accessible) >= 1:
            return VerifiedFinding(
                url=base_url,
                finding_type="actuator",
                exploitable=True if any("[200]" in a for a in accessible) else False,
                confidence="MEDIUM" if any("[200]" in a for a in accessible) else "LOW",
                evidence=f"Actuator 端点存在: {', '.join(accessible)}",
                detail="Spring Boot Actuator 端点暴露，可能泄露运行环境信息",
            )
        return None

    # ═══════════════════════════════════════════════
    # 模块 7: API 端点探测
    # ═══════════════════════════════════════════════

    async def _check_api_endpoints(
        self, base_url: str, client: httpx.AsyncClient
    ) -> list[VerifiedFinding]:
        """探测常见 API 端点"""
        findings = []
        api_paths = [
            ("/api/user", "用户接口"),
            ("/api/login", "登录接口"),
            ("/api/v1/users", "用户列表"),
            ("/api/admin", "管理接口"),
            ("/graphql", "GraphQL"),
            ("/api/graphql", "GraphQL"),
        ]
        for path, desc in api_paths:
            try:
                resp = await client.get(
                    f"{base_url.rstrip('/')}{path}", timeout=self.timeout
                )
                if resp.status_code == 200 and len(resp.content) > 80:
                    preview = resp.text[:200].lower()
                    # 排除 HTML/JS/CDN 假阳性
                    if any(preview.startswith(t) for t in
                           ("<!doctype", "<html", "<script", "<?xml")):
                        continue
                    if "x5secdata" in preview or "tmd" in preview:
                        continue
                    # 排除 "模块不存在" 等通用错误
                    if "没有找到" in resp.text or "not found" in preview \
                       or "not exist" in preview:
                        continue
                    findings.append(VerifiedFinding(
                        url=f"{base_url.rstrip('/')}{path}",
                        finding_type="api",
                        exploitable=True,
                        confidence="MEDIUM",
                        evidence=f"API 端点可访问: {desc}",
                        detail=f"返回 {len(resp.content)}B 数据",
                    ))
            except Exception:
                pass
        return findings

    # ═══════════════════════════════════════════════
    # 模块 8: phpinfo 解析
    # ═══════════════════════════════════════════════

    def _parse_phpinfo(self, html: str) -> dict:
        """从 phpinfo 输出中提取关键信息"""
        info = {}
        patterns = {
            "php_version": r"PHP Version</td[^>]*><td[^>]*>([^<]+)",
            "server_api": r"Server API</td[^>]*><td[^>]*>([^<]+)",
            "doc_root": r"DOCUMENT_ROOT</td[^>]*><td[^>]*>([^<]+)",
            "extensions": r"<h2[^>]*>\s*(\w+)\s*</h2>",
        }
        for key, pat in patterns.items():
            m = re.findall(pat, html)
            if m:
                info[key] = m[0] if key != "extensions" else m[:10]
        return info

    # ═══════════════════════════════════════════════
    # 模块 9: 服务端信息提取
    # ═══════════════════════════════════════════════

    async def _check_server_info(
        self, base_url: str, client: httpx.AsyncClient
    ) -> Optional[VerifiedFinding]:
        """从响应头提取服务端信息"""
        try:
            resp = await client.get(base_url, timeout=self.timeout)
            info_bits = []
            for header in ["server", "x-powered-by", "x-aspnet-version",
                          "x-generator", "x-drupal-cache"]:
                val = resp.headers.get(header, "")
                if val:
                    info_bits.append(f"{header}: {val}")

            if len(info_bits) >= 2:  # 至少2个才算有意义的泄露
                return VerifiedFinding(
                    url=base_url,
                    finding_type="info_leak",
                    exploitable=False,
                    confidence="LOW",
                    evidence="服务端信息泄露",
                    detail=" | ".join(info_bits[:5]),
                )
        except Exception:
            pass
        return None

    # ═══════════════════════════════════════════════
    # 模块 7: .DS_Store 解析
    # ═══════════════════════════════════════════════

    def _parse_ds_store(self, content: bytes) -> list[str]:
        """解析 .DS_Store 文件提取文件名（UTF-16BE）"""
        names = set()
        i = 0
        while i < len(content) - 4:
            if content[i] == 0 and 0x20 <= content[i+1] <= 0x7e:
                chars = []
                j = i
                while j < len(content) - 1 and content[j] == 0 and 0x20 <= content[j+1] <= 0x7e:
                    chars.append(chr(content[j+1]))
                    j += 2
                s = ''.join(chars)
                if len(s) >= 3 and ('.' in s or '/' in s):
                    names.add(s)
                i = j
            else:
                i += 1
        return sorted(names)

    # ═══════════════════════════════════════════════
    # 主流程
    # ═══════════════════════════════════════════════

    async def _scan_single_path(
        self, base: str, path: str, client: httpx.AsyncClient, is_catchall
    ) -> list[VerifiedFinding]:
        """扫描单个路径并返回发现列表"""
        findings: list[VerifiedFinding] = []
        full_url = f"{base}{path}"
        try:
            resp = await client.get(full_url, timeout=self.timeout)
            if resp.status_code != 200:
                return findings
            if is_catchall(resp):
                return findings
            content = resp.content
            size = len(content)
            text = content.decode('utf-8', errors='ignore')

            # ── .DS_Store ──
            if path == "/.DS_Store" and size > 100:
                if content[:4] == b'\x00\x00\x00\x01':
                    names = self._parse_ds_store(content)
                    if names:
                        findings.append(VerifiedFinding(
                            url=full_url, finding_type="source",
                            exploitable=True, confidence="HIGH",
                            evidence=f".DS_Store 泄露 {len(names)} 个文件",
                            detail=f"包含: {', '.join(names[:8])}",
                        ))
                        return findings

            # ── .gitignore ──
            if path == "/.gitignore" and size > 50:
                tlow = text.lower()
                if any(tlow.startswith(t) for t in
                       ("<!doctype", "<html", "<script")):
                    return findings
                if "x5secdata" in tlow:
                    return findings
                lines = [ln.strip() for ln in text.splitlines()
                         if ln.strip() and not ln.startswith('#')]
                if lines:
                    findings.append(VerifiedFinding(
                        url=full_url, finding_type="git",
                        exploitable=True, confidence="MEDIUM",
                        evidence=f".gitignore 泄露 {len(lines)} 条规则",
                        detail=f"包含: {', '.join(lines[:5])}",
                    ))
                    return findings

            # ── 配置/敏感文件 ──
            if path in ("/config.php", "/.env", "/web.config"):
                if not text.lower().startswith("<!doctype") \
                   and not text.lower().startswith("<html") and size > 100:
                    config_kw = ["<?php", "DB_", "database", "password",
                                 "APP_KEY", "jdbc:", "<?xml", "<configuration"]
                    matches = [k for k in config_kw if k.lower() in text.lower()]
                    if matches:
                        findings.append(VerifiedFinding(
                            url=full_url, finding_type="config",
                            exploitable=True, confidence="HIGH",
                            evidence=f"配置文件泄露 ({size}B)",
                            detail=f"包含关键词: {matches[:3]}",
                        ))
                        return findings

            # ── 备份文件 ──
            if path in ("/backup.zip", "/wwwroot.zip") and size > 100:
                if content[:4] == b'PK\x03\x04':
                    findings.append(VerifiedFinding(
                        url=full_url, finding_type="backup",
                        exploitable=True, confidence="HIGH",
                        evidence=f"备份文件可下载 ({size}B)",
                        detail=f"{full_url} 为有效 ZIP 文件",
                    ))
                    return findings

            # ── 管理后台 ──
            if path in ("/admin/login", "/admin", "/login"):
                if any(kw in text.lower() for kw in
                       ["<form", "password", "登录", "login"]):
                    cred_results = await self._check_default_creds(full_url, client)
                    if cred_results:
                        findings.extend(cred_results)
                    else:
                        findings.append(VerifiedFinding(
                            url=full_url, finding_type="admin",
                            exploitable=False, confidence="LOW",
                            evidence="存在登录表单（默认口令测试未通过）",
                            detail=f"登录页面可访问 ({size}B)",
                        ))
                    return findings

            # ── phpinfo ──
            if path in ("/phpinfo.php", "/info.php"):
                info = self._parse_phpinfo(text)
                if info:
                    findings.append(VerifiedFinding(
                        url=full_url, finding_type="debug",
                        exploitable=True, confidence="HIGH",
                        evidence=f"phpinfo 泄露: PHP {info.get('php_version','?')}",
                        detail=f"Server API: {info.get('server_api','?')} | "
                               f"DocRoot: {info.get('doc_root','?')}",
                    ))
                    return findings

        except Exception:
            pass
        return findings

    async def verify(self, target_url: str) -> list[VerifiedFinding]:
        """对单个目标执行所有验证"""
        findings = []
        base = target_url.rstrip('/')

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # ── 校准: 探测随机路径检测 CDN catch-all ──
            catchall_preview = ""
            try:
                probe = await client.get(
                    f"{base}/_jingzhe_probe_8472_", timeout=self.timeout
                )
                if probe.status_code == 200:
                    catchall_preview = probe.text[:200].lower()
            except Exception:
                pass

            # ── 辅助函数: 判断是否 catch-all ──
            def _is_catchall(resp) -> bool:
                if not catchall_preview or resp.status_code != 200:
                    return False
                preview = resp.text[:200].lower()
                if "<html" in preview and catchall_preview.startswith("<!doctype"):
                    return True
                if preview == catchall_preview:
                    return True
                return False

            # ── 专项检测（异步）──
            tasks = [
                self._check_git(base, client),
                self._check_swagger(base, client),
                self._check_actuator(base, client),
                self._check_server_info(base, client),
                self._check_dir_listing(base, client),
                self._check_config(f"{base}/config.php", client),
                self._check_config(f"{base}/.env", client),
            ]
            # API 端点探测
            api_findings = await self._check_api_endpoints(base, client)
            findings.extend(api_findings)
            for r in await asyncio.gather(*tasks):
                if r:
                    findings.append(r)

            # ── 路径扫描式检测 (并行) ──
            check_paths = [
                "/.DS_Store", "/.gitignore",
                "/admin/login", "/admin", "/login",
                "/config.php", "/.env", "/web.config",
                "/backup.zip", "/wwwroot.zip",
                "/phpinfo.php", "/info.php", "/test.php",
            ]
            semaphore = asyncio.Semaphore(5)

            async def _limited_scan(path: str) -> list[VerifiedFinding]:
                async with semaphore:
                    return await self._scan_single_path(
                        base, path, client, _is_catchall
                    )

            scan_results = await asyncio.gather(
                *[_limited_scan(p) for p in check_paths]
            )
            for result_list in scan_results:
                findings.extend(result_list)

        return findings

    async def verify_from_scan(self, scan_summary_path: str) -> list[VerifiedFinding]:
        """从破晓扫描汇总 JSON 中提取发现并验证"""
        data = json.loads(Path(scan_summary_path).read_text(encoding="utf-8"))
        targets = data.get("targets", data.get("findings", []))

        all_findings = []
        for t in targets:
            target_url = t.get("target_url", "")
            if not target_url:
                continue

            # 验证这个目标
            findings = await self.verify(target_url)
            all_findings.extend(findings)

        return all_findings

    def score(self, findings: list[VerifiedFinding]) -> dict:
        """对验证结果评分"""
        high = sum(1 for f in findings if f.confidence == "HIGH" and f.exploitable)
        med = sum(1 for f in findings if f.confidence == "MEDIUM" and f.exploitable)
        low = sum(1 for f in findings if f.confidence == "LOW")
        total_score = high * 10 + med * 5 + low * 2

        risk = "🟢 安全" if total_score == 0 else \
               "🔵 低风险" if total_score < 10 else \
               "🟡 中风险" if total_score < 25 else "🔴 高风险"

        return {
            "high": high, "medium": med, "low": low,
            "total_score": total_score, "risk": risk,
            "summary": f"{risk} (评分: {total_score})",
        }

    def verify_sync(self, target_url: str) -> list[VerifiedFinding]:
        """同步版"""
        return asyncio.run(self.verify(target_url))
