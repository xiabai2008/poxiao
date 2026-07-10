"""SRC 报告生成 — 补天 / 漏洞盒子 / CNVD 格式

Enhanced: vulnerability-specific reproduction steps, evidence capture,
severity auto-adjustment, per-type fix suggestions, Chinese severity labels.
"""

from pathlib import Path
from typing import Optional


class SRCReporter:
    """SRC 平台报告生成器"""

    # 漏洞等级→中文
    SEVERITY_CN = {
        "critical": "严重",
        "CRITICAL": "严重",
        "high": "高危",
        "HIGH": "高危",
        "medium": "中危",
        "MEDIUM": "中危",
        "low": "低危",
        "LOW": "低危",
        "info": "信息",
        "INFO": "信息",
    }

    # 漏洞类型→中文分类
    VULN_TYPE_MAP = {
        "sqli": "SQL注入",
        "xss": "跨站脚本攻击(XSS)",
        "cmdi": "命令注入",
        "lfi": "文件包含",
        "rce": "远程代码执行",
        "ssrf": "服务端请求伪造(SSRF)",
        "xxe": "XML外部实体注入(XXE)",
        "info_leak": "敏感信息泄露",
        "cors": "跨域配置不当(CORS)",
        "backup": "备份文件泄露",
        "config": "配置文件泄露",
        "git": "Git信息泄露",
        "source": "源代码泄露",
        "debug": "调试信息泄露",
        "admin": "未授权访问",
        "api": "API信息泄露",
        "db": "数据库管理入口暴露",
        "swagger": "Swagger/API文档泄露",
        "actuator": "Spring Boot Actuator泄露",
        "phpinfo": "phpinfo信息泄露",
        "default_cred": "默认凭据",
        "directory_listing": "目录遍历",
        "missing_header": "缺少安全响应头",
    }

    # 平台特定格式配置
    PLATFORM_CONFIG = {
        "butian": {
            "name": "补天",
            "header_style": "#",
            "include_evidence": True,
            "severity_field": "危害等级",
            "url_field": "漏洞URL",
        },
        "vulbox": {
            "name": "漏洞盒子",
            "header_style": "##",
            "include_evidence": True,
            "severity_field": "风险等级",
            "url_field": "漏洞链接",
        },
        "cnvd": {
            "name": "CNVD",
            "header_style": "#",
            "include_evidence": False,
            "severity_field": "危害级别",
            "url_field": "漏洞地址",
        },
    }

    # 各平台专属元数据字段（label, key）—— 增强 P2-5 平台格式
    PLATFORM_META = {
        "butian": [
            ("厂商名称", "vendor"),
            ("漏洞类型", "vuln_type_cn"),
            ("提交类型", "submit_type"),
        ],
        "vulbox": [
            ("漏洞标题", "title"),
            ("利用条件", "condition"),
            ("漏洞危害", "impact"),
        ],
        "cnvd": [
            ("影响产品", "affected_product"),
            ("漏洞类型", "vuln_type_cn"),
            ("危害级别", "severity_cn"),
        ],
    }

    # ── 平台字段查询 ──────────────────────────────

    def platform_fields(self, platform: str) -> list[tuple[str, str]]:
        """返回某平台专属元数据字段列表 [(label, key), ...]

        增强 P2-5：补天/漏洞盒子/CNVD 导出字段差异。
        """
        return list(self.PLATFORM_META.get(platform, []))

    # ── 单漏洞报告 ──────────────────────────────

    def generate_vuln_report(
        self,
        title: str,
        severity: str,
        vuln_url: str,
        vuln_type: str,
        description: str,
        steps: list[str],
        suggestion: str = "",
        platform: str = "butian",
        evidence: str = "",
        finding: dict = None,
        meta: dict = None,
    ) -> str:
        """生成单个漏洞的SRC报告（Markdown格式）

        Args:
            platform: butian / vulbox / cnvd — 影响报告格式
            evidence: HTTP 请求/响应证据文本
            finding: 原始发现数据（用于自动生成证据）
            meta: 平台专属元数据 dict（如 {"vendor": "...", "affected_product": "..."}），
                  渲染 PLATFORM_META 中声明的字段。
        """
        cfg = self.PLATFORM_CONFIG.get(platform, self.PLATFORM_CONFIG["butian"])
        sev_cn = self.SEVERITY_CN.get(severity, severity)
        type_cn = self.VULN_TYPE_MAP.get(vuln_type, vuln_type)

        # 如果没传 evidence 但有 finding 数据，自动生成
        if not evidence and finding and cfg["include_evidence"]:
            evidence = self._generate_evidence(finding)

        h = cfg["header_style"]
        lines = []
        lines.append(f"{h} {title}")
        lines.append("")
        lines.append(f"{h}# 基本信息")
        lines.append("")
        lines.append(f"- **{cfg['severity_field']}**: {sev_cn}")
        lines.append(f"- **{cfg['url_field']}**: {vuln_url}")
        lines.append(f"- **漏洞类型**: {type_cn}")

        # 平台专属元数据字段（P2-5 增强）
        if meta:
            for label, key in self.platform_fields(platform):
                val = meta.get(key, "")
                if val:
                    lines.append(f"- **{label}**: {val}")
        lines.append("")
        lines.append(f"{h}# 漏洞描述")
        lines.append("")
        lines.append(description)
        lines.append("")
        lines.append(f"{h}# 复现步骤")
        lines.append("")
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

        # 证据部分（补天/漏洞盒子要求）
        if evidence and cfg["include_evidence"]:
            lines.append(f"{h}# HTTP 证据")
            lines.append("")
            lines.append("```http")
            lines.append(evidence)
            lines.append("```")
            lines.append("")

        lines.append(f"{h}# 修复建议")
        lines.append("")
        lines.append(suggestion or self._default_suggestion(vuln_type))
        lines.append("")

        return "\n".join(lines)

    # ── 从扫描结果自动生成 ───────────────────────

    def generate_from_sensitive(
        self,
        target_url: str,
        host: str,
        findings: list[dict],
        tech_tags: list[str] = None,
        platform: str = "butian",
    ) -> list[dict]:
        """从敏感路径发现生成报告"""
        reports = []

        for f in findings:
            category = f.get("category", "info_leak")
            path_url = f.get("url", "")
            status = f.get("status", 0)

            vuln_type = category
            title = f"[{host}] {self._finding_title(category, path_url)}"
            severity = self._finding_severity(category, status, f)
            description = self._finding_description(category, path_url, target_url)
            steps = self._finding_steps(category, path_url, f)
            suggestion = self._default_suggestion(category)
            evidence = self._generate_evidence(f)

            report = self.generate_vuln_report(
                title=title,
                severity=severity,
                vuln_url=path_url,
                vuln_type=vuln_type,
                description=description,
                steps=steps,
                suggestion=suggestion,
                platform=platform,
                evidence=evidence,
                finding=f,
            )
            reports.append({
                "title": title,
                "severity": severity,
                "url": path_url,
                "type": vuln_type,
                "report": report,
            })

        return reports

    def generate_from_cve(
        self,
        host: str,
        cve_matches: list[dict],
    ) -> list[dict]:
        """从 CVE 匹配生成报告"""
        reports = []

        for cve in cve_matches:
            cve_id = cve.get("cve", "")
            severity = cve.get("severity", "MEDIUM")
            desc = cve.get("description", "")

            title = f"[{host}] 疑似 {cve_id}: {desc[:50]}"
            description = (
                f"目标使用可能存在 {cve_id} 漏洞的组件。\n"
                f"建议验证该漏洞是否可被实际利用。\n\n"
                f"漏洞描述: {desc}"
            )
            steps = [
                "使用破晓扫描，识别到目标技术栈可能受此 CVE 影响",
                f"手动验证：参考 {cve_id} 公开 PoC 进行复现",
                "记录复现结果（截图/响应内容）",
            ]
            suggestion = f"升级受影响的组件版本，参考 {cve_id} 公告中的修复版本。"

            report = self.generate_vuln_report(
                title=title,
                severity=severity,
                vuln_url="",
                vuln_type="cve",
                description=description,
                steps=steps,
                suggestion=suggestion,
            )
            reports.append({
                "title": title,
                "severity": severity,
                "type": f"CVE/{cve_id}",
                "report": report,
            })

        return reports

    def generate_batch(
        self,
        scan_results: list[dict],
        output_dir: str = "scan_results",
        platform: str = "butian",
    ) -> dict:
        """
        批量生成 SRC 报告
        scan_results: ScanResult.to_dict() 列表
        platform: butian / vulbox / cnvd — 影响报告格式（P2-5 增强）
        返回: {"reports": [...], "output_dir": "...", "platform": "..."}
        """
        out = Path(output_dir) / "src_reports"
        out.mkdir(parents=True, exist_ok=True)

        all_reports = []

        for t in scan_results:
            host = t.get("host", "unknown")
            tech_tags = t.get("tech_tags", [])

            # 敏感路径发现
            sensitive = t.get("sensitive_paths", [])
            if sensitive:
                reports = self.generate_from_sensitive(
                    target_url=t.get("target_url", ""),
                    host=host,
                    findings=sensitive,
                    tech_tags=tech_tags,
                    platform=platform,
                )
                all_reports.extend(reports)

            # CVE 匹配
            cves = t.get("cve_matches", [])
            if cves:
                reports = self.generate_from_cve(host=host, cve_matches=cves)
                all_reports.extend(reports)

        # 保存每个报告
        for i, r in enumerate(all_reports):
            filename = f"{i+1:03d}_{r['title'][:40].replace('/', '_').replace(' ', '_')}.md"
            filepath = out / filename
            filepath.write_text(r["report"], encoding="utf-8")

        # 生成索引
        index_lines = ["# SRC 报告索引", ""]
        sev_order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3}
        all_reports.sort(key=lambda x: sev_order.get(
            self.SEVERITY_CN.get(x["severity"], ""), 99
        ))

        for i, r in enumerate(all_reports):
            sev = self.SEVERITY_CN.get(r["severity"], r["severity"])
            icon = "🔴" if sev in ("严重", "高危") else "🟡" if sev == "中危" else "🔵"
            index_lines.append(f"{i+1}. {icon} [{sev}] {r['title']}")

        index_path = out / "INDEX.md"
        index_path.write_text("\n".join(index_lines), encoding="utf-8")

        return {
            "total": len(all_reports),
            "output_dir": str(out),
            "index": str(index_path),
            "platform": platform,
            "reports": all_reports,
        }

    # ── 辅助方法 ─────────────────────────────────

    def _finding_title(self, category: str, url: str) -> str:
        cat_cn = {
            "git": "Git 仓库信息泄露",
            "config": "配置文件可访问",
            "backup": "备份文件泄露",
            "debug": "调试信息泄露",
            "admin": "后台管理页面暴露",
            "api": "API 接口信息泄露",
            "source": "源代码泄露",
            "db": "数据库管理入口暴露",
            "swagger": "Swagger/API文档泄露",
            "actuator": "Spring Boot Actuator信息泄露",
            "phpinfo": "phpinfo信息泄露",
            "default_cred": "默认凭据登录",
            "directory_listing": "目录遍历",
            "missing_header": "缺少安全响应头",
            "sqli": "SQL注入漏洞",
            "xss": "跨站脚本攻击(XSS)",
            "ssrf": "服务端请求伪造(SSRF)",
            "cors": "CORS跨域配置不当",
        }
        return cat_cn.get(category, f"敏感信息泄露 ({category})")

    def _finding_severity(self, category: str, status: int, finding: dict = None) -> str:
        """根据漏洞类型和上下文自动判定严重等级

        finding 可包含额外字段用于细化判定:
          - content_preview: 响应内容预览
          - response_headers: 响应头
          - has_write_endpoints: swagger 是否含写接口
          - is_admin_panel: 是否管理后台
        """
        if finding is None:
            finding = {}

        # ── Critical 级 ──
        if category == "git":
            # .git 配合源码可下载 → Critical
            preview = finding.get("content_preview", "")
            if any(kw in preview.lower() for kw in ("ref:", "repositoryformatversion", "[core]")):
                return "CRITICAL"
            return "HIGH"

        if category == "actuator":
            # /actuator/env 暴露环境变量 → Critical
            url_lower = finding.get("url", "").lower()
            if "/env" in url_lower or "/heapdump" in url_lower:
                return "CRITICAL"
            return "HIGH"

        if category == "swagger":
            # 含写接口的 Swagger → Critical
            if finding.get("has_write_endpoints"):
                return "CRITICAL"
            return "HIGH"

        if category == "default_cred":
            return "CRITICAL"

        if category == "sqli":
            return "CRITICAL"

        # ── High 级 ──
        if category in ("backup", "source", "config"):
            return "HIGH"

        if category in ("admin", "db"):
            if status == 403:
                return "MEDIUM"
            # 管理后台默认 High
            if finding.get("is_admin_panel"):
                return "HIGH"
            return "HIGH"

        if category == "ssrf":
            return "HIGH"

        # ── Medium 级 ──
        if category in ("debug", "phpinfo"):
            return "MEDIUM"

        if category == "api":
            return "MEDIUM"

        if category == "xss":
            return "MEDIUM"

        if category == "cors":
            return "MEDIUM"

        if category == "directory_listing":
            return "MEDIUM"

        # ── Low 级 ──
        if category == "missing_header":
            return "LOW"

        # ── Info 级 ──
        if category == "info" or category == "info_leak":
            return "INFO"

        return "LOW"

    def _finding_description(self, category: str, path_url: str, target_url: str) -> str:
        templates = {
            "git": (
                f"目标站点 {target_url} 的 {path_url} 可被外部访问，存在 Git 版本控制信息泄露风险。"
                f"攻击者可利用此漏洞下载完整源代码、历史提交记录及可能包含的数据库密码、API密钥等敏感配置信息。"
            ),
            "config": (
                f"目标站点 {target_url} 的 {path_url} 存在配置文件泄露风险。"
                f"配置文件可能包含数据库连接信息、API密钥、云服务凭证等敏感数据，可被攻击者直接利用进行进一步入侵。"
            ),
            "backup": (
                f"目标站点 {target_url} 的 {path_url} 可能存在备份文件。"
                f"备份文件可能包含源代码、数据库转储或配置文件，攻击者可下载后分析获取敏感信息。"
            ),
            "admin": (
                f"目标站点 {target_url} 的 {path_url} 暴露了后台管理页面。"
                f"攻击者可利用该页面进行暴力破解、默认凭据尝试或直接访问管理功能。"
            ),
            "debug": (
                f"目标站点 {target_url} 的 {path_url} 存在调试信息泄露。"
                f"调试页面可能泄露服务器配置、环境变量、数据库连接等敏感信息。"
            ),
            "api": (
                f"目标站点 {target_url} 的 {path_url} 暴露了 API 接口文档。"
                f"攻击者可获取完整接口列表，发现未授权访问接口或参数注入点。"
            ),
            "db": (
                f"目标站点 {target_url} 的 {path_url} 暴露了数据库管理工具入口。"
                f"攻击者可能通过默认凭据或漏洞直接操作数据库。"
            ),
            "source": (
                f"目标站点 {target_url} 的 {path_url} 存在源代码泄露风险。"
                f"攻击者可获取服务器端源代码，分析业务逻辑发现更多安全漏洞。"
            ),
            "swagger": (
                f"目标站点 {target_url} 的 {path_url} 暴露了 Swagger/OpenAPI 文档。"
                f"文档包含完整的 API 接口定义、参数说明和数据模型，攻击者可据此发现未授权接口或参数注入点。"
            ),
            "actuator": (
                f"目标站点 {target_url} 的 {path_url} 暴露了 Spring Boot Actuator 端点。"
                f"Actuator 端点可能泄露环境变量（含数据库密码、API密钥）、堆转储、配置信息等敏感数据。"
            ),
            "phpinfo": (
                f"目标站点 {target_url} 的 {path_url} 暴露了 phpinfo() 页面。"
                f"该页面泄露 PHP 版本、服务器配置、环境变量、已加载扩展等信息，攻击者可据此构造针对性攻击。"
            ),
            "default_cred": (
                f"目标站点 {target_url} 的 {path_url} 存在默认凭据登录漏洞。"
                f"攻击者可使用默认用户名和密码直接登录系统，获取管理权限。"
            ),
            "directory_listing": (
                f"目标站点 {target_url} 的 {path_url} 开启了目录遍历功能。"
                f"攻击者可浏览目录结构，发现敏感文件（配置文件、备份文件、源代码等）。"
            ),
            "missing_header": (
                f"目标站点 {target_url} 缺少安全响应头。"
                f"缺少安全头部可能导致点击劫持、MIME 嗅探、XSS 等安全风险。"
            ),
            "sqli": (
                f"目标站点 {target_url} 的 {path_url} 存在 SQL 注入漏洞。"
                f"攻击者可通过构造恶意 SQL 语句获取、篡改或删除数据库数据，甚至获取服务器权限。"
            ),
            "xss": (
                f"目标站点 {target_url} 的 {path_url} 存在跨站脚本攻击(XSS)漏洞。"
                f"攻击者可注入恶意脚本，窃取用户 Cookie、会话令牌或执行钓鱼攻击。"
            ),
            "ssrf": (
                f"目标站点 {target_url} 的 {path_url} 存在服务端请求伪造(SSRF)漏洞。"
                f"攻击者可利用该漏洞访问内网资源、云元数据服务或进行端口扫描。"
            ),
            "cors": (
                f"目标站点 {target_url} 的 {path_url} 存在 CORS 跨域配置不当问题。"
                f"攻击者可从恶意网站发起跨域请求，窃取用户数据。"
            ),
        }
        return templates.get(category, f"目标站点 {target_url} 的 {path_url} 存在信息泄露风险。")

    def _finding_steps(self, category: str, path_url: str, finding: dict = None) -> list[str]:
        """根据漏洞类型生成专用复现步骤

        finding 可包含: username, password, header_name 等字段
        """
        if finding is None:
            finding = {}

        # 从 URL 提取 base URL
        from urllib.parse import urlparse
        parsed = urlparse(path_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else path_url

        steps_map = {
            "git": [
                f"访问 {path_url}（或 {base_url}/.git/HEAD），确认返回 200 状态码",
                f"访问 {base_url}/.git/config，获取 Git 配置信息",
                f"使用 GitHack 等工具下载源码：GitHack.py {base_url}/.git/",
            ],
            "backup": [
                f"访问 {path_url}，确认返回 200 状态码",
                "下载备份文件，检查文件内容",
                "确认文件包含敏感信息（数据库配置、源码等）",
            ],
            "swagger": [
                f"访问 {path_url}，确认返回 Swagger/OpenAPI 文档",
                "查看 API 接口列表，记录敏感接口",
                "测试接口是否可未授权访问",
            ],
            "api": [
                f"访问 {path_url}，确认返回 API 文档或接口信息",
                "查看接口列表，记录敏感接口",
                "测试接口是否可未授权访问",
            ],
            "default_cred": [
                f"访问 {path_url} 登录页面",
                "使用默认凭据 {username}:{password} 尝试登录".format(
                    username=finding.get("username", "admin"),
                    password=finding.get("password", "admin"),
                ),
                "确认登录成功，获取后台访问权限",
            ],
            "directory_listing": [
                f"访问 {path_url}，确认返回目录列表页面",
                "浏览目录结构，记录敏感文件",
                "尝试访问敏感文件确认可读取",
            ],
            "config": [
                f"访问 {path_url}，确认返回配置文件内容",
                "检查配置文件中的敏感信息（数据库连接、API Key 等）",
                "确认信息可被利用",
            ],
            "actuator": [
                f"访问 {base_url}/actuator，确认返回 Actuator 端点列表",
                f"访问 {base_url}/actuator/env，获取环境变量",
                f"访问 {base_url}/actuator/heapdump，下载堆转储分析敏感信息",
            ],
            "debug": [
                f"访问 {path_url}，确认返回 phpinfo() 或调试信息页面",
                "记录 PHP 版本、服务器配置、环境变量",
                "检查是否包含敏感信息（数据库密码、API Key 等）",
            ],
            "phpinfo": [
                f"访问 {path_url}，确认返回 phpinfo() 页面",
                "记录 PHP 版本、服务器配置、环境变量",
                "检查是否包含敏感信息（数据库密码、API Key 等）",
            ],
            "sqli": [
                f"访问 {path_url}，注入单引号 ' 观察响应",
                f'使用 SQLMap 验证：sqlmap -u "{path_url}" --batch',
                "确认可注入，获取数据库信息",
            ],
            "xss": [
                f"访问 {path_url}，注入 payload: <script>alert(1)</script>",
                "确认 payload 被反射/存储",
                "在浏览器中触发弹窗验证",
            ],
            "ssrf": [
                f"访问 {path_url}，注入内网地址：http://127.0.0.1/",
                "观察响应是否包含内网信息",
                "尝试访问云元数据：http://169.254.169.254/",
            ],
            "cors": [
                "使用 curl 发送请求，设置 Origin: https://evil.com",
                "检查响应头 Access-Control-Allow-Origin 是否为 *",
                "确认 Access-Control-Allow-Credentials: true",
            ],
            "missing_header": [
                f"使用 curl -I {path_url} 检查响应头",
                f"确认 {finding.get('header_name', '安全响应头')} 缺失",
                "说明缺失该头部的安全风险",
            ],
            "admin": [
                f"访问 {path_url}，确认管理后台页面可访问",
                "记录页面信息（框架、版本等）",
                "尝试默认凭据或暴力破解登录",
            ],
            "db": [
                f"访问 {path_url}，确认数据库管理工具可访问",
                "记录工具类型和版本信息",
                "尝试默认凭据登录（如 root:root、admin:admin）",
            ],
            "source": [
                f"访问 {path_url}，确认返回源代码文件",
                "检查文件内容，确认包含业务逻辑代码",
                "分析代码中的硬编码密钥、注释信息等",
            ],
        }

        return steps_map.get(category, [
            f"使用浏览器访问 {path_url}",
            "观察到页面返回了敏感信息/配置/管理功能",
            "截图保存证据",
        ])

    def _generate_evidence(self, finding: dict) -> str:
        """Generate HTTP evidence for the finding

        finding 可包含:
          - request_url / url: 请求地址
          - response_status / status: 响应状态码
          - http_version: HTTP 版本
          - response_headers: 响应头 dict
          - content_preview: 响应内容预览
        """
        evidence = []
        url = finding.get("request_url") or finding.get("url", "")
        if url:
            evidence.append(f"GET {url} HTTP/1.1")
            evidence.append(f"Host: {url.split('/')[2] if '://' in url else ''}")

        status = finding.get("response_status") or finding.get("status")
        if status:
            http_ver = finding.get("http_version", "1.1")
            evidence.append(f"HTTP/{http_ver} {status}")

        # 关键响应头
        headers = finding.get("response_headers", {})
        if headers:
            for key in ["Server", "Content-Type", "X-Powered-By", "Content-Length"]:
                val = headers.get(key) or headers.get(key.lower())
                if val:
                    evidence.append(f"{key}: {val}")

        # 响应内容预览
        preview = finding.get("content_preview", "")
        if preview and len(preview) > 10:
            # 截取前 200 字符作为证据
            evidence.append("")
            evidence.append(preview[:200])

        return "\n".join(evidence)

    def _default_suggestion(self, vuln_type: str) -> str:
        suggestions = {
            "git": (
                "1. 从生产环境删除 .git 目录\n"
                "2. 在 Web 服务器配置中禁止访问 .git 路径（Nginx: location ~ /\\.git { deny all; }）\n"
                "3. 部署时使用 `git archive` 导出而非直接 clone\n"
                "4. 在 .gitignore 中排除敏感配置文件"
            ),
            "config": (
                "1. 将配置文件移至 Web 根目录之外\n"
                "2. 配置 Web 服务器禁止访问 .env / .config / .yaml 等文件\n"
                "3. 敏感配置使用环境变量或密钥管理服务\n"
                "4. 定期检查并清理残留配置文件"
            ),
            "backup": (
                "1. 立即删除 Web 目录下的备份文件\n"
                "2. 配置服务器禁止访问 .bak / .zip / .tar / .sql 等文件\n"
                "3. 备份文件存储在非 Web 可访问的目录\n"
                "4. 定期清理临时文件和历史备份"
            ),
            "swagger": (
                "1. 在生产环境禁用 Swagger UI 和 API 文档端点\n"
                "2. 如需保留，添加 IP 白名单或认证机制\n"
                "3. 配置 Spring Boot: springdoc.api-docs.enabled=false\n"
                "4. 使用 Nginx 屏蔽 /swagger-ui.html、/v2/api-docs 等路径"
            ),
            "api": (
                "1. 在生产环境关闭 API 文档自动生成\n"
                "2. 对 API 接口添加认证和授权机制\n"
                "3. 限制 API 接口的访问权限\n"
                "4. 使用 API 网关统一管理接口访问"
            ),
            "default_cred": (
                "1. 立即修改所有默认密码\n"
                "2. 实施密码策略：最小长度、复杂度要求\n"
                "3. 启用双因素认证(2FA)\n"
                "4. 限制登录尝试次数，防止暴力破解\n"
                "5. 修改默认用户名，避免使用 admin/root"
            ),
            "directory_listing": (
                "1. 在 Web 服务器配置中禁用目录列表\n"
                "   Nginx: autoindex off;\n"
                "   Apache: Options -Indexes\n"
                "2. 为每个目录添加默认首页文件（index.html）\n"
                "3. 将敏感文件移至 Web 根目录之外"
            ),
            "admin": (
                "1. 对管理后台加强访问控制（IP 白名单 / VPN）\n"
                "2. 启用双因素认证(2FA)\n"
                "3. 避免使用常见管理路径（/admin、/manager）\n"
                "4. 修改默认端口，增加访问门槛"
            ),
            "debug": (
                "1. 在生产环境关闭 debug 模式\n"
                "2. 删除测试文件（phpinfo.php / test.php / debug 页面）\n"
                "3. 配置 PHP: display_errors = Off\n"
                "4. 日志输出到文件而非页面"
            ),
            "phpinfo": (
                "1. 立即删除服务器上的 phpinfo.php 文件\n"
                "2. 在 php.ini 中设置 expose_php = Off\n"
                "3. 配置 display_errors = Off，避免泄露路径信息\n"
                "4. 定期扫描并清理测试文件"
            ),
            "db": (
                "1. 限制数据库管理工具的访问 IP\n"
                "2. 使用强密码并定期更换\n"
                "3. 禁用 phpMyAdmin / Adminer 等工具的远程访问\n"
                "4. 将管理工具部署在内网，通过 VPN 访问"
            ),
            "source": (
                "1. 删除服务器上的编辑器临时文件（.swp / ~ / .bak）\n"
                "2. 配置 Web 服务器禁止访问 .swp / ~ / .bak 文件\n"
                "3. 使用 .gitignore 排除编辑器临时文件\n"
                "4. 部署前检查并清理非必要文件"
            ),
            "actuator": (
                "1. 限制 Actuator 端点访问，仅暴露必要端点\n"
                "   management.endpoints.web.exposure.include=health,info\n"
                "2. 为 Actuator 端点添加认证\n"
                "   management.endpoints.web.base-path=/management\n"
                "3. 使用 Spring Security 限制 /actuator 路径\n"
                "4. 在生产环境禁用 /env 和 /heapdump 端点"
            ),
            "sqli": (
                "1. 使用参数化查询（PreparedStatement）替代字符串拼接\n"
                "2. 对用户输入进行严格的输入验证和过滤\n"
                "3. 部署 WAF（Web 应用防火墙）拦截 SQL 注入攻击\n"
                "4. 使用 ORM 框架减少手动 SQL 编写\n"
                "5. 遵循最小权限原则配置数据库用户"
            ),
            "xss": (
                "1. 对所有用户输入进行输出编码（HTML / JS / URL 编码）\n"
                "2. 添加 Content-Security-Policy (CSP) 响应头\n"
                "3. 设置 HttpOnly 标记保护 Cookie\n"
                "4. 使用模板引擎的自动转义功能\n"
                "5. 对用户输入进行严格的白名单验证"
            ),
            "ssrf": (
                "1. 对用户可控的 URL 进行白名单验证\n"
                "2. 禁止请求内网地址（10.x / 172.16-31.x / 192.168.x）\n"
                "3. 禁止访问云元数据地址（169.254.169.254）\n"
                "4. 限制请求协议（仅允许 http/https）\n"
                "5. 使用 DNS 解析验证目标地址"
            ),
            "cors": (
                "1. 限制 Access-Control-Allow-Origin 为可信域名，不使用通配符 *\n"
                "2. 不要同时设置 Origin: * 和 Credentials: true\n"
                "3. 限制允许的 HTTP 方法（Access-Control-Allow-Methods）\n"
                "4. 定期审查 CORS 配置"
            ),
            "missing_header": (
                "1. 添加缺失的安全响应头\n"
                "   X-Content-Type-Options: nosniff\n"
                "   X-Frame-Options: DENY\n"
                "   X-XSS-Protection: 1; mode=block\n"
                "   Strict-Transport-Security: max-age=31536000\n"
                "   Content-Security-Policy: default-src 'self'\n"
                "2. 在 Web 服务器或应用框架中统一配置\n"
                "3. 使用安全中间件自动添加响应头"
            ),
            "cve": (
                "1. 升级相关组件到最新安全版本\n"
                "2. 关注官方安全公告及时修复\n"
                "3. 如无法升级，使用 WAF 规则临时防护\n"
                "4. 评估漏洞影响范围，优先修复高危漏洞"
            ),
        }
        return suggestions.get(vuln_type, "建议联系厂商进行安全加固。")
