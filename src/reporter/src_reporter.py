"""SRC 报告生成 — 补天 / 漏洞盒子 / CNVD 格式"""

from pathlib import Path
from typing import Optional


class SRCReporter:
    """SRC 平台报告生成器"""

    # 漏洞等级→中文
    SEVERITY_CN = {
        "CRITICAL": "严重",
        "HIGH": "高危",
        "MEDIUM": "中危",
        "LOW": "低危",
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
    }

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
    ) -> str:
        """生成单个漏洞的SRC报告（Markdown格式）"""

        sev_cn = self.SEVERITY_CN.get(severity, severity)
        type_cn = self.VULN_TYPE_MAP.get(vuln_type, vuln_type)

        lines = []
        lines.append(f"# {title}")
        lines.append("")
        lines.append("## 基本信息")
        lines.append("")
        lines.append(f"- **漏洞等级**: {sev_cn}")
        lines.append(f"- **漏洞URL**: {vuln_url}")
        lines.append(f"- **漏洞类型**: {type_cn}")
        lines.append("")
        lines.append("## 漏洞描述")
        lines.append("")
        lines.append(description)
        lines.append("")
        lines.append("## 复现步骤")
        lines.append("")
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append("## 修复建议")
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
    ) -> list[dict]:
        """从敏感路径发现生成报告"""
        reports = []

        for f in findings:
            category = f.get("category", "info_leak")
            path_url = f.get("url", "")
            status = f.get("status", 0)

            vuln_type = category
            title = f"[{host}] {self._finding_title(category, path_url)}"
            severity = self._finding_severity(category, status)
            description = self._finding_description(category, path_url, target_url)
            steps = self._finding_steps(category, path_url)
            suggestion = self._default_suggestion(category)

            report = self.generate_vuln_report(
                title=title,
                severity=severity,
                vuln_url=path_url,
                vuln_type=vuln_type,
                description=description,
                steps=steps,
                suggestion=suggestion,
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
    ) -> dict:
        """
        批量生成 SRC 报告
        scan_results: ScanResult.to_dict() 列表
        返回: {"reports": [...], "output_dir": "..."}
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
        }
        return cat_cn.get(category, f"敏感信息泄露 ({category})")

    def _finding_severity(self, category: str, status: int) -> str:
        if category in ("git", "backup", "source", "config"):
            return "HIGH"
        if category in ("admin", "db", "debug"):
            return "MEDIUM" if status == 403 else "HIGH"
        if category == "api":
            return "MEDIUM"
        return "LOW"

    def _finding_description(self, category: str, path_url: str, target_url: str) -> str:
        templates = {
            "git": f"目标站点 {target_url} 的 {path_url} 可被外部访问，存在 Git 版本控制信息泄露风险。攻击者可利用此漏洞获取源代码、历史提交记录及可能包含的敏感配置信息。",
            "config": f"目标站点 {target_url} 的 {path_url} 存在配置文件泄露风险。配置文件可能包含数据库连接信息、API密钥等敏感数据。",
            "backup": f"目标站点 {target_url} 的 {path_url} 可能存在备份文件。备份文件可能包含源代码、数据库或配置文件。",
            "admin": f"目标站点 {target_url} 的 {path_url} 暴露了后台管理页面。攻击者可利用该页面进行暴力破解或直接访问管理功能。",
            "debug": f"目标站点 {target_url} 的 {path_url} 存在调试信息泄露风险。",
            "api": f"目标站点 {target_url} 的 {path_url} 暴露了API接口信息。",
            "db": f"目标站点 {target_url} 的 {path_url} 暴露了数据库管理工具入口。",
            "source": f"目标站点 {target_url} 的 {path_url} 存在源代码泄露风险。",
        }
        return templates.get(category, f"目标站点 {target_url} 的 {path_url} 存在信息泄露风险。")

    def _finding_steps(self, category: str, path_url: str) -> list[str]:
        return [
            f"使用浏览器访问 {path_url}",
            "观察到页面返回了敏感信息/配置/管理功能",
            "截图保存证据",
        ]

    def _default_suggestion(self, vuln_type: str) -> str:
        suggestions = {
            "git": "1. 在 Web 服务器配置中禁止访问 .git 目录\n2. 确保 .git 目录不在 Web 根目录下\n3. 部署时使用 archive/export 而非 clone",
            "config": "1. 将配置文件移至 Web 根目录之外\n2. 配置 Web 服务器禁止访问 .env / .config 等文件\n3. 敏感配置使用环境变量",
            "backup": "1. 删除 Web 目录下的备份文件\n2. 配置服务器禁止访问 .bak / .zip / .tar 等文件\n3. 定期清理临时文件",
            "admin": "1. 对管理后台加强访问控制（IP白名单/VPN）\n2. 启用双因素认证\n3. 避免使用常见管理路径",
            "debug": "1. 在生产环境关闭 debug 模式\n2. 删除测试文件（phpinfo.php / test.php）",
            "db": "1. 限制数据库管理工具的访问IP\n2. 使用强密码并定期更换\n3. 禁用phpMyAdmin等工具的远程访问",
            "source": "1. 删除服务器上的编辑器临时文件\n2. 配置 Web 服务器禁止访问 .swp / ~ 文件",
            "cve": "1. 升级相关组件到最新安全版本\n2. 关注官方安全公告及时修复\n3. 如无法升级，使用 WAF 规则临时防护",
        }
        return suggestions.get(vuln_type, "建议联系厂商进行安全加固。")
