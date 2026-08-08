"""
模板加载器 — 加载 YAML 模板文件
================================

支持:
  - 单个 YAML 文件
  - 目录递归扫描
  - 按 ID / 标签 / 严重级别过滤
  - 模板语法验证
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .template import (
    Template, TemplateInfo, HTTPRequest,
    Matcher, Extractor,
)


class TemplateLoader:
    """YAML 模板加载器"""

    @staticmethod
    def _default_template_dir() -> Path:
        """默认模板目录（B1: 兼容 PyInstaller 单文件打包的 _MEIPASS 解包路径）"""
        env = os.environ.get("POXIAO_TEMPLATES_PATH", "")
        if env:
            return Path(env)
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            return Path(meipass) / "templates"
        return Path(__file__).parent.parent.parent / "templates"

    # 默认模板目录（支持环境变量覆盖）
    DEFAULT_TEMPLATE_DIR = _default_template_dir()

    def __init__(self, template_dir: str = "", extra_dirs: list = None):
        """
        Args:
            template_dir: 主模板目录 (默认 templates/)
            extra_dirs: 额外模板目录列表 (会合并加载)
        """
        self.template_dir = Path(template_dir) if template_dir else self.DEFAULT_TEMPLATE_DIR
        self.extra_dirs = [Path(d) for d in (extra_dirs or []) if d]

    def load_all(self, tags: List[str] = None, severity: List[str] = None,
                 ids: List[str] = None,
                 verify_signatures: bool = False,
                 public_key_path: str = "") -> List[Template]:
        """
        加载目录下的所有模板

        Args:
            tags: 按标签过滤
            severity: 按严重级别过滤
            ids: 按模板 ID 过滤
            verify_signatures: 启用模板 ECDSA 签名校验（P1-C，默认关）
            public_key_path: 校验用公钥 PEM 路径（verify_signatures=True 时必填）

        Returns:
            List[Template]
        """
        if not HAS_YAML:
            print("  [!] PyYAML not installed (pip install pyyaml)")
            return []

        # P1-C: 预构建 目录→签名状态映射（未启用/无签名清单时为空）
        sig_status: Dict[Path, Dict[str, str]] = {}
        if verify_signatures:
            try:
                from .template_sign import verify_directory
                if not public_key_path:
                    print("  [!] verify_signatures=True 但未提供 public_key_path，跳过校验")
                else:
                    for template_dir in [self.template_dir] + self.extra_dirs:
                        if template_dir.exists():
                            sig_status[template_dir] = verify_directory(
                                template_dir, public_key_path
                            )
            except Exception as e:
                print(f"  [!] 签名校验初始化失败（跳过）: {e}")

        templates = []
        seen_ids = set()

        # 加载所有目录 (主目录 + 额外目录)
        all_dirs = [self.template_dir] + self.extra_dirs

        for template_dir in all_dirs:
            if not template_dir.exists():
                continue

            status_map = sig_status.get(template_dir, {})

            # 递归扫描 YAML 文件
            for yaml_file in sorted(template_dir.rglob("*.yaml")):
                try:
                    if not self._signature_ok(status_map, template_dir, yaml_file):
                        continue
                    tmpl = self.load_file(yaml_file)
                    if tmpl and tmpl.id not in seen_ids:
                        templates.append(tmpl)
                        seen_ids.add(tmpl.id)
                except Exception as e:
                    print(f"  [!] Load failed {yaml_file.name}: {e}")

            for yml_file in sorted(template_dir.rglob("*.yml")):
                try:
                    if not self._signature_ok(status_map, template_dir, yml_file):
                        continue
                    tmpl = self.load_file(yml_file)
                    if tmpl and tmpl.id not in seen_ids:
                        templates.append(tmpl)
                        seen_ids.add(tmpl.id)
                except Exception as e:
                    print(f"  [!] Load failed {yml_file.name}: {e}")

        # 过滤
        if tags:
            templates = [t for t in templates if any(tag in t.info.tags for tag in tags)]

        if severity:
            templates = [t for t in templates if t.info.severity in severity]

        if ids:
            templates = [t for t in templates if t.id in ids]

        return templates

    def load_file(self, file_path: Path) -> Optional[Template]:
        """加载单个 YAML 模板文件"""
        try:
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        except Exception:
            return None

        if not isinstance(raw, dict):
            return None

        return self._parse_template(raw, str(file_path))

    @staticmethod
    def _signature_ok(status_map: Dict[str, str], template_dir: Path,
                      yaml_file: Path) -> bool:
        """P1-C: 按签名状态决定是否加载；未启用校验时恒放行"""
        if not status_map:
            return True
        rel = yaml_file.relative_to(template_dir).as_posix()
        status = status_map.get(rel, "unsigned")
        if status == "bad":
            print(f"  [!] 签名不匹配，已拒绝加载（可能被篡改）: {rel}")
            return False
        if status == "unsigned":
            print(f"  [!] 未签名模板（校验模式）: {rel}")
            return False
        return True

    def _parse_template(self, raw: dict, file_path: str = "") -> Optional[Template]:
        """解析 YAML 字典为 Template 对象"""
        # 基本信息
        tmpl_id = raw.get("id", "")
        if not tmpl_id:
            return None

        # info 块
        info_raw = raw.get("info", {})
        if not isinstance(info_raw, dict):
            info_raw = {}
        sev = info_raw.get("severity") or "info"
        info = TemplateInfo(
            name=info_raw.get("name", tmpl_id) or tmpl_id,
            author=info_raw.get("author", "poxiao") or "poxiao",
            severity=str(sev).lower(),
            description=info_raw.get("description", "") or "",
            reference=self._ensure_list(info_raw.get("reference", [])),
            tags=self._parse_tags(info_raw.get("tags", "")),
            classification=info_raw.get("classification", {}) or {},
        )

        # requests 块 (兼容 http 块)
        requests_raw = raw.get("http", raw.get("requests", []))
        if isinstance(requests_raw, dict):
            requests_raw = [requests_raw]

        requests = []
        for req_raw in requests_raw:
            # P2-1: raw 列表 → 每个报文独立请求，共享 http 块顶层 matchers/extractors
            raw_list = req_raw.get("raw") if isinstance(req_raw, dict) else None
            if isinstance(raw_list, list):
                base = {k: v for k, v in req_raw.items() if k != "raw"}
                for rtext in raw_list:
                    if not isinstance(rtext, str) or not rtext.strip():
                        continue
                    merged = dict(base)
                    merged["raw"] = rtext
                    req = self._parse_request(merged)
                    if req:
                        requests.append(req)
            else:
                req = self._parse_request(req_raw)
                if req:
                    requests.append(req)

        if not requests:
            return None

        # 全局变量
        variables = raw.get("variables", {})

        template = Template(
            id=tmpl_id,
            info=info,
            requests=requests,
            variables=variables if isinstance(variables, dict) else {},
            raw_yaml=raw,
            file_path=file_path,
        )

        return template

    def _parse_request(self, raw: dict) -> Optional[HTTPRequest]:
        """解析单个请求模板（P2-1: 支持 nuclei raw HTTP 报文格式）"""
        if not raw:
            return None

        # ── raw 报文模式（nuclei http.raw；list 由 _parse_template 展开）──
        raw_text = raw.get("raw", "")
        if isinstance(raw_text, list):
            raw_text = raw_text[0] if raw_text else ""
        if raw_text:
            parsed = self._parse_raw_http(raw_text)
            if parsed:
                raw["method"] = parsed["method"]
                raw["path"] = [parsed["path"]]
                if parsed["headers"]:
                    merged = dict(raw.get("headers", {}) or {})
                    merged.update(parsed["headers"])
                    raw["headers"] = merged
                if parsed["body"]:
                    raw["body"] = parsed["body"]

        # 路径 (支持 path 和 paths)
        paths = raw.get("path", raw.get("paths", []))
        if isinstance(paths, str):
            paths = [paths]

        # Headers
        headers = raw.get("headers", {})
        if isinstance(headers, str):
            headers = {}

        # Matchers
        matchers_raw = raw.get("matchers", [])
        matchers = []
        for m_raw in matchers_raw:
            matcher = self._parse_matcher(m_raw)
            if matcher:
                matchers.append(matcher)

        # Extractors
        extractors_raw = raw.get("extractors", [])
        extractors = []
        for e_raw in extractors_raw:
            extractor = self._parse_extractor(e_raw)
            if extractor:
                extractors.append(extractor)

        # Body
        body = raw.get("body", "")
        if isinstance(body, dict):
            import json
            body = json.dumps(body)

        req = HTTPRequest(
            method=str(raw.get("method") or "GET").upper(),
            path=paths,
            headers=headers,
            body=body,
            content_type=raw.get("content-type", raw.get("content_type", "")),
            raw=raw_text,
            matchers_condition=raw.get("matchers-condition", raw.get("matchers_logic", "and")),
            matchers=matchers,
            extractors=extractors,
            timeout=raw.get("timeout", 10.0),
            follow_redirects=raw.get("redirects", raw.get("follow_redirects", True)),
            max_redirects=raw.get("max-redirects", 3),
            stop_at_first_match=raw.get("stop-at-first-match", False),
        )

        return req

    @staticmethod
    def _parse_raw_http(raw_text: str) -> Optional[dict]:
        """解析 nuclei raw HTTP 报文为 {method, path, headers, body}

        格式:
          GET /path HTTP/1.1
          Host: {{Hostname}}
          User-Agent: xyz

          <body>

        变量占位符（{{...}}）原样保留，运行时展开。
        """
        if not raw_text:
            return None
        lines = raw_text.replace("\r\n", "\n").split("\n")
        # 跳过空行
        idx = 0
        while idx < len(lines) and not lines[idx].strip():
            idx += 1
        if idx >= len(lines):
            return None

        request_line = lines[idx].strip()
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None
        method = parts[0].upper()
        path = parts[1]
        headers: dict = {}
        idx += 1
        body_lines: list[str] = []
        in_body = False
        for line in lines[idx:]:
            if not in_body:
                if line.strip() == "":
                    in_body = True
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
            else:
                body_lines.append(line)
        body = "\n".join(body_lines)
        return {
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
        }

    def _parse_matcher(self, raw: dict) -> Optional[Matcher]:
        """解析单个匹配器"""
        if not raw:
            return None

        matcher_type = raw.get("type", "word")

        matcher = Matcher(
            type=matcher_type,
            words=self._ensure_list(raw.get("words", raw.get("word", []))),
            case_sensitive=raw.get("case-sensitive", False),
            status=self._ensure_list(raw.get("status", [])),
            regex=self._ensure_list(raw.get("regex", raw.get("regexes", []))),
            size=self._ensure_list(raw.get("size", [])),
            header=raw.get("header", ""),
            header_value=raw.get("header_value", raw.get("value", "")),
            dsl=self._ensure_list(raw.get("dsl", [])),
            binary=self._ensure_list(raw.get("binary", [])),
            part=raw.get("part", "body"),
            negative=raw.get("negative", False),
            condition=raw.get("condition", "or"),
        )

        return matcher

    def _parse_extractor(self, raw: dict) -> Optional[Extractor]:
        """解析单个提取器"""
        if not raw:
            return None

        extractor = Extractor(
            type=raw.get("type", "regex"),
            regex=self._ensure_list(raw.get("regex", raw.get("regexes", []))),
            group=raw.get("group", 0),
            kval=self._ensure_list(raw.get("kval", [])),
            json=self._ensure_list(raw.get("json", [])),
            part=raw.get("part", "body"),
            name=raw.get("name", ""),
        )

        return extractor

    def _parse_tags(self, tags) -> List[str]:
        """解析标签 (支持字符串或列表)"""
        if isinstance(tags, str):
            return [t.strip() for t in tags.split(",") if t.strip()]
        elif isinstance(tags, list):
            return [str(t).strip() for t in tags if t]
        return []

    def _ensure_list(self, value) -> list:
        """确保值是列表"""
        if isinstance(value, list):
            return value
        if value is None:
            return []
        return [value]

    def list_templates(self, templates: List[Template]):
        """格式化打印模板列表"""
        print(f"\n  [*] Templates ({len(templates)} total)")
        print(f"  {'─' * 60}")

        # 按严重级别分组
        by_severity = {}
        for t in templates:
            by_severity.setdefault(t.severity, []).append(t)

        for sev in ["critical", "high", "medium", "low", "info"]:
            tmlps = by_severity.get(sev, [])
            if not tmlps:
                continue

            icon = tmlps[0].info.severity_icon
            print(f"\n  {icon} {sev.upper()} ({len(tmlps)})")
            for t in tmlps:
                tags_str = f" [{','.join(t.info.tags[:3])}]" if t.info.tags else ""
                print(f"    {t.id:40s} {t.info.name[:35]}{tags_str}")

        print(f"\n  {'─' * 60}")
        print(f"  共 {len(templates)} 个模板")

    def count_by_severity(self, templates: List[Template]) -> Dict[str, int]:
        """按严重级别统计"""
        counts = {}
        for t in templates:
            counts[t.severity] = counts.get(t.severity, 0) + 1
        return counts
