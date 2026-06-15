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
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple

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

    # 默认模板目录
    DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"

    def __init__(self, template_dir: str = "", extra_dirs: list = None):
        """
        Args:
            template_dir: 主模板目录 (默认 templates/)
            extra_dirs: 额外模板目录列表 (会合并加载)
        """
        self.template_dir = Path(template_dir) if template_dir else self.DEFAULT_TEMPLATE_DIR
        self.extra_dirs = [Path(d) for d in (extra_dirs or []) if d]

    def load_all(self, tags: List[str] = None, severity: List[str] = None,
                 ids: List[str] = None) -> List[Template]:
        """
        加载目录下的所有模板

        Args:
            tags: 按标签过滤
            severity: 按严重级别过滤
            ids: 按模板 ID 过滤

        Returns:
            List[Template]
        """
        if not HAS_YAML:
            print("  [!] PyYAML not installed (pip install pyyaml)")
            return []

        templates = []
        seen_ids = set()

        # 加载所有目录 (主目录 + 额外目录)
        all_dirs = [self.template_dir] + self.extra_dirs

        for template_dir in all_dirs:
            if not template_dir.exists():
                continue

            # 递归扫描 YAML 文件
            for yaml_file in sorted(template_dir.rglob("*.yaml")):
                try:
                    tmpl = self.load_file(yaml_file)
                    if tmpl and tmpl.id not in seen_ids:
                        templates.append(tmpl)
                        seen_ids.add(tmpl.id)
                except Exception as e:
                    print(f"  [!] Load failed {yaml_file.name}: {e}")

            for yml_file in sorted(template_dir.rglob("*.yml")):
                try:
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

    def _parse_template(self, raw: dict, file_path: str = "") -> Optional[Template]:
        """解析 YAML 字典为 Template 对象"""
        # 基本信息
        tmpl_id = raw.get("id", "")
        if not tmpl_id:
            return None

        # info 块
        info_raw = raw.get("info", {})
        info = TemplateInfo(
            name=info_raw.get("name", tmpl_id),
            author=info_raw.get("author", "poxiao"),
            severity=info_raw.get("severity", "info").lower(),
            description=info_raw.get("description", ""),
            reference=self._ensure_list(info_raw.get("reference", [])),
            tags=self._parse_tags(info_raw.get("tags", "")),
            classification=info_raw.get("classification", {}),
        )

        # requests 块 (兼容 http 块)
        requests_raw = raw.get("http", raw.get("requests", []))
        if isinstance(requests_raw, dict):
            requests_raw = [requests_raw]

        requests = []
        for req_raw in requests_raw:
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
        """解析单个请求模板"""
        if not raw:
            return None

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
            method=raw.get("method", "GET").upper(),
            path=paths,
            headers=headers,
            body=body,
            content_type=raw.get("content-type", raw.get("content_type", "")),
            matchers_condition=raw.get("matchers-condition", raw.get("matchers_logic", "and")),
            matchers=matchers,
            extractors=extractors,
            timeout=raw.get("timeout", 10.0),
            follow_redirects=raw.get("redirects", raw.get("follow_redirects", True)),
            max_redirects=raw.get("max-redirects", 3),
            stop_at_first_match=raw.get("stop-at-first-match", False),
        )

        return req

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
