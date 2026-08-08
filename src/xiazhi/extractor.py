"""
提取器 (Extractor) — 从响应中提取有价值的数据
===============================================

支持的提取类型:
  - regex:  正则提取
  - kval:   Key-Value 提取 (从 headers/cookies 中提取)
  - json:   JSON 路径提取
"""

import re
import json
from typing import Dict, List
from .template import Extractor


class ExtractorEngine:
    """提取器执行引擎"""

    def extract(self, extractors: List[Extractor],
                status_code: int,
                headers: dict,
                body: str) -> Dict[str, str]:
        """
        执行所有提取器，返回提取的数据

        Returns:
            Dict[name, extracted_value]
        """
        results = {}

        for i, ext in enumerate(extractors):
            name = ext.name or f"extractor_{i}"

            handler = {
                "regex": self._extract_regex,
                "kval": self._extract_kval,
                "json": self._extract_json,
            }.get(ext.type)

            if not handler:
                continue

            target = self._get_target(ext.part, status_code, headers, body)
            extracted = handler(ext, target, status_code, headers, body)

            if extracted:
                results[name] = extracted

        return results

    def _get_target(self, part: str, status: int, headers: dict, body: str) -> str:
        """根据 part 选择提取目标"""
        if part == "header":
            return "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif part == "all":
            header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
            return f"{header_str}\n\n{body}"
        else:  # body
            return body

    def _extract_regex(self, ext: Extractor, target: str,
                       status: int, headers: dict, body: str) -> str:
        """正则提取"""
        all_results = []

        for pattern in ext.regex:
            try:
                matches = re.findall(pattern, target, re.IGNORECASE | re.DOTALL)
                if matches:
                    for m in matches:
                        if isinstance(m, tuple):
                            # 多个捕获组 → 取指定组或第一个
                            idx = ext.group if ext.group and ext.group < len(m) else 0
                            all_results.append(m[idx])
                        else:
                            all_results.append(m)
            except re.error:
                continue

        return ", ".join(all_results[:5]) if all_results else ""

    def _extract_kval(self, ext: Extractor, target: str,
                      status: int, headers: dict, body: str) -> str:
        """从 headers/cookies 中提取键值"""
        results = []

        for key in ext.kval:
            key_lower = key.lower()

            # 从 headers 中提取
            for h_key, h_val in headers.items():
                if h_key.lower() == key_lower:
                    results.append(h_val)
                    break

            # 从 cookies 中提取
            if key_lower.startswith("cookie_"):
                cookie_name = key_lower.replace("cookie_", "")
                cookie_header = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
                if cookie_name in cookie_header.lower():
                    # 解析 cookie 值
                    for part in cookie_header.split(";"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            if k.strip().lower() == cookie_name:
                                results.append(v.strip())

        return ", ".join(results) if results else ""

    def _extract_json(self, ext: Extractor, target: str,
                      status: int, headers: dict, body: str) -> str:
        """JSON 路径提取 (简化版，支持 dot notation)"""
        results = []

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return ""

        for path in ext.json:
            try:
                value = self._json_path(data, path)
                if value is not None:
                    results.append(str(value))
            except Exception:
                continue

        return ", ".join(results) if results else ""

    def _json_path(self, data, path: str):
        """
        简化的 JSONPath 解析
        支持: key.subkey, key[0], key[*].subkey
        """
        parts = path.replace("[", ".").replace("]", "").split(".")
        current = data

        for part in parts:
            if part == "*" or part == "":
                continue

            if isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx]
                except (ValueError, IndexError):
                    # 遍历数组
                    results = []
                    for item in current:
                        if isinstance(item, dict) and part in item:
                            results.append(item[part])
                    return results if results else None
            elif isinstance(current, dict):
                if part in current:
                    current = current[part]
                else:
                    return None
            else:
                return None

        return current
