"""
匹配器 (Matcher) — 判断响应是否符合漏洞特征
=============================================

支持的匹配类型:
  - word:     关键词匹配 (支持多词 + or/and 条件)
  - status:   HTTP 状态码匹配
  - regex:    正则表达式匹配
  - size:     响应体大小匹配
  - header:   响应头匹配
  - binary:   二进制特征匹配 (十六进制)
  - dsl:      DSL 表达式匹配 (高级)
"""

import re
from typing import List, Tuple, Optional, Any
from .template import Matcher


class MatcherEngine:
    """匹配器执行引擎"""

    def match(self, matcher: Matcher,
              status_code: int,
              headers: dict,
              body: str,
              body_bytes: bytes = b"",
              url: str = "") -> Tuple[bool, str]:
        """
        执行匹配，返回 (是否匹配, 匹配描述)

        Returns:
            (matched: bool, description: str)
        """
        # 获取匹配目标内容
        target = self._get_target(matcher.part, status_code, headers, body, body_bytes)

        # 执行匹配
        handler = {
            "word": self._match_word,
            "status": self._match_status,
            "regex": self._match_regex,
            "size": self._match_size,
            "dsl": self._match_dsl,
            "binary": self._match_binary,
            "header": self._match_header,
        }.get(matcher.type)

        if not handler:
            return False, f"Unknown matcher type: {matcher.type}"

        matched, desc = handler(matcher, target, status_code, headers, body)

        # 取反
        if matcher.negative:
            matched = not matched
            if matched:
                desc = f"NOT ({desc})"

        return matched, desc

    def match_all(self, matchers: List[Matcher], condition: str,
                  status_code: int, headers: dict, body: str,
                  body_bytes: bytes = b"") -> Tuple[bool, str]:
        """
        执行多个匹配器

        Args:
            matchers: 匹配器列表
            condition: "and" 或 "or"

        Returns:
            (all_matched: bool, combined_description: str)
        """
        if not matchers:
            return True, "no matchers (always pass)"

        results = []
        descriptions = []

        for m in matchers:
            matched, desc = self.match(m, status_code, headers, body, body_bytes)
            results.append(matched)
            if matched:
                descriptions.append(desc)

        if condition == "and":
            all_matched = all(results)
            desc = " AND ".join(descriptions) if all_matched else "some matchers failed"
        else:  # or
            all_matched = any(results)
            desc = " OR ".join(descriptions) if all_matched else "no matchers matched"

        return all_matched, desc

    def _get_target(self, part: str, status: int, headers: dict,
                    body: str, body_bytes: bytes) -> str:
        """根据 part 选择匹配目标"""
        if part == "header":
            return "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif part == "all":
            header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
            return f"{header_str}\n\n{body}"
        else:  # body (default)
            return body

    # ── 具体匹配器 ──────────────────────────────────

    def _match_word(self, matcher: Matcher, target: str,
                    status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """关键词匹配"""
        if not matcher.words:
            return False, "no words to match"

        if not matcher.case_sensitive:
            target_lower = target.lower()
            matches = [w for w in matcher.words if w.lower() in target_lower]
        else:
            matches = [w for w in matcher.words if w in target]

        if matcher.condition == "and":
            matched = len(matches) == len(matcher.words)
        else:  # or
            matched = len(matches) > 0

        if matched:
            return True, f"word matched: {matches[:3]}"
        return False, "no word matched"

    def _match_status(self, matcher: Matcher, target: str,
                      status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """状态码匹配"""
        if not matcher.status:
            return False, "no status to match"

        matched = status in matcher.status
        return matched, f"status {status} {'in' if matched else 'not in'} {matcher.status}"

    def _match_regex(self, matcher: Matcher, target: str,
                     status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """正则匹配"""
        if not matcher.regex:
            return False, "no regex to match"

        all_matches = []
        for pattern in matcher.regex:
            try:
                flags = re.IGNORECASE if not matcher.case_sensitive else 0
                found = re.findall(pattern, target, flags)
                if found:
                    all_matches.append(pattern)
            except re.error:
                continue

        if matcher.condition == "and":
            matched = len(all_matches) == len(matcher.regex)
        else:
            matched = len(all_matches) > 0

        if matched:
            return True, f"regex matched: {all_matches[:3]}"
        return False, "no regex matched"

    def _match_size(self, matcher: Matcher, target: str,
                    status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """响应体大小匹配"""
        size = len(body.encode("utf-8", errors="ignore"))

        if not matcher.size:
            return False, "no size range"

        if len(matcher.size) == 1:
            matched = size == matcher.size[0]
        elif len(matcher.size) == 2:
            matched = matcher.size[0] <= size <= matcher.size[1]
        else:
            matched = size in matcher.size

        return matched, f"size {size} {'matches' if matched else 'does not match'} {matcher.size}"

    def _match_dsl(self, matcher: Matcher, target: str,
                   status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """DSL 表达式匹配 (安全版，无 eval)"""
        if not matcher.dsl:
            return False, "no DSL expression"

        # DSL 变量替换
        variables = {
            "status_code": status,
            "content_length": len(body),
            "body": body,
            "header": "\n".join(f"{k}: {v}" for k, v in headers.items()),
        }

        results = []
        for expr in matcher.dsl:
            try:
                result = self._safe_eval_dsl(expr, variables)
                results.append(result)
            except Exception:
                results.append(False)

        if matcher.condition == "and":
            matched = all(results)
        else:
            matched = any(results)

        return matched, f"DSL {'passed' if matched else 'failed'}: {matcher.dsl}"

    def _safe_eval_dsl(self, expr: str, variables: dict) -> bool:
        """
        安全的 DSL 表达式求值 (不使用 eval)

        支持:
          - 比较运算: ==, !=, >, <, >=, <=
          - 包含检查: contains, in
          - 变量替换: status_code, content_length, body, header
        """
        import operator
        import re

        # 危险关键字检查
        DANGEROUS = ['import', 'exec', 'eval', 'open', '__', 'os.', 'sys.',
                     'subprocess', 'builtins', 'getattr', 'setattr', 'delattr']
        expr_lower = expr.lower()
        for kw in DANGEROUS:
            if kw in expr_lower:
                return False

        # 替换变量
        resolved = expr
        for name, val in variables.items():
            resolved = resolved.replace(name, repr(val) if isinstance(val, str) else str(val))

        # 安全操作符
        SAFE_OPS = {
            '==': operator.eq,
            '!=': operator.ne,
            '>=': operator.ge,
            '<=': operator.le,
            '>':  operator.gt,
            '<':  operator.lt,
        }

        # 处理 contains
        if ' contains ' in resolved:
            left, right = resolved.split(' contains ', 1)
            left = left.strip().strip("'\"")
            right = right.strip().strip("'\"")
            return right in left

        # 处理 in
        if ' in ' in resolved and 'contains' not in resolved:
            left, right = resolved.split(' in ', 1)
            left = left.strip().strip("'\"")
            right = right.strip().strip("'\"")
            return left in right

        # 处理比较运算 (按长度排序，先匹配 >= <= 再匹配 > <)
        for op_str in sorted(SAFE_OPS.keys(), key=len, reverse=True):
            if op_str in resolved:
                parts = resolved.split(op_str, 1)
                if len(parts) == 2:
                    left = parts[0].strip().strip("'\"")
                    right = parts[1].strip().strip("'\"")
                    # 尝试转数字
                    try:
                        left_f, right_f = float(left), float(right)
                        return SAFE_OPS[op_str](left_f, right_f)
                    except (ValueError, TypeError):
                        pass
                    # 字符串比较
                    return SAFE_OPS[op_str](left, right)

        # 布尔值
        resolved_lower = resolved.strip().lower()
        if resolved_lower in ('true', '1', 'yes'):
            return True
        if resolved_lower in ('false', '0', 'no', ''):
            return False

        return False

    def _match_binary(self, matcher: Matcher, target: str,
                      status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """二进制特征匹配"""
        if not matcher.binary:
            return False, "no binary pattern"

        body_bytes = body.encode("utf-8", errors="ignore")
        matches = []
        for hex_pattern in matcher.binary:
            try:
                pattern_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
                if pattern_bytes in body_bytes:
                    matches.append(hex_pattern[:20])
            except ValueError:
                continue

        matched = len(matches) > 0
        return matched, f"binary {'matched' if matched else 'no match'}: {matches}"

    def _match_header(self, matcher: Matcher, target: str,
                      status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """响应头匹配"""
        if not matcher.header:
            return False, "no header to match"

        # 查找 header (大小写不敏感)
        header_val = ""
        for k, v in headers.items():
            if k.lower() == matcher.header.lower():
                header_val = v
                break

        if not header_val:
            return False, f"header '{matcher.header}' not found"

        if matcher.header_value:
            matched = matcher.header_value.lower() in header_val.lower()
            return matched, f"header '{matcher.header}' {'contains' if matched else 'does not contain'} '{matcher.header_value}'"
        else:
            return True, f"header '{matcher.header}' present: {header_val[:50]}"
