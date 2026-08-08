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

import base64
import hashlib
import random
import re
import urllib.parse
from typing import List, Tuple, Optional, Any, Dict
from .template import Matcher


def _b64encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode()


def _b64decode(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


class MatcherEngine:
    """匹配器执行引擎"""

    @staticmethod
    def _expand(text: str, variables: Optional[Dict[str, Any]]) -> str:
        """展开 {{VariableName}} 模板变量（仅匹配期展开，不修改共享模板对象）"""
        if not variables or not text or "{{" not in text:
            return text
        for name, value in variables.items():
            text = text.replace(f"{{{{{name}}}}}", str(value))
        return text

    def match(self, matcher: Matcher,
              status_code: int,
              headers: dict,
              body: str,
              body_bytes: bytes = b"",
              url: str = "",
              variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        执行匹配，返回 (是否匹配, 匹配描述)

        Returns:
            (matched: bool, description: str)
        """
        # 获取匹配目标内容
        target = self._get_target(matcher.part, status_code, headers, body, body_bytes)

        # 二进制匹配必须使用原始字节（resp.content），
        # 文本解码已损坏二进制内容（zip/PE 头等），不能再 encode 重建。
        if matcher.type == "binary":
            raw = body_bytes or body.encode("utf-8", errors="ignore")
            matched, desc = self._match_binary(matcher, raw, status_code, headers, body)

            # 取反
            if matcher.negative:
                matched = not matched
                if matched:
                    desc = f"NOT ({desc})"
            return matched, desc

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

        matched, desc = handler(matcher, target, status_code, headers, body, variables)

        # 取反
        if matcher.negative:
            matched = not matched
            if matched:
                desc = f"NOT ({desc})"

        return matched, desc

    def match_all(self, matchers: List[Matcher], condition: str,
                  status_code: int, headers: dict, body: str,
                  body_bytes: bytes = b"",
                  variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
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
            matched, desc = self.match(m, status_code, headers, body, body_bytes, variables=variables)
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
                    status: int, headers: dict, body: str,
                    variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """关键词匹配"""
        if not matcher.words:
            return False, "no words to match"

        if not matcher.case_sensitive:
            target_lower = target.lower()
            matches = [w for w in matcher.words
                       if self._expand(w, variables).lower() in target_lower]
        else:
            matches = [w for w in matcher.words
                       if self._expand(w, variables) in target]

        if matcher.condition == "and":
            matched = len(matches) == len(matcher.words)
        else:  # or
            matched = len(matches) > 0

        if matched:
            return True, f"word matched: {matches[:3]}"
        return False, "no word matched"

    def _match_status(self, matcher: Matcher, target: str,
                      status: int, headers: dict, body: str,
                      variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """状态码匹配"""
        if not matcher.status:
            return False, "no status to match"

        matched = status in matcher.status
        return matched, f"status {status} {'in' if matched else 'not in'} {matcher.status}"

    def _match_regex(self, matcher: Matcher, target: str,
                     status: int, headers: dict, body: str,
                     variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """正则匹配"""
        if not matcher.regex:
            return False, "no regex to match"

        all_matches = []
        for pattern in matcher.regex:
            try:
                flags = re.IGNORECASE if not matcher.case_sensitive else 0
                found = re.findall(self._expand(pattern, variables), target, flags)
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
                    status: int, headers: dict, body: str,
                    variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
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
                   status: int, headers: dict, body: str,
                   variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """DSL 表达式匹配 (安全版，无 eval)"""
        if not matcher.dsl:
            return False, "no DSL expression"

        # DSL 变量替换
        dsl_vars = {
            "status_code": status,
            "content_length": len(body),
            "body": body,
            "header": "\n".join(f"{k}: {v}" for k, v in headers.items()),
        }
        if variables:
            dsl_vars.update(variables)

        results = []
        for expr in matcher.dsl:
            try:
                result = self._safe_eval_dsl(expr, dsl_vars)
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

        # 危险关键字检查
        DANGEROUS = ['import', 'exec', 'eval', 'open', '__', 'os.', 'sys.',
                     'subprocess', 'builtins', 'getattr', 'setattr', 'delattr']
        expr_lower = expr.lower()
        for kw in DANGEROUS:
            if kw in expr_lower:
                return False

        # P2-2: 白名单函数展开（支持嵌套调用），再走比较/contains 逻辑
        resolved = self._expand_dsl_functions(expr, variables)

        # 替换变量（仅剩未函数化的裸变量，如 status_code）
        for name, val in variables.items():
            resolved = resolved.replace(name, repr(val) if isinstance(val, str) else str(val))

        # 支持 && / || 组合（nuclei DSL 常用）
        if " && " in resolved:
            return all(self._safe_eval_dsl(part, variables) for part in resolved.split(" && "))
        if " || " in resolved:
            return any(self._safe_eval_dsl(part, variables) for part in resolved.split(" || "))

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

        # 引号字符串字面量（函数展开产物）：非空即为真
        stripped = resolved.strip()
        if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ("'", '"'):
            return True

        return False

    # ── P2-2: DSL 白名单函数 ───────────────────────────
    _FUNC_WHITELIST = {
        # 字符串
        "to_lower": lambda s: str(s).lower(),
        "to_upper": lambda s: str(s).upper(),
        "trim": lambda s: str(s).strip(),
        "len": lambda s: len(str(s)),
        "contains": lambda a, b: str(b) in str(a),
        "icontains": lambda a, b: str(b).lower() in str(a).lower(),
        "starts_with": lambda a, b: str(a).startswith(str(b)),
        "ends_with": lambda a, b: str(a).endswith(str(b)),
        "replace": lambda a, b, c: str(a).replace(str(b), str(c)),
        "concat": lambda *args: "".join(str(a) for a in args),
        "substr": lambda s, start, end=None: str(s)[int(start):int(end)] if end is not None else str(s)[int(start):],
        # 编码
        "base64": lambda s: _b64encode(str(s)),
        "base64_decode": lambda s: _b64decode(str(s)),
        "url_encode": lambda s: urllib.parse.quote(str(s), safe=""),
        "url_decode": lambda s: urllib.parse.unquote(str(s)),
        "hex_encode": lambda s: str(s).encode("utf-8").hex(),
        "hex_decode": lambda s: bytes.fromhex(str(s)).decode("utf-8", errors="ignore"),
        # 哈希（检测用，非安全用途）
        "md5": lambda s: hashlib.md5(str(s).encode("utf-8")).hexdigest(),
        "sha1": lambda s: hashlib.sha1(str(s).encode("utf-8")).hexdigest(),
        "sha256": lambda s: hashlib.sha256(str(s).encode("utf-8")).hexdigest(),
        # 随机
        "rand_int": lambda a=0, b=99999999: str(random.randint(int(a), int(b))),
        "rand_base": lambda length=8, charset="abcdefghijklmnopqrstuvwxyz0123456789":
            "".join(random.choice(str(charset)) for _ in range(int(length))),
        "rand_char": lambda s="abcdefghijklmnopqrstuvwxyz":
            random.choice(str(s)),
        # 判断
        "regex": lambda s, p: bool(re.search(str(p), str(s))),
        "printable": lambda s: "".join(c for c in str(s) if c.isprintable()),
    }

    def _expand_dsl_functions(self, expr: str, variables: dict) -> str:
        """递归展开白名单函数调用为字面量（repr 形式，供 contains/比较使用）

        未知函数/非法参数保持原样（后续按无函数表达式处理，不会误报）。
        """
        func_re = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\(([^()]*)\)")
        for _ in range(8):  # 嵌套深度上限
            m = func_re.search(expr)
            if not m:
                break
            name, args_str = m.group(1), m.group(2)
            fn = self._FUNC_WHITELIST.get(name)
            if fn is None:
                break  # 未知函数：整体保留，等待外部逻辑处理
            args = self._split_dsl_args(args_str)
            resolved_args = []
            for a in args:
                a = a.strip()
                if len(a) >= 2 and a[0] == a[-1] and a[0] in ("'", '"'):
                    resolved_args.append(a[1:-1])
                elif a in variables:
                    resolved_args.append(variables[a])
                else:
                    try:
                        resolved_args.append(float(a) if "." in a else int(a))
                    except ValueError:
                        resolved_args.append(a)
            try:
                value = fn(*resolved_args)
            except Exception:
                value = ""
            expr = expr[:m.start()] + repr(value) + expr[m.end():]
        return expr

    @staticmethod
    def _split_dsl_args(args_str: str) -> list:
        """拆分函数参数（支持引号内逗号）"""
        args, cur, quote = [], "", None
        for ch in args_str:
            if quote:
                cur += ch
                if ch == quote:
                    quote = None
            elif ch in ("'", '"'):
                quote = ch
                cur += ch
            elif ch == ",":
                args.append(cur)
                cur = ""
            else:
                cur += ch
        if cur.strip():
            args.append(cur)
        return args

    def _match_binary(self, matcher: Matcher, body_bytes: bytes,
                      status: int, headers: dict, body: str) -> Tuple[bool, str]:
        """二进制特征匹配（针对原始响应字节）"""
        if not matcher.binary:
            return False, "no binary pattern"

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
                      status: int, headers: dict, body: str,
                      variables: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
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
            wanted = self._expand(matcher.header_value, variables)
            matched = wanted.lower() in header_val.lower()
            return matched, f"header '{matcher.header}' {'contains' if matched else 'does not contain'} '{wanted}'"
        else:
            return True, f"header '{matcher.header}' present: {header_val[:50]}"
