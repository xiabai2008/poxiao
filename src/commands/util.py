"""编解码工具命令"""

import json

from src.utils.crypto_tools import OPERATIONS, auto_decode
from src.utils.output import Out, C


def cmd_util(args):
    """编解码 / 加解密工具"""
    if not args.util_action:
        Out.section("编解码工具", "🔧")
        Out.info("用法: poxiao util {encode|decode|hash|jwt-decode|auto}")
        Out.blank()
        Out._print("    poxiao util encode base64 hello")
        Out._print("    poxiao util decode hex 68656c6c6f")
        Out._print("    poxiao util hash md5 hello")
        Out._print("    poxiao util jwt-decode eyJhbGciOi...")
        Out._print("    poxiao util auto aGVsbG8=")
        Out.blank()
        Out._print(f"    {C.BOLD}支持的编码类型:{C.RESET}")
        for name in OPERATIONS:
            enc, dec = OPERATIONS[name]
            flags = f"{'E' if enc else '-'}{'D' if dec else '-'}"
            Out._print(f"      {C.DIM}{flags}{C.RESET} {name}")
        return

    if args.util_action == "auto":
        results = auto_decode(args.text)
        if not results:
            Out.warning("未能识别编码类型")
            return
        Out.section(f"自动识别结果 ({len(results)} 种可能)", "🔍")
        for enc_type, decoded, confidence in results:
            Out._print(f"    {C.BOLD}[{confidence.upper()}] {enc_type}:{C.RESET}")
            Out._print(f"      {decoded[:200]}")
            Out.blank()

    elif args.util_action == "encode":
        enc_type = args.type.lower()
        if enc_type not in OPERATIONS:
            Out.error(f"不支持的编码类型: {enc_type}")
            Out.info(f"支持: {', '.join(OPERATIONS.keys())}")
            return
        enc_func, _ = OPERATIONS[enc_type]
        if enc_func is None:
            Out.error(f"{enc_type} 不支持编码")
            return
        result = enc_func(args.text)
        Out.section(f"{enc_type} encode", "✓")
        Out._print(f"    {result}")

    elif args.util_action == "decode":
        dec_type = args.type.lower()
        if dec_type not in OPERATIONS:
            Out.error(f"不支持的解码类型: {dec_type}")
            Out.info(f"支持: {', '.join(OPERATIONS.keys())}")
            return
        _, dec_func = OPERATIONS[dec_type]
        if dec_func is None:
            Out.error(f"{dec_type} 不支持解码 (单向哈希)")
            return
        result = dec_func(args.text)
        Out.section(f"{dec_type} decode", "✓")
        if isinstance(result, dict):
            Out._print(f"    {json.dumps(result, indent=2, ensure_ascii=False)}")
        else:
            Out._print(f"    {result}")

    elif args.util_action == "hash":
        hash_type = args.type.lower()
        if hash_type not in OPERATIONS:
            Out.error(f"不支持的哈希类型: {hash_type}")
            return
        enc_func, _ = OPERATIONS[hash_type]
        result = enc_func(args.text)
        Out.section(f"{hash_type}({args.text})", "✓")
        Out._print(f"    {result}")

    elif args.util_action == "jwt-decode":
        from src.utils.crypto_tools import jwt_decode
        result = jwt_decode(args.token)
        Out.section("JWT 解码", "✓")
        Out._print(f"    {C.BOLD}Header:{C.RESET}")
        Out._print(f"      {json.dumps(result.get('header', {}), indent=2)}")
        Out._print(f"    {C.BOLD}Payload:{C.RESET}")
        Out._print(f"      {json.dumps(result.get('payload', {}), indent=2, ensure_ascii=False)}")
