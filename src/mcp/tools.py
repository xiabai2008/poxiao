"""破晓 PoXiao — MCP 工具定义与分发

每个工具直接调用现有引擎的同步封装方法（*_sync / asyncio.run 内部），
返回结构化 dict，由 server.py 序列化为 JSON-RPC 的 text content。

设计原则:
  - 纯 stdlib，不引入外部依赖（与 X3 / Q5 一致）
  - 工具返回结构化数据，便于 AI 消费
  - 不直接调用 CLI handler（避免横幅/进度条污染协议流）
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional


# ── 工具定义（用于 MCP tools/list）────────────────────────
# inputSchema 遵循 JSON Schema (draft-07)，便于客户端渲染参数 UI。
TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "scan_targets",
        "description": (
            "破晓核心扫描：对目标 URL/域名列表执行存活检测 + 技术栈指纹识别 + "
            "版本提取 + CVE 精确匹配 + 敏感路径发现（三层降噪）。返回每个目标的"
            "技术栈、版本、命中 CVE、敏感路径等结构化结果。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "目标 URL 或域名列表，如 ['https://example.com']",
                },
                "target_file": {
                    "type": "string",
                    "description": "可选：目标文件路径，每行一个（支持 # 注释）",
                },
                "concurrency": {"type": "integer", "default": 5, "description": "并发数"},
                "timeout": {"type": "number", "default": 5.0, "description": "HTTP 超时秒数"},
                "no_sensitive": {
                    "type": "boolean",
                    "default": False,
                    "description": "跳过敏感路径检测（更快）",
                },
            },
            "required": [],
        },
    },
    {
        "name": "check_alive",
        "description": "快速检测目标列表是否存活（HTTP HEAD 探测），返回存活统计与状态码。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "目标 URL 或域名列表",
                },
                "target_file": {"type": "string", "description": "可选：目标文件路径"},
                "concurrency": {"type": "integer", "default": 10},
                "timeout": {"type": "number", "default": 5.0},
            },
            "required": [],
        },
    },
    {
        "name": "subdomain_enum",
        "description": (
            "霜月子域名收集：crt.sh/certspotter/OTX 证书透明 + DNS 字典爆破 + "
            "泛解析检测 + 存活验证。返回子域名、IP、标题、分类等。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "根域名，如 example.com"},
                "no_crtsh": {"type": "boolean", "default": False, "description": "跳过证书透明源"},
                "no_brute": {"type": "boolean", "default": False, "description": "跳过 DNS 爆破"},
                "no_alive": {"type": "boolean", "default": False, "description": "跳过存活验证"},
                "timeout": {"type": "number", "default": 5.0},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "passive_recon",
        "description": (
            "春分被动信息收集（不主动触碰目标）：Whois + 备案 + DNS + 证书 + CDN/WAF "
            "+ IP 情报(Shodan/Censys/FOFA) + Wayback 历史 + GitHub 代码泄露。返回汇总情报。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标域名"},
                "quick": {"type": "boolean", "default": False, "description": "快速模式（仅 DNS+Whois+证书）"},
                "timeout": {"type": "number", "default": 10.0},
                "shodan_key": {"type": "string", "default": ""},
                "fofa_key": {"type": "string", "default": ""},
                "fofa_email": {"type": "string", "default": ""},
                "censys_id": {"type": "string", "default": ""},
                "censys_secret": {"type": "string", "default": ""},
                "github_token": {"type": "string", "default": ""},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "verify_target",
        "description": (
            "惊蛰漏洞自动验证：对单个目标验证默认口令、目录列表、Swagger、Git 泄露、"
            "配置文件泄露、Spring Actuator、API 端点、phpinfo 等。返回已验证发现与风险评分。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 URL，如 https://example.com"},
                "timeout": {"type": "number", "default": 8.0},
            },
            "required": ["target"],
        },
    },
    {
        "name": "poc_scan",
        "description": (
            "夏至 POC 模板扫描：用内置/自定义 Nuclei 风格模板扫描目标，匹配漏洞。 "
            "返回命中模板、严重级别、证据等。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标 URL 或目标文件"},
                "templates": {"type": "string", "default": "", "description": "模板目录或文件（默认内置库）"},
                "template_dir": {"type": "string", "default": "", "description": "额外模板目录"},
                "tags": {"type": "string", "default": "", "description": "按标签过滤（逗号分隔）"},
                "severity": {"type": "string", "default": "", "description": "按严重级别过滤（逗号分隔）"},
                "concurrency": {"type": "integer", "default": 10},
                "timeout": {"type": "number", "default": 10.0},
                "stealth": {"type": "boolean", "default": False, "description": "隐匿模式（代理池+UA 轮换）"},
                "waf_bypass": {"type": "boolean", "default": False, "description": "启用 WAF 绕过（默认关）"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "util_codec",
        "description": (
            "编解码/加解密工具：encode/decode/hash/jwt-decode/auto。支持 base64、hex、"
            "url、html、unicode、rot13、morse、md5/sha 系列、JWT 等。auto 可自动识别编码类型。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["encode", "decode", "hash", "jwt-decode", "auto"],
                    "description": "操作类型",
                },
                "type": {
                    "type": "string",
                    "description": "编码/哈希类型（encode/decode/hash 时必填），如 base64/md5/jwt",
                },
                "text": {"type": "string", "description": "待处理文本（auto 时为待识别文本）"},
                "token": {"type": "string", "description": "JWT token（action=jwt-decode 时使用）"},
            },
            "required": ["action", "text"],
        },
    },
]


# ── 结果辅助 ──────────────────────────────────────────────
def _ok(data: Any) -> Dict[str, Any]:
    """构造成功的 MCP tool 结果"""
    return {
        "content": [
            {"type": "text", "text": json.dumps(data, ensure_ascii=False, default=str)}
        ],
        "isError": False,
    }


def _err(msg: str) -> Dict[str, Any]:
    """构造失败的 MCP tool 结果"""
    return {
        "content": [
            {"type": "text", "text": json.dumps({"error": msg}, ensure_ascii=False)}
        ],
        "isError": True,
    }


def _split(value: Optional[str]) -> List[str]:
    """逗号/空格分隔字符串为列表，过滤空项"""
    if not value:
        return []
    return [v.strip() for v in str(value).replace(" ", ",").split(",") if v.strip()]


# ── 工具处理器 ────────────────────────────────────────────
def _t_scan_targets(args: Dict[str, Any]) -> Dict[str, Any]:
    from src.target.manager import TargetManager
    from src.dawn.engine import ScanEngine

    timeout = float(args.get("timeout", 5.0))
    concurrency = int(args.get("concurrency", 5))

    mgr = TargetManager(timeout=timeout, concurrency=concurrency)
    if args.get("target_file"):
        try:
            raw = mgr.load_from_file(args["target_file"])
        except FileNotFoundError as e:
            return _err(str(e))
    elif args.get("targets"):
        raw = mgr.load_from_list(args["targets"])
    else:
        return _err("请提供 targets 或 target_file")

    targets = mgr.deduplicate(raw)
    alive = mgr.check_alive_sync(targets)
    mgr.classify(alive)
    alive_urls = [t.url for t in alive if t.is_alive]

    engine = ScanEngine(
        timeout=timeout,
        concurrency=concurrency,
        enable_sensitive=not args.get("no_sensitive", False),
    )
    try:
        results = engine.scan_batch_sync(alive_urls) if alive_urls else []
    finally:
        asyncio.run(engine.aclose())

    return _ok({
        "total_targets": len(targets),
        "alive": len(alive_urls),
        "results": [r.to_dict() for r in results],
        "summary": mgr.summary(alive),
    })


def _t_check_alive(args: Dict[str, Any]) -> Dict[str, Any]:
    from src.target.manager import TargetManager

    timeout = float(args.get("timeout", 5.0))
    concurrency = int(args.get("concurrency", 10))

    mgr = TargetManager(timeout=timeout, concurrency=concurrency)
    if args.get("target_file"):
        try:
            raw = mgr.load_from_file(args["target_file"])
        except FileNotFoundError as e:
            return _err(str(e))
    elif args.get("targets"):
        raw = mgr.load_from_list(args["targets"])
    else:
        return _err("请提供 targets 或 target_file")

    targets = mgr.deduplicate(raw)
    alive = mgr.check_alive_sync(targets)
    return _ok({
        "total": len(targets),
        "alive": sum(1 for t in alive if t.is_alive),
        "targets": [t.url for t in alive if t.is_alive],
        "summary": mgr.summary(alive),
    })


def _t_subdomain_enum(args: Dict[str, Any]) -> Dict[str, Any]:
    from src.frostmoon.collector import ShuangYue

    domain = (args.get("domain") or "").strip()
    if not domain:
        return _err("请提供 domain")

    s = ShuangYue(timeout=float(args.get("timeout", 5.0)))
    subs = s.collect_sync(
        domain,
        use_crtsh=not args.get("no_crtsh", False),
        use_brute=not args.get("no_brute", False),
        check_alive=not args.get("no_alive", False),
    )
    return _ok({
        "domain": domain,
        "total": len(subs),
        "alive": sum(1 for x in subs if x.alive),
        "subdomains": [
            {
                "domain": x.domain,
                "alive": x.alive,
                "status_code": x.status_code,
                "title": x.title,
                "ip": x.ip,
                "category": x.category,
                "source": x.source,
            }
            for x in subs
        ],
        "summary": s.summary(subs),
    })


def _t_passive_recon(args: Dict[str, Any]) -> Dict[str, Any]:
    from src.vernalequinox.engine import ReconEngine

    domain = (args.get("domain") or "").strip()
    if not domain:
        return _err("请提供 domain")

    shodan_key = args.get("shodan_key", "") or ""
    fofa_key = args.get("fofa_key", "") or ""
    fofa_email = args.get("fofa_email", "") or ""
    censys_id = args.get("censys_id", "") or ""
    censys_secret = args.get("censys_secret", "") or ""
    github_token = args.get("github_token", "") or ""

    eng = ReconEngine(
        timeout=float(args.get("timeout", 10.0)),
        shodan_key=shodan_key,
        fofa_key=fofa_key,
        fofa_email=fofa_email,
        censys_id=censys_id,
        censys_secret=censys_secret,
        github_token=github_token,
        skip_shodan=not shodan_key,
        skip_fofa=not fofa_key,
    )
    if args.get("quick"):
        report = asyncio.run(eng.quick_recon(domain))
    else:
        report = asyncio.run(eng.full_recon(domain))
    return _ok(report.to_dict())


def _t_verify_target(args: Dict[str, Any]) -> Dict[str, Any]:
    from src.jingzhe.jingzhe import JingZhe

    target = (args.get("target") or "").strip()
    if not target:
        return _err("请提供 target")

    j = JingZhe(timeout=float(args.get("timeout", 8.0)))
    findings = j.verify_sync(target)
    return _ok({
        "target": target,
        "findings": [f.__dict__ for f in findings],
        "score": j.score(findings),
    })


def _t_poc_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    from src.xiazhi.loader import TemplateLoader
    from src.xiazhi.poc_engine import POCEngine

    target = (args.get("target") or "").strip()
    if not target:
        return _err("请提供 target")

    tags = _split(args.get("tags", ""))
    severity = _split(args.get("severity", ""))
    template_dir = args.get("templates", "") or ""
    extra_dir = args.get("template_dir", "") or ""

    loader = TemplateLoader(
        template_dir=template_dir,
        extra_dirs=[extra_dir] if extra_dir else None,
    )
    templates = loader.load_all(tags=tags or None, severity=severity or None)

    if not templates:
        return _ok({"target": target, "templates_loaded": 0, "findings": []})

    concurrency = int(args.get("concurrency", 10))
    eng = POCEngine(
        timeout=float(args.get("timeout", 10.0)),
        concurrency=concurrency,
        stealth=bool(args.get("stealth", False)),
        enable_waf_bypass=bool(args.get("waf_bypass", False)),
    )
    results = asyncio.run(
        eng.scan_targets(
            [target],
            templates,
            concurrency=concurrency,
            tags=tags or None,
            severity=severity or None,
        )
    )
    findings = []
    for _t, matches in results.items():
        for m in matches:
            findings.append(m.to_dict())

    return _ok({
        "target": target,
        "templates_loaded": len(templates),
        "findings": findings,
    })


def _t_util_codec(args: Dict[str, Any]) -> Dict[str, Any]:
    from src.utils.crypto_tools import OPERATIONS, auto_decode, jwt_decode

    action = (args.get("action") or "").strip().lower()
    text = args.get("text", "") or ""
    typ = (args.get("type") or "").strip().lower()

    if action == "auto":
        return _ok({
            "action": "auto",
            "results": [
                {"type": t, "decoded": d, "confidence": c}
                for t, d, c in auto_decode(text)
            ],
        })

    if action == "jwt-decode":
        token = args.get("token", "") or text
        return _ok({"action": "jwt-decode", "result": jwt_decode(token)})

    if action in ("encode", "decode", "hash"):
        if typ not in OPERATIONS:
            return _err(f"不支持的类型: {typ}（支持: {', '.join(OPERATIONS.keys())}）")
        enc_func, dec_func = OPERATIONS[typ]
        if action == "encode":
            if enc_func is None:
                return _err(f"{typ} 不支持编码")
            return _ok({"action": "encode", "type": typ, "result": enc_func(text)})
        if action == "decode":
            if dec_func is None:
                return _err(f"{typ} 为单向哈希，不支持解码")
            return _ok({"action": "decode", "type": typ, "result": dec_func(text)})
        # hash
        return _ok({"action": "hash", "type": typ, "result": enc_func(text)})

    return _err(f"未知 action: {action}（支持 encode/decode/hash/jwt-decode/auto）")


_HANDLERS = {
    "scan_targets": _t_scan_targets,
    "check_alive": _t_check_alive,
    "subdomain_enum": _t_subdomain_enum,
    "passive_recon": _t_passive_recon,
    "verify_target": _t_verify_target,
    "poc_scan": _t_poc_scan,
    "util_codec": _t_util_codec,
}


def dispatch_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """分发 MCP 工具调用，始终返回 {content, isError} 结构"""
    handler = _HANDLERS.get(name)
    if not handler:
        return _err(f"未知工具: {name}")
    try:
        return handler(arguments or {})
    except Exception as e:  # 工具内部异常转为 MCP 错误结果
        return _err(f"工具执行异常: {e}")
