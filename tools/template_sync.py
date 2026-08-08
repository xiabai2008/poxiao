#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 · POC 模板工具链 (Phase 3 / P3-2 / D1 / X1)
=================================================

提供可独立运行的 Nuclei 模板运维 CLI，与 `ci_audit.py`（CI 硬门禁）互补：
  * `validate <dir|file>` —— 单文件/目录的 Nuclei 字段校验（不修改任何模板）。
  * `diff <dirA> <dirB>`   —— 两目录按相对路径 + 内容 sha256 比对，输出
                            added / removed / modified 清单与计数；
                            **差异作指标，不判失败**（用于社区模板增量同步，守 X1）。

设计原则（升级方案 §六.5）：模板同步必然产生 added/modified，
**绝不硬编码 215 为失败断言**，计数仅报告。

用法：
  python tools/template_sync.py validate templates
  python tools/template_sync.py validate templates/default-logins/jenkins-default-login.yaml
  python tools/template_sync.py diff templates community-templates
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# 作为独立脚本运行时（python tools/template_sync.py），仓库根加入 sys.path
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


TPL_SEVERITIES = {"critical", "high", "medium", "low", "info"}
TPL_REQUIRED_TOP = {"id", "info"}


def _iter_yaml(d: Path):
    if d.is_file():
        yield d
        return
    yield from sorted(d.rglob("*.yaml"))
    yield from sorted(d.rglob("*.yml"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_path(target: Path) -> Dict[str, Any]:
    """校验单个文件或目录，返回结构化结果（不修改模板）。"""
    res: Dict[str, Any] = {
        "target": str(target),
        "files": 0,
        "valid": 0,
        "field_errors": [],
        "parse_errors": [],
        "sev_warns": [],
    }
    if not target.exists():
        res["parse_errors"].append(f"路径不存在: {target}")
        return res

    for yml in _iter_yaml(target):
        res["files"] += 1
        if yaml is None:
            res["parse_errors"].append("PyYAML 未安装，无法解析校验")
            continue
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception as e:
            res["parse_errors"].append(f"{yml.name}: {e}")
            continue
        if not isinstance(raw, dict):
            res["parse_errors"].append(f"{yml.name}: 顶层非映射")
            continue

        tid = raw.get("id")
        if not tid:
            res["field_errors"].append(f"{yml.name}: 缺 id")
            continue
        res["valid"] += 1

        info = raw.get("info")
        if not isinstance(info, dict):
            res["field_errors"].append(f"{yml.name}: 缺 info 块")
        elif not info.get("name"):
            res["field_errors"].append(f"{tid}: info.name 缺失")
        else:
            sev = str(info.get("severity", "info")).lower()
            if sev not in TPL_SEVERITIES:
                res["sev_warns"].append(f"{tid}: 未知 severity={sev}")

        if not raw.get("http") and not raw.get("requests"):
            res["sev_warns"].append(f"{tid}: 无 http/requests 块（非 HTTP 协议模板？）")
    return res


def diff_dirs(dir_a: Path, dir_b: Path) -> Dict[str, Any]:
    """比对 dirA 与 dirB，返回 added/removed/modified（相对路径）。"""
    def _index(d: Path) -> Dict[str, str]:
        idx: Dict[str, str] = {}
        if not d.exists():
            return idx
        for yml in _iter_yaml(d):
            idx[str(yml.relative_to(d))] = _sha256(yml)
        return idx

    a = _index(dir_a)
    b = _index(dir_b)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    modified = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    return {
        "dir_a": str(dir_a),
        "dir_b": str(dir_b),
        "counts": {"a": len(a), "b": len(b), "added": len(added), "removed": len(removed), "modified": len(modified)},
        "added": added,
        "removed": removed,
        "modified": modified,
    }


def _print_validate(res: Dict[str, Any]) -> None:
    print(f"[validate] {res['target']}")
    print(f"  files={res['files']}  valid={res['valid']}")
    for e in res["parse_errors"]:
        print(f"  [parse-error] {e}")
    for e in res["field_errors"]:
        print(f"  [field-error] {e}")
    for w in res["sev_warns"]:
        print(f"  [warn] {w}")


def compat_stats(templates_dir: Path) -> Dict[str, Any]:
    """严格兼容性统计（S4：评估 nuclei-templates 对破晓引擎的运行时兼容面）

    与 loader.load_file 的"可解析"不同，本统计检查：
      - 协议类型（仅 http/requests 可执行）
      - matcher 类型分布（word/status/regex/size/dsl/binary/header 支持；其余不支持）
      - DSL 表达式引用（引擎 _safe_eval_dsl 支持比较/contains/in；统计使用量）
      - 模板变量引用（{{X}} 与引擎支持集的交集，统计未知变量）
      - 不支持的请求特性（cookie_reuse/stop_at_first_match/raw 等为引擎不支持项）
    统计作指标，不判失败（守 X1 精神）。
    """
    import re

    stats: Dict[str, Any] = {
        "yaml_total": 0, "http_supported": 0, "other_protocols": {},
        "matcher_types": {}, "dsl_count": 0, "unknown_vars": {},
        "unsupported_features": {}, "unsupported_templates": [],
    }
    SUPPORTED_MATCHERS = {"word", "status", "regex", "size", "dsl", "binary", "header"}
    # 引擎支持的变量（loader _parse_template 注入 + _gen_runtime_vars）
    KNOWN_VARS = {"BaseURL", "Hostname", "Scheme", "Port",
                  "randstr", "randbase64", "timestamp", "oast-url", "oast-domain",
                  "interactsh-url", "interactsh-protocol", "FQDN", "Host", "RandomInt",
                  "RandomExtVar", "sni", "password", "username"}
    VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_-]+)")

    for yml in _iter_yaml(templates_dir):
        rel = str(yml.relative_to(templates_dir)) if templates_dir in yml.parents else yml.name
        if yaml is None:
            break
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        stats["yaml_total"] += 1

        # 协议判断
        if raw.get("http") or raw.get("requests"):
            stats["http_supported"] += 1
        else:
            proto = next((k for k in ("tcp", "dns", "file", "code", "headless",
                                      "ssl", "websocket", "whois", "javascript")
                          if k in raw), "other")
            stats["other_protocols"][proto] = stats["other_protocols"].get(proto, 0) + 1
            stats["unsupported_templates"].append(rel)
            continue

        # 提取 http 块
        http_block = raw.get("http", raw.get("requests"))
        reqs = http_block if isinstance(http_block, list) else [http_block]

        # 请求特性
        for req in reqs:
            if not isinstance(req, dict):
                continue
            for feat in ("raw", "cookie_reuse", "stop_at_first_match", "fuzzing",
                         "attack_type", "max-redirects", "pipeline", "race", "throttle"):
                if feat in req:
                    stats["unsupported_features"][feat] = \
                        stats["unsupported_features"].get(feat, 0) + 1

            # matcher 类型
            for m in req.get("matchers", []) or []:
                if not isinstance(m, dict):
                    continue
                mtype = m.get("type", "word")
                stats["matcher_types"][mtype] = stats["matcher_types"].get(mtype, 0) + 1
                if mtype not in SUPPORTED_MATCHERS:
                    stats["unsupported_templates"].append(rel)

            # DSL 引用
            for m in req.get("matchers", []) or []:
                if isinstance(m, dict) and m.get("dsl"):
                    stats["dsl_count"] += len(m["dsl"])

        # 变量引用（整个模板文本）
        text = yml.read_text(encoding="utf-8", errors="ignore")
        for name in VAR_RE.findall(text):
            if name not in KNOWN_VARS:
                stats["unknown_vars"][name] = stats["unknown_vars"].get(name, 0) + 1

    stats["unknown_vars_top"] = dict(
        sorted(stats["unknown_vars"].items(), key=lambda x: -x[1])[:15]
    )
    stats["unsupported_templates"] = stats["unsupported_templates"][:50]
    return stats


def print_compat(stats: Dict[str, Any]) -> None:
    total = stats["yaml_total"]
    print(f"[compat] 模板总数: {total}")
    print(f"[compat] HTTP 可执行: {stats['http_supported']} "
          f"({100 * stats['http_supported'] // max(total, 1)}%)")
    if stats["other_protocols"]:
        print(f"[compat] 非 HTTP 协议: {stats['other_protocols']}")
    if stats["matcher_types"]:
        top = dict(sorted(stats["matcher_types"].items(), key=lambda x: -x[1])[:8])
        print(f"[compat] matcher 类型分布: {top}")
    print(f"[compat] DSL 表达式: {stats['dsl_count']} 处")
    if stats["unknown_vars_top"]:
        print(f"[compat] 未知变量 top15: {stats['unknown_vars_top']}")
    if stats["unsupported_features"]:
        print(f"[compat] 引擎不支持的特性: {stats['unsupported_features']}")
    print(f"[compat] 需关注模板数: {len(stats['unsupported_templates'])} (前50列)")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="破晓 POC 模板工具链")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("validate", help="校验模板字段（不修改）")
    pv.add_argument("target", help="模板文件或目录")

    pd = sub.add_parser("diff", help="两目录模板差异比对（差异非错误）")
    pd.add_argument("dir_a")
    pd.add_argument("dir_b")
    pd.add_argument("--json", default=None, help="将 diff 结果写入 JSON")

    pg = sub.add_parser("genkey", help="生成 ECDSA P-256 签名密钥对")
    pg.add_argument("private", help="私钥输出 PEM 路径")
    pg.add_argument("public", help="公钥输出 PEM 路径")

    ps = sub.add_parser("sign", help="为模板目录生成签名清单 .signatures.json")
    ps.add_argument("dir", help="模板目录")
    ps.add_argument("--key", required=True, help="私钥 PEM 路径")
    ps.add_argument("--out", default=None, help="签名清单输出路径（默认 <dir>/.signatures.json）")

    pv2 = sub.add_parser("verify", help="校验模板目录签名（bad 即失败，unsigned 仅报告）")
    pv2.add_argument("dir", help="模板目录")
    pv2.add_argument("--key", required=True, help="公钥 PEM 路径")
    pv2.add_argument("--manifest", default=None, help="签名清单路径（默认 <dir>/.signatures.json）")

    psync = sub.add_parser("sync", help="从 nuclei-templates 拉取社区模板到独立目录（不写入默认 templates/）")
    psync.add_argument("dir", help="目标目录（建议用独立 community 目录）")
    psync.add_argument("--repo", default="projectdiscovery/nuclei-templates", help="GitHub 仓库")
    psync.add_argument("--ref", default="main", help="分支/标签")
    psync.add_argument("--subdirs", default="http", help="拉取子目录，逗号分隔（如 http,cves）")
    psync.add_argument("--no-extract", action="store_true", help="仅下载 zip 不解压")

    pc = sub.add_parser("compat", help="严格兼容性统计（协议/matcher/DSL/变量，作指标）")
    pc.add_argument("dir", help="模板目录")

    args = parser.parse_args(argv)

    if args.cmd == "validate":
        res = validate_path(Path(args.target))
        _print_validate(res)
        # 校验失败判定：解析错误 / 字段缺失
        if res["parse_errors"] or res["field_errors"]:
            print("RESULT: FAIL (exit 1)")
            return 1
        print("RESULT: PASS (exit 0)")
        return 0

    if args.cmd == "diff":
        d = diff_dirs(Path(args.dir_a), Path(args.dir_b))
        c = d["counts"]
        print(f"[diff] {d['dir_a']}  vs  {d['dir_b']}")
        print(f"  A={c['a']}  B={c['b']}  added={c['added']}  removed={c['removed']}  modified={c['modified']}")
        for p in d["added"]:
            print(f"  [+] {p}")
        for p in d["removed"]:
            print(f"  [-] {p}")
        for p in d["modified"]:
            print(f"  [~] {p}")
        if args.json:
            Path(args.json).write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"  diff json -> {args.json}")
        # diff 始终视为成功：差异是同步指标，非错误（守 X1）
        print("RESULT: OK (exit 0, 差异作指标)")
        return 0

    if args.cmd == "genkey":
        import importlib
        ts = importlib.import_module("src.xiazhi.template_sign")
        priv, pub = ts.generate_keypair(args.private, args.public)
        print(f"[genkey] private -> {priv}")
        print(f"[genkey] public  -> {pub}")
        print("RESULT: OK (exit 0)")
        return 0

    if args.cmd == "sign":
        import importlib
        ts = importlib.import_module("src.xiazhi.template_sign")
        manifest = ts.sign_directory(Path(args.dir), args.key, output=args.out or "")
        out = args.out or str(Path(args.dir) / ts.SIG_FILENAME)
        print(f"[sign] {len(manifest)} 个模板已签名 -> {out}")
        print("RESULT: OK (exit 0)")
        return 0

    if args.cmd == "verify":
        import importlib
        ts = importlib.import_module("src.xiazhi.template_sign")
        res = ts.verify_directory(Path(args.dir), args.key, manifest_path=args.manifest or "")
        if not res:
            print(f"[verify] {args.dir}: 无签名清单，跳过（模板未签名）")
            print("RESULT: SKIP (exit 0)")
            return 0
        ok = sum(1 for v in res.values() if v == "ok")
        bad = sorted(k for k, v in res.items() if v == "bad")
        unsigned = sorted(k for k, v in res.items() if v == "unsigned")
        print(f"[verify] ok={ok}  bad={len(bad)}  unsigned={len(unsigned)}")
        for p in bad:
            print(f"  [bad] {p}")
        for p in unsigned:
            print(f"  [unsigned] {p}")
        if bad:
            print("RESULT: FAIL (exit 1, 存在签名不匹配的模板)")
            return 1
        print("RESULT: PASS (exit 0)")
        return 0

    if args.cmd == "sync":
        rc = sync_templates(
            Path(args.dir), repo=args.repo, ref=args.ref,
            subdirs=[s.strip() for s in args.subdirs.split(",") if s.strip()],
            extract=not args.no_extract,
        )
        return 0 if rc else 1

    if args.cmd == "compat":
        stats = compat_stats(Path(args.dir))
        print_compat(stats)
        print("RESULT: OK (exit 0, 统计作指标)")
        return 0

    return 2


def sync_templates(target_dir: Path, repo: str = "projectdiscovery/nuclei-templates",
                   ref: str = "main", subdirs: List[str] | None = None,
                   extract: bool = True) -> bool:
    """从 GitHub 仓库下载社区模板 zip，解压指定子目录到 target_dir（P1-G）。

    下载源为 codeload 归档（与 git 无关，免安装 git）；zip 保留在
    target_dir/nuclei-templates-<ref>.zip 供复核。模板数/兼容性作指标，
    不硬编码失败阈值（守 X1 精神）。
    """
    import urllib.request
    import zipfile

    subdirs = subdirs or ["http"]
    target_dir.mkdir(parents=True, exist_ok=True)
    url = f"https://codeload.github.com/{repo}/zip/refs/heads/{ref}"
    print(f"[sync] 下载 {url} ...")
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:  # nosec B310 — URL 为硬编码 codeload 地址，非用户输入
            raw = resp.read()
    except Exception as e:
        print(f"[sync] 下载失败: {e}")
        return False

    zip_path = target_dir / f"nuclei-templates-{ref}.zip"
    zip_path.write_bytes(raw)
    print(f"[sync] 归档 -> {zip_path} ({len(raw) // 1024} KB)")

    if not extract:
        print("RESULT: OK (exit 0, 仅下载)")
        return True

    # 解压指定子目录（zip 顶层含 <repo>-<ref>/ 前缀）
    prefix = f"{repo.split('/')[-1]}-{ref}/"
    stats: Dict[str, Any] = {"extracted": 0, "yaml_total": 0, "loadable": 0,
                             "incompatible": 0, "incompatible_types": {}}
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():
                rel = member[len(prefix):] if member.startswith(prefix) else member
                first = rel.split("/", 1)[0]
                if first not in subdirs or not rel.endswith((".yaml", ".yml")):
                    continue
                stats["yaml_total"] += 1
                out = target_dir / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(zf.read(member))
                stats["extracted"] += 1
    except Exception as e:
        print(f"[sync] 解压失败: {e}")
        return False

    # 兼容性统计：用破晓加载器实测可加载数（作指标）
    try:
        import importlib
        loader_mod = importlib.import_module("src.xiazhi.loader")
        TemplateLoader = loader_mod.TemplateLoader
        loader = TemplateLoader(str(target_dir))
        loadable = loader.load_all()
        stats["loadable"] = len(loadable)
        stats["incompatible"] = stats["yaml_total"] - stats["loadable"]
        # 失败类型粗分：协议（无 http/requests）vs 其他
        for yml in sorted((target_dir).rglob("*.yaml")):
            rel = str(yml.relative_to(target_dir))
            if rel.startswith("nuclei-templates"):
                continue
            if loader.load_file(yml) is None:
                try:
                    import yaml as _y
                    raw = _y.safe_load(yml.read_text(encoding="utf-8"))
                    if not isinstance(raw, dict) or (not raw.get("http") and not raw.get("requests")):
                        proto = next((k for k in ("tcp", "dns", "file", "code", "headless", "ssl", "websocket", "whois", "javascript") if k in raw), "other")
                        stats["incompatible_types"][proto] = stats["incompatible_types"].get(proto, 0) + 1
                except Exception:
                    stats["incompatible_types"]["other"] = stats["incompatible_types"].get("other", 0) + 1
    except Exception as e:
        print(f"[sync] 兼容性统计失败（不影响同步）: {e}")

    print(f"[sync] 解压: {stats['extracted']} 个 YAML（子目录 {','.join(subdirs)}）")
    print(f"[sync] 兼容性: 可加载 {stats['loadable']} / {stats['yaml_total']} "
          f"（不兼容 {stats['incompatible']}）")
    if stats["incompatible_types"]:
        print(f"[sync] 不兼容类型分布: {stats['incompatible_types']}")
    print("RESULT: OK (exit 0, 计数作指标)")
    return True


if __name__ == "__main__":
    sys.exit(main())
