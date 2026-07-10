#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 · SBOM 生成工具 (Phase 3 / P3-1 / D12 / 安全 A08)
======================================================

生成 **CycloneDX 1.5** 格式的软件物料清单（SBOM）JSON，
使依赖版本可被锁定、追溯与审计（缓解供应链投毒 A08）。

设计：
  * 依赖清单来源：本包自身 `importlib.metadata.requires("poxiao")`（运行时 + 可选 dev）。
  * 版本解析：优先取**已安装**版本（`importlib.metadata.version`），
    缺失则回退到声明下限（>=x.y），不因未安装而失败。
  * 每个组件含 purl（`pkg:pypi/<name>@<version>`），`--hashes` 时附带 SHA-256 完整性指纹。
  * 纯标准库 + setuptools 提供的 `importlib.metadata`，无新增第三方依赖（守 X3/Q5 精神）。

用法：
  python tools/gen_sbom.py --out sbom.json
  python tools/gen_sbom.py --out sbom.json --include-dev --no-hashes
  python tools/gen_sbom.py --deps-file requirements.txt   # 追加额外依赖文件中的条目
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    importlib_metadata = None  # type: ignore


PKG_NAME = "poxiao"
NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
LOWER_RE = re.compile(r">=\s*([0-9][^\s,;]*)")


def _iter_requirement_entries(include_dev: bool) -> List[Tuple[str, str]]:
    """返回 [(包名, 原始需求串), ...]；剔除非 dev 的 extra 条件。"""
    out: List[Tuple[str, str]] = []
    if importlib_metadata is None:
        return out
    try:
        raw = importlib_metadata.requires(PKG_NAME) or []
    except Exception:
        return out

    for r in raw:
        r = r.strip()
        if not r:
            continue
        if "; extra ==" in r:
            if not include_dev:
                continue
            if 'extra == "dev"' not in r:
                continue
        m = NAME_RE.match(r)
        if m:
            out.append((m.group(1), r))
    return out


def _read_deps_file(path: str) -> List[Tuple[str, str]]:
    """从 requirements.txt 追加条目（仅取包名与下限，用于补充声明）。"""
    out: List[Tuple[str, str]] = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = NAME_RE.match(line)
        if m:
            out.append((m.group(1), line))
    return out


def _resolve_version(name: str, req: str) -> Optional[str]:
    if importlib_metadata is not None:
        try:
            return importlib_metadata.version(name)
        except Exception:
            pass
    m = LOWER_RE.search(req)
    if m:
        return m.group(1)
    return None


def _dist_sha256(name: str) -> Optional[str]:
    """计算已安装分发的完整性 SHA-256（遍历其文件内容）。失败返回 None。"""
    if importlib_metadata is None:
        return None
    try:
        dist = importlib_metadata.distribution(name)
    except Exception:
        return None
    h = hashlib.sha256()
    files = getattr(dist, "files", None) or []
    try:
        ordered = sorted(files, key=lambda f: str(f))
    except Exception:
        ordered = list(files)
    for f in ordered:
        try:
            loc = Path(str(dist.locate_file(f)))  # SimplePath -> str -> Path
        except Exception:
            try:
                loc = Path(str(dist._path)).parent / str(f)  # type: ignore[attr-defined]
            except Exception:
                continue
        try:
            if loc.is_file():
                h.update(loc.read_bytes())
        except Exception:
            continue
    return h.hexdigest()


def build_sbom(
    include_dev: bool = False,
    with_hashes: bool = True,
    deps_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """构建 CycloneDX 1.5 结构的 SBOM dict。"""
    entries: Dict[str, str] = {}
    for name, req in _iter_requirement_entries(include_dev):
        entries.setdefault(name, req)
    for df in deps_files or []:
        for name, req in _read_deps_file(df):
            entries.setdefault(name, req)

    components: List[Dict[str, Any]] = []
    for name, req in sorted(entries.items(), key=lambda kv: kv[0].lower()):
        ver = _resolve_version(name, req)
        comp: Dict[str, Any] = {"type": "library", "name": name}
        if ver:
            comp["version"] = ver
        purl = "pkg:pypi/" + name.lower()
        if ver:
            purl += "@" + ver
        comp["purl"] = purl
        if with_hashes:
            hh = _dist_sha256(name)
            if hh:
                comp["hashes"] = [{"alg": "SHA-256", "content": hh}]
        components.append(comp)

    try:
        pkg_ver = importlib_metadata.version(PKG_NAME) if importlib_metadata else "3.0.0"
    except Exception:
        pkg_ver = "3.0.0"

    sbom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "name": PKG_NAME,
                "version": pkg_ver,
            },
        },
        "components": components,
    }
    return sbom


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="生成 CycloneDX SBOM")
    parser.add_argument("--out", default="sbom.json", help="输出 SBOM JSON 路径")
    parser.add_argument("--include-dev", action="store_true", help="包含 dev 可选依赖")
    parser.add_argument("--no-hashes", action="store_true", help="不计算组件 SHA-256")
    parser.add_argument(
        "--deps-file",
        action="append",
        default=None,
        help="追加额外的 requirements 文件（可多次）",
    )
    args = parser.parse_args(argv)

    sbom = build_sbom(
        include_dev=args.include_dev,
        with_hashes=not args.no_hashes,
        deps_files=args.deps_file,
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[SBOM] 组件数: {len(sbom['components'])}")
    print(f"[SBOM] 输出: {out} (CycloneDX {sbom['specVersion']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
