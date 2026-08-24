"""授权范围管理命令 (poxiao scope)"""

import sys

from src.utils.scope import ScopeManager, scope_file, scope_enforced
from src.utils.output import Out


_usage = "用法: poxiao scope {list|check|add|rm|status}"


def cmd_scope(args):
    """授权范围管理"""
    action = args.scope_action
    if action == "list":
        _list()
    elif action == "check":
        _check(args.target)
    elif action == "add":
        _add(args.entry)
    elif action == "rm":
        _rm(args.entry)
    elif action == "status":
        _status()
    else:
        Out.info(_usage)


def _list():
    f = scope_file()
    mgr = ScopeManager(f)
    Out.section(f"授权范围 ({mgr.file})", "🎯")
    if not scope_enforced():
        Out.warning("范围校验未启用（无范围文件）。启用：创建范围文件或设 POXIAO_SCOPE_ENFORCE=1")
    entries = mgr.describe()
    if not entries:
        Out.info("（空范围）")
    for e in entries:
        Out._print(f"  • {e}")
    Out.kv_row("条目数", str(mgr.count()))


def _check(target: str):
    from src.utils.scope import target_in_scope
    if not target:
        Out.error("请指定要检查的目标")
        Out._print("    poxiao scope check example.com")
        sys.exit(1)
    ok = target_in_scope(target)
    Out.section(f"范围检查: {target}", "🔍")
    if ok:
        Out.success("✅ 在授权范围内")
    else:
        Out.error("❌ 越界（不在授权范围内）")
    Out.kv_row("校验启用", str(scope_enforced()))


def _add(entry: str):
    f = scope_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    # 避免重复
    existing = f.read_text(encoding="utf-8").splitlines() if f.exists() else []
    if entry in [x.strip() for x in existing]:
        Out.info(f"已存在: {entry}")
        return
    with open(f, "a", encoding="utf-8") as fh:
        fh.write(entry + "\n")
    Out.success(f"已加入范围: {entry} → {f}")
    mgr = ScopeManager(f)
    Out.info(f"当前范围条目: {mgr.count()}")


def _rm(entry: str):
    f = scope_file()
    if not f.exists():
        Out.error("范围文件不存在")
        return
    lines = f.read_text(encoding="utf-8").splitlines()
    kept = [x for x in lines if x.strip() != entry]
    if len(kept) == len(lines):
        Out.info(f"未找到: {entry}")
        return
    f.write_text("\n".join(kept) + "\n", encoding="utf-8")
    Out.success(f"已移除: {entry}")


def _status():
    f = scope_file()
    Out.section("范围状态", "🛡")
    Out.kv_row("范围文件", str(f))
    Out.kv_row("存在", str(f.exists()))
    Out.kv_row("校验启用", str(scope_enforced()))
    if f.exists():
        mgr = ScopeManager(f)
        Out.kv_row("条目数", str(mgr.count()))
    Out.kv_row("环境变量", f"POXIAO_SCOPE_FILE={__import__('os').environ.get('POXIAO_SCOPE_FILE','')}")
    Out.kv_row("强制模式", __import__('os').environ.get("POXIAO_SCOPE_ENFORCE", "(off)"))
