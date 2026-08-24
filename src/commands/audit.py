"""审计日志管理命令 (poxiao audit)

校验审计 hash 链完整性、清理过期审计、查看审计目录（安全设计 §7.2）。
"""

import sys

from src.utils import audit
from src.utils.output import Out


_usage = "用法: poxiao audit {verify|cleanup|path}"


def cmd_audit(args):
    """审计日志管理"""
    action = args.audit_action
    if action == "verify":
        _verify()
    elif action == "cleanup":
        _cleanup(args.days)
    elif action == "path":
        Out.info(str(audit.audit_dir()))
    else:
        Out.info(_usage)


def _verify():
    """重放审计日志，校验 hash 链完整性（§7.2 不可篡改）。"""
    res = audit.verify_chain()
    Out.section(f"审计链校验 ({audit.audit_dir()})", "🔗")
    if res["ok"]:
        Out.success("✅ 审计链完整")
    else:
        Out.error("❌ 检测到链断裂 / 记录损坏")
    Out.kv_row("日志总行数", str(res["total"]))
    Out.kv_row("已校验(含链)", str(res["checked"]))
    Out.kv_row("历史旧行(无链字段)", str(res["legacy"]))
    Out.kv_row("损坏行数", str(res["broken"]))
    Out.kv_row("首个损坏行序", str(res["first_broken"] or "-"))
    Out.kv_row("原因", res["reason"])
    if not res["ok"]:
        sys.exit(1)


def _cleanup(days: int):
    """清理超过保留期的审计文件（默认保留期 365 天）。"""
    max_days = days if days and days > 0 else audit.AUDIT_RETENTION_DAYS
    Out.section("审计清理", "🧹")
    removed = audit.cleanup_expired(max_days=max_days)
    Out.kv_row("保留期(天)", str(max_days))
    Out.kv_row("已删除文件", str(len(removed)))
    for name in removed:
        Out._print(f"  • {name}")