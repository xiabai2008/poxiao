"""
破晓 审计日志模块 (安全设计 §7.2 / §7.1)
========================================

五维度审计日志（本地等价），落盘为 JSONL（每行一个 JSON 事件），
f-string 组织不可信字段前先经脱敏，禁止密钥/密码明文入日志。

设计约束（对齐 §7.2 / §3.3 / §6.3）：
  * 返回结果为**脱敏后**的日志行，脱敏在字段级完成，不依赖调用方。
  * 追加式写入（append-only），不覆盖历史，支撑"不可篡改"的本地最小保障。
  * 常用字段内置 `timestamp / level / service / traceId / userId /
    module / event / msg`（对齐系统设计 §8.2.2 字段规范）。
  * 敏感数据（API Key、真实凭据等）通过 `secret` 参数显式登记并打码，
    不会进入 msg/其他字段再由调用方拼入而泄露（§6.3 红线）。
  * 写日志文件失败不阻断主流程（安全工具以扫描为主，审计为附属）。
"""

import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── 保留期 / 路径 ───────────────────────────────────

# 审计保留期（天）。安全设计 §7.2 权威：≥ 1 年。
AUDIT_RETENTION_DAYS = 365

# 默认审计根目录（可用环境变量 POXIAO_AUDIT_DIR 覆盖）
_DEFAULT_AUDIT_DIR = "scan_results/audit"


def audit_dir() -> Path:
    """返回审计日志目录，支持环境变量覆盖（对齐 db.POXIAO_GUANXING_DB 惯例）。"""
    custom = os.environ.get("POXIAO_AUDIT_DIR", "")
    return Path(custom) if custom else Path(_DEFAULT_AUDIT_DIR)


# ── 脱敏工具 ────────────────────────────────────────

def _mask_secret(value: str) -> str:
    """密钥/口令打码：保留首尾，中段替换为 *；短值全打码。"""
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return s[0] + "*" * (len(s) - 2) + s[-1]


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(1[3-9]\d{9})(?!\d)")
_ID_RE = re.compile(r"\d{17}[\dXx]|\d{15}")


def mask_pii(text: str) -> str:
    """对文本中的 PII（邮箱/手机/身份证号）打码（§3.3.5 展示脱敏）。

    * 邮箱: a***@x.com
    * 手机: 138****8888
    * 身份证: 110***********1234
    """
    if not isinstance(text, str):
        text = str(text)
    text = _EMAIL_RE.sub(lambda m: _mask_email(m.group(0)), text)
    text = _PHONE_RE.sub(lambda m: m.group(1)[:3] + "****" + m.group(1)[7:], text)
    text = _ID_RE.sub(lambda m: m.group(0)[:3] + "****" + m.group(0)[-4:], text)
    return text


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "**"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@*{domain.lstrip('*')}"


def sanitize_record(record: dict) -> dict:
    """最终脱敏：clone 后对用户可控长文本字段应用 mask_pii，防止泄露 PII。"""
    out = dict(record)
    for field in ("target", "msg"):
        if isinstance(out.get(field), str) and out[field]:
            out[field] = mask_pii(out[field])
    return out


# ── traceId / 时间 ──────────────────────────────────

def new_trace_id() -> str:
    """生成 16 位十六进制随机 traceId。"""
    return secrets.token_hex(8)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── 审计记录构造 ────────────────────────────────────

def _merge_record(**kwargs) -> dict:
    """按 §8.2.2 字段规范补齐 audit 记录公共字段。"""
    rec = {
        "timestamp": _utcnow(),
        "level": kwargs.pop("level", "info"),
        "service": kwargs.pop("service", "poxiao"),
        "traceId": kwargs.pop("trace_id", new_trace_id()),
        "tenantId": "local",
        "userId": kwargs.pop("user_id", "local-user"),
        "module": kwargs.pop("module", "core"),
        "event": kwargs.pop("event", ""),
    }
    # msg 作为可读描述，可能含 PII，最后统一 sanitize
    if "msg" in kwargs:
        rec["msg"] = kwargs.pop("msg")
    # 显式登记的密钥字段打码，且不进入其他自由文本
    if "secret" in kwargs:
        rec["secret"] = _mask_secret(kwargs.pop("secret"))
    # 其余扩展字段透传
    rec.update(kwargs)
    return sanitize_record(rec)


def _write_line(record: dict) -> None:
    """追加一条 JSON 审计事件到当日文件（append-only）。"""
    try:
        d = audit_dir()
        d.mkdir(parents=True, exist_ok=True)
        date_path = Path(record["timestamp"][:10])
        fp = (d / f"{date_path}.jsonl")
        line = json.dumps(record, ensure_ascii=False)
        with open(fp, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        # 审计写盘失败不阻断主流程
        return


# ── 公共 API ────────────────────────────────────────

def audit(module: str, event: str, msg: str = "", level: str = "info",
          trace_id: Optional[str] = None, user_id: Optional[str] = None,
          secret: Optional[str] = None, **extra) -> str:
    """写入一条审计事件，返回该事件的 JSON 行文本（已脱敏）。

    供扫描 / 报告 / 监控 / 面板命令在关键操作处调用。
    """
    rec = _merge_record(
        level=level,
        module=module,
        event=event,
        msg=msg,
        trace_id=trace_id,
        user_id=user_id,
        secret=secret,
        **extra,
    )
    _write_line(rec)
    return json.dumps(rec, ensure_ascii=False)


# 便捷别名：业务操作审计
def biz(module: str, event: str, **kwargs) -> str:
    """业务操作审计（§7.2 维度二）：扫描 / 报告 / 监控操作。"""
    return audit(module, event, **kwargs)


def cleanup_expired(max_days: int = AUDIT_RETENTION_DAYS) -> list:
    """清理超过保留期的审计文件，返回删除的文件名列表（§7.2 保留期 ≥1年）。

    Args:
        max_days: 保留天数，默认 365。
    """
    removed: list[str] = []
    try:
        d = audit_dir()
        if not d.exists():
            return removed
        cutoff = datetime.now(timezone.utc).timestamp() - max_days * 86400
        for f in d.glob("*.jsonl"):
            if f.is_file():
                try:
                    mtime = f.stat().st_mtime
                except OSError:
                    continue
                if mtime < cutoff:
                    try:
                        f.unlink()
                        removed.append(f.name)
                    except OSError:
                        pass
    except Exception:
        return removed
    return removed
