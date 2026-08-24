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

import hashlib
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


# ── 审计 hash 链（不可篡改，§7.2）──────────────────
#
# 每条审计记录追加两个字段：
#   * prev_hash：上一条记录的 row_hash（链头为 GENESIS）
#   * row_hash ：对"不含自身 row_hash"的规范化序列（含 prev_hash）做 SHA-256
# 链头持久化于审计目录下隐藏文件 .chain_head，写盘后原子更新。
# 校验：verify_chain() 从头重放，任一记录被增删改都会导致前后 prev_hash 断裂。

# 链起源（genesis）哈希：空链头使用的固定起点，64 个 '0'。
_GENESIS_HASH = "0" * 64

# 链头文件名（隐藏，.jsonl glob 不会误删）
_CHAIN_STATE = ".chain_head"


def _chain_state_file() -> Path:
    """链头文件路径（与审计日志同目录）。"""
    return audit_dir() / _CHAIN_STATE


def _read_chain_head() -> str:
    """读取当前链头（最近一条记录的 row_hash），无则返回 GENESIS。"""
    try:
        return _chain_state_file().read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return _GENESIS_HASH


def _chain_hash(data: str) -> str:
    """对规范化字符串计算 SHA-256 十六进制摘要。"""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _finalize_record(record: dict, prev_hash: str) -> dict:
    """写入 prev_hash 并计算 row_hash，构成链式绑定。

    行哈希基于"除自身 row_hash 外的规范化序列"（含 prev_hash），
    因此内容或链序任何变化都会使校验失败。
    """
    record["prev_hash"] = prev_hash
    data = json.dumps(
        {k: v for k, v in record.items() if k != "row_hash"},
        ensure_ascii=False,
        sort_keys=True,
    )
    record["row_hash"] = _chain_hash(data)
    return record


def _write_chain_head(head: str) -> None:
    """原子更新链头：先写临时文件再替换，避免半写状态。"""
    target = _chain_state_file()
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(head, encoding="ascii")
    tmp.replace(target)


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


def _write_line(record: dict) -> str:
    """追加一条 JSON 审计事件到当日文件（append-only），并维护 hash 链。

    返回落盘行的完整 JSON 文本（含 prev_hash / row_hash），保证与磁盘一致。
    写文件或更新链头失败均不阻断主流程。
    """
    try:
        prev = _read_chain_head()
        _finalize_record(record, prev)
        line = json.dumps(record, ensure_ascii=False)
        d = audit_dir()
        d.mkdir(parents=True, exist_ok=True)
        date_path = Path(record["timestamp"][:10])
        fp = (d / f"{date_path}.jsonl")
        with open(fp, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        # 写盘成功后推进链头（失败静默，verify_chain 可发现断链）
        try:
            _write_chain_head(record["row_hash"])
        except OSError:
            pass
        return line
    except Exception:
        # 审计写盘失败不阻断主流程
        return ""


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
    return _write_line(rec)  # 落盘并返回（含 hash 链字段的）完整行


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


def verify_chain() -> dict:
    """从头重放审计日志，校验 hash 链完整性（§7.2 不可篡改）。

    任一记录的增、删、改（含链头篡改）都会导致前后 prev_hash 断裂或
    row_hash 失配，返回 ok=False。

    Returns:
        {
          "ok": bool,            # 链式完整
          "total": int,          # 日志总行数
          "checked": int,        # 已校验（含 hash 链字段）的行数
          "legacy": int,         # 链启用前的旧行（无 row_hash，无法校验）
          "broken": int,         # 发现断裂/失配的行数
          "first_broken": int,   # 首个损坏行的序号（从 1 计，无则 0）
          "reason": str,         # 损坏原因摘要
        }
    """
    d = audit_dir()
    ok = True
    total = 0
    checked = 0
    legacy = 0
    broken = 0
    first_broken = 0
    reason = ""
    prev = _GENESIS_HASH

    try:
        if not d.exists():
            return {
                "ok": True, "total": 0, "checked": 0,
                "legacy": 0, "broken": 0, "first_broken": 0,
                "reason": "审计目录为空",
            }
        for fp in sorted(d.glob("*.jsonl")):
            try:
                lines = fp.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for text in lines:
                text = text.strip()
                if not text:
                    continue
                total += 1
                try:
                    rec = json.loads(text)
                except (ValueError, TypeError):
                    broken += 1
                    ok = False
                    if first_broken == 0:
                        first_broken = total
                        reason = "存在无法解析的 JSON 行"
                    continue
                row_hash = rec.get("row_hash")
                prev_hash = rec.get("prev_hash")
                if not (isinstance(row_hash, str) and isinstance(prev_hash, str)):
                    legacy += 1  # 链启用前的旧行，无法校验
                    continue
                bad = False
                if prev_hash != prev:
                    bad = True
                data = json.dumps(
                    {k: v for k, v in rec.items() if k != "row_hash"},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                if _chain_hash(data) != row_hash:
                    bad = True
                if bad:
                    broken += 1
                    ok = False
                    if first_broken == 0:
                        first_broken = total
                        reason = "prev_hash 或 row_hash 失配（记录被篡改）"
                else:
                    checked += 1
                prev = rec["row_hash"]
    except Exception:
        # 校验本身异常不抛出，返回失败状态
        return {
            "ok": False, "total": total, "checked": checked,
            "legacy": legacy, "broken": broken + 1,
            "first_broken": first_broken or total,
            "reason": reason or "校验过程异常",
        }
    return {
        "ok": ok, "total": total, "checked": checked,
        "legacy": legacy, "broken": broken, "first_broken": first_broken,
        "reason": reason or ("链完整" if ok else "检测到链断裂"),
    }
