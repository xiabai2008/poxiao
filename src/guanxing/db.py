"""观星 — 资产监控平台数据库层"""

import csv
import io
import json
import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import notify


def _get_db_path() -> Path:
    """获取数据库路径，支持环境变量覆盖"""
    custom = os.environ.get("POXIAO_GUANXING_DB", "")
    if custom:
        return Path(custom)
    return Path("scan_results/guanxing.db")


DB_PATH = _get_db_path()
_initialized = False


@contextmanager
def get_db():
    """数据库连接上下文管理器 (自动提交/回滚/关闭)"""
    global _initialized
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise RuntimeError(f"无法创建数据库目录 {DB_PATH.parent}: {e}") from e

    try:
        conn = sqlite3.connect(str(DB_PATH))
    except sqlite3.Error as e:
        raise RuntimeError(f"无法连接数据库 {DB_PATH}: {e}") from e

    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")  # 并发读写优化
    except sqlite3.Error:
        pass  # WAL 模式不是必需的，某些系统可能不支持

    try:
        if not _initialized:
            _migrate(conn)
            _initialized = True
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Schema 版本：随结构演进递增，旧库自动迁移至最新。
SCHEMA_VERSION = 1


def _get_schema_version(conn: sqlite3.Connection) -> int:
    """读取当前已落库的 schema 版本（无表时视为 0）。"""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT)"
    )
    row = conn.execute(
        "SELECT value FROM _meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        return 0
    try:
        return int(row[0])
    except (ValueError, TypeError):
        return 0


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', ?)",
        (str(version),),
    )


def _migrate(conn: sqlite3.Connection) -> None:
    """幂等迁移：从当前版本升级到 SCHEMA_VERSION。

    每次连接首次进入时调用；CREATE TABLE IF NOT EXISTS 保证可重复执行，
    版本号避免重复执行已完成的迁移步骤。
    """
    _create_tables(conn)
    current = _get_schema_version(conn)
    # 未来迁移在下方按 current < N 追加，例如：
    #   if current < 2:
    #       conn.execute("ALTER TABLE targets ADD COLUMN foo TEXT")
    #       current = 2
    if current < SCHEMA_VERSION:
        _set_schema_version(conn, SCHEMA_VERSION)


def _create_tables(conn: sqlite3.Connection):
    """创建数据库表"""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            host TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'unknown',
            tech_stack TEXT DEFAULT '[]',
            sensitive_count INTEGER DEFAULT 0,
            cve_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            scanned_at TEXT NOT NULL,
            alive INTEGER DEFAULT 0,
            tech_stack TEXT DEFAULT '[]',
            sensitive_paths TEXT DEFAULT '[]',
            cve_matches TEXT DEFAULT '[]',
            response_time REAL DEFAULT 0,
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );

        CREATE TABLE IF NOT EXISTS changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            changed_at TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_value TEXT DEFAULT '',
            new_value TEXT DEFAULT '',
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );

        CREATE INDEX IF NOT EXISTS idx_targets_host ON targets(host);
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
        CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scanned_at);
        CREATE INDEX IF NOT EXISTS idx_changes_target ON changes(target_id);
    """)


# 保持向后兼容
def init_db():
    """初始化数据库表 (向后兼容)"""
    with get_db() as conn:
        pass  # 表已在 context manager 中自动创建


# ── Target CRUD ──────────────────────────────────

def upsert_target(url: str, host: str, status: str = "unknown",
                  tech_stack: Optional[list] = None, sensitive_count: int = 0,
                  cve_count: int = 0) -> int:
    """插入或更新目标"""
    with get_db() as conn:
        now = datetime.now().isoformat()
        tech_json = json.dumps(tech_stack or [])

        existing = conn.execute(
            "SELECT id, first_seen, tech_stack FROM targets WHERE url = ?", (url,)
        ).fetchone()

        if existing:
            # 检测变更
            old_tech = json.loads(existing["tech_stack"])
            new_tech = tech_stack or []
            if old_tech != new_tech and old_tech and new_tech:
                _record_change(conn, existing["id"], "tech_change",
                              ",".join(old_tech), ",".join(new_tech))

            conn.execute("""
                UPDATE targets SET last_seen=?, status=?, tech_stack=?,
                sensitive_count=?, cve_count=?
                WHERE id=?
            """, (now, status, tech_json, sensitive_count, cve_count, existing["id"]))
            return existing["id"]
        else:
            cursor = conn.execute("""
                INSERT INTO targets (url, host, first_seen, last_seen, status,
                                    tech_stack, sensitive_count, cve_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (url, host, now, now, status, tech_json, sensitive_count, cve_count))
            return cursor.lastrowid


def add_scan(target_id: int, alive: bool, tech_stack: list,
             sensitive_paths: list, cve_matches: list,
             response_time: float = 0) -> None:
    """记录一次扫描"""
    with get_db() as conn:
        now = datetime.now().isoformat()
        conn.execute("""
            INSERT INTO scans (target_id, scanned_at, alive, tech_stack,
                              sensitive_paths, cve_matches, response_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            target_id, now, int(alive),
            json.dumps(tech_stack),
            json.dumps(sensitive_paths),
            json.dumps(cve_matches),
            response_time,
        ))


def _record_change(conn: sqlite3.Connection, target_id: int,
                   change_type: str, old_value: str, new_value: str) -> None:
    """记录变更，并解耦推送告警 / 写本地日志"""
    conn.execute("""
        INSERT INTO changes (target_id, changed_at, change_type, old_value, new_value)
        VALUES (?, ?, ?, ?, ?)
    """, (target_id, datetime.now().isoformat(), change_type, old_value, new_value))
    _notify_change({
        "target_id": target_id,
        "change_type": change_type,
        "old_value": old_value,
        "new_value": new_value,
        "changed_at": datetime.now().isoformat(),
    })


def _notify_change(change: dict) -> None:
    """推送变更事件与本地日志；任何失败均被吞掉，绝不中断 DB 写入。"""
    try:
        notify.push_change_event(change)
        notify.append_change_log(change)
    except Exception:
        pass


# ── 查询 ────────────────────────────────────────

def get_targets(status: Optional[str] = None, limit: int = 100, offset: int = 0,
                search: Optional[str] = None) -> tuple[list[dict], int]:
    """获取目标列表，返回 (列表, 总数)。

    Args:
        status: 按状态筛选
        limit: 每页条数
        offset: 偏移量
        search: 搜索关键词 (匹配 host 或 url)
    """
    with get_db() as conn:
        conditions = []
        params = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if search:
            conditions.append("(host LIKE ? OR url LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM targets{where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM targets{where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        return [_row_to_dict(r) for r in rows], total


def get_target_by_id(target_id: int) -> Optional[dict]:
    """获取单个目标"""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return _row_to_dict(row) if row else None


def get_scans(target_id: int, limit: int = 20) -> list[dict]:
    """获取扫描历史"""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE target_id = ? ORDER BY scanned_at DESC LIMIT ?",
            (target_id, limit)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_changes(target_id: Optional[int] = None, limit: int = 50) -> list[dict]:
    """获取变更记录"""
    with get_db() as conn:
        if target_id:
            rows = conn.execute(
                "SELECT * FROM changes WHERE target_id = ? ORDER BY changed_at DESC LIMIT ?",
                (target_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM changes ORDER BY changed_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_stats() -> dict:
    """获取统计信息"""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        alive = conn.execute("SELECT COUNT(*) FROM targets WHERE status='alive'").fetchone()[0]

        tech_rows = conn.execute(
            "SELECT tech_stack FROM targets WHERE tech_stack != '[]'"
        ).fetchall()
        tech_dist: dict[str, int] = {}
        for row in tech_rows:
            for t in json.loads(row[0]):
                tech_dist[t] = tech_dist.get(t, 0) + 1

        with_findings = conn.execute(
            "SELECT COUNT(*) FROM targets WHERE sensitive_count > 0 OR cve_count > 0"
        ).fetchone()[0]

        recent_changes = conn.execute(
            "SELECT COUNT(*) FROM changes WHERE changed_at > datetime('now', '-7 days')"
        ).fetchone()[0]

        return {
            "total": total,
            "alive": alive,
            "with_findings": with_findings,
            "recent_changes": recent_changes,
            "tech_distribution": tech_dist,
        }


def import_from_summary(summary_path: str) -> None:
    """从扫描汇总 JSON 导入数据"""
    import asyncio
    from pathlib import Path

    data = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    targets = data.get("targets", [])

    for t in targets:
        url = t.get("target_url", "")
        if not url:
            continue
        host = url.split("//")[-1].split("/")[0].split(":")[0]
        status = "alive" if t.get("alive") else "dead"
        tech = t.get("tech", {})
        if isinstance(tech, dict):
            tech_list = list(tech.keys())
        else:
            tech_list = tech if isinstance(tech, list) else []
        sensitive_count = len(t.get("sensitive_paths", []))
        cve_count = len(t.get("cve_matches", []))

        target_id = upsert_target(url, host, status, tech_list, sensitive_count, cve_count)
        add_scan(target_id, t.get("alive", False), tech_list,
                t.get("sensitive_paths", []), t.get("cve_matches", []),
                t.get("duration_sec", 0))


def _row_to_dict(row: Optional[sqlite3.Row]) -> dict:
    """将 sqlite3.Row 转为 dict"""
    if row is None:
        return {}
    d = dict(row)
    # JSON 字段反序列化
    for key in ("tech_stack", "sensitive_paths", "cve_matches"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


def export_data(format: str = "json") -> tuple[str, str, str]:
    """导出资产与变更为 CSV / JSON（P2-2 / X3：仅本地文件，无服务端）。

    返回 (内容, MIME 类型, 建议文件名)。
    """
    targets, _ = get_targets(limit=100000)
    changes = get_changes(limit=100000)
    stats = get_stats()

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "url", "host", "status", "tech_stack",
            "sensitive_count", "cve_count", "first_seen", "last_seen",
        ])
        for t in targets:
            tech = ",".join(t.get("tech_stack") or [])
            writer.writerow([
                t.get("id"), t.get("url"), t.get("host"), t.get("status"),
                tech, t.get("sensitive_count"), t.get("cve_count"),
                t.get("first_seen"), t.get("last_seen"),
            ])
        return buf.getvalue(), "text/csv; charset=utf-8", "guanxing_targets.csv"

    content = json.dumps(
        {"targets": targets, "changes": changes, "stats": stats},
        ensure_ascii=False, indent=2,
    )
    return content, "application/json; charset=utf-8", "guanxing_export.json"
