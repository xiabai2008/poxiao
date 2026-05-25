"""观星 — 资产监控平台数据库层"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


DB_PATH = Path("scan_results/guanxing.db")


def get_db() -> sqlite3.Connection:
    """获取数据库连接"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库表"""
    conn = get_db()
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

        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
        CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scanned_at);
        CREATE INDEX IF NOT EXISTS idx_changes_target ON changes(target_id);
    """)
    conn.commit()
    conn.close()


# ── Target CRUD ──────────────────────────────────

def upsert_target(url: str, host: str, status: str = "unknown",
                  tech_stack: list = None, sensitive_count: int = 0,
                  cve_count: int = 0) -> int:
    """插入或更新目标"""
    conn = get_db()
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
        target_id = existing["id"]
    else:
        cursor = conn.execute("""
            INSERT INTO targets (url, host, first_seen, last_seen, status,
                                tech_stack, sensitive_count, cve_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (url, host, now, now, status, tech_json, sensitive_count, cve_count))
        target_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return target_id


def add_scan(target_id: int, alive: bool, tech_stack: list,
             sensitive_paths: list, cve_matches: list,
             response_time: float = 0):
    """记录一次扫描"""
    conn = get_db()
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
    conn.commit()
    conn.close()


def _record_change(conn: sqlite3.Connection, target_id: int,
                   change_type: str, old_value: str, new_value: str):
    """记录变更"""
    conn.execute("""
        INSERT INTO changes (target_id, changed_at, change_type, old_value, new_value)
        VALUES (?, ?, ?, ?, ?)
    """, (target_id, datetime.now().isoformat(), change_type, old_value, new_value))


# ── 查询 ────────────────────────────────────────

def get_targets(status: str = None, limit: int = 100) -> list[dict]:
    """获取目标列表"""
    conn = get_db()
    if status:
        rows = conn.execute(
            "SELECT * FROM targets WHERE status = ? ORDER BY last_seen DESC LIMIT ?",
            (status, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM targets ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_target_by_id(target_id: int) -> Optional[dict]:
    """获取单个目标"""
    conn = get_db()
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    conn.close()
    return _row_to_dict(row) if row else None


def get_scans(target_id: int, limit: int = 20) -> list[dict]:
    """获取扫描历史"""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans WHERE target_id = ? ORDER BY scanned_at DESC LIMIT ?",
        (target_id, limit)
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_changes(target_id: int = None, limit: int = 50) -> list[dict]:
    """获取变更记录"""
    conn = get_db()
    if target_id:
        rows = conn.execute(
            "SELECT * FROM changes WHERE target_id = ? ORDER BY changed_at DESC LIMIT ?",
            (target_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM changes ORDER BY changed_at DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_stats() -> dict:
    """获取统计信息"""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    alive = conn.execute("SELECT COUNT(*) FROM targets WHERE status='alive'").fetchone()[0]
    with_findings = conn.execute(
        "SELECT COUNT(*) FROM targets WHERE sensitive_count > 0 OR cve_count > 0"
    ).fetchone()[0]

    # 技术栈分布
    techs = conn.execute("SELECT tech_stack FROM targets WHERE tech_stack != '[]'").fetchall()
    tech_count = {}
    for (ts,) in techs:
        for t in json.loads(ts):
            tech_count[t] = tech_count.get(t, 0) + 1

    # 最近变更
    recent_changes = conn.execute(
        "SELECT COUNT(*) FROM changes WHERE changed_at > datetime('now', '-7 days')"
    ).fetchone()[0]

    conn.close()
    return {
        "total": total,
        "alive": alive,
        "with_findings": with_findings,
        "tech_distribution": tech_count,
        "recent_changes": recent_changes,
    }


def get_recent_scan_count(hours: int = 24) -> int:
    """最近N小时扫描次数"""
    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE scanned_at > datetime('now', ?)",
        (f"-{hours} hours",)
    ).fetchone()[0]
    conn.close()
    return count


def import_from_summary(summary_path: str):
    """从破晓扫描汇总JSON导入数据"""
    data = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    targets = data.get("targets", [])

    for t in targets:
        url = t.get("target_url", "")
        host = t.get("host", url)
        alive = t.get("alive", False)
        tech = t.get("tech_tags", [])
        sensitive = t.get("sensitive_paths", [])
        cve = t.get("cve_matches", [])

        tid = upsert_target(
            url=url, host=host,
            status="alive" if alive else "dead",
            tech_stack=tech,
            sensitive_count=len(sensitive),
            cve_count=len(cve),
        )
        add_scan(tid, alive, tech, sensitive, cve, t.get("response_time", 0))


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Row → dict，解析 JSON 字段"""
    d = dict(row)
    for key in ("tech_stack", "sensitive_paths", "cve_matches"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d


# ── 初始化 ─────────────────────────────────────

init_db()
