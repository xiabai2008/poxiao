"""
目标状态管理 — 扫描结果持久化 & 历史对比
=========================================

功能:
  - POC 扫描结果自动存入 SQLite
  - 同目标历史对比 (新增/消失/变化)
  - 增量报告 (只显示新增发现)
  - 目标快照 & 回滚

表结构:
  poc_scans:    扫描批次记录
  poc_findings: 漏洞发现记录 (关联到 scans)
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field, asdict

from .db import get_db


def _ensure_poc_tables(conn: sqlite3.Connection):
    """确保 POC 表存在"""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS poc_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            template_count INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0,
            new_count INTEGER DEFAULT 0,
            elapsed_sec REAL DEFAULT 0,
            tags TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS poc_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            template_id TEXT NOT NULL,
            template_name TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            url TEXT DEFAULT '',
            matched INTEGER DEFAULT 1,
            matcher_name TEXT DEFAULT '',
            extracted TEXT DEFAULT '{}',
            response_status INTEGER DEFAULT 0,
            response_size INTEGER DEFAULT 0,
            request_url TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            description TEXT DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER DEFAULT 1,
            is_new INTEGER DEFAULT 1,
            FOREIGN KEY (scan_id) REFERENCES poc_scans(id)
        );

        CREATE INDEX IF NOT EXISTS idx_poc_findings_target ON poc_findings(target);
        CREATE INDEX IF NOT EXISTS idx_poc_findings_template ON poc_findings(template_id);
        CREATE INDEX IF NOT EXISTS idx_poc_findings_severity ON poc_findings(severity);
        CREATE INDEX IF NOT EXISTS idx_poc_scans_target ON poc_scans(target);
    """)


@dataclass
class FindingDiff:
    """漏洞对比结果"""
    new_findings: list = field(default_factory=list)       # 新增
    existing_findings: list = field(default_factory=list)   # 已存在
    disappeared: list = field(default_factory=list)         # 消失


def save_scan_results(target: str, results: list, template_count: int = 0,
                      elapsed: float = 0.0) -> int:
    """
    保存 POC 扫描结果到数据库

    Returns:
        scan_id: 本次扫描 ID
    """
    with get_db() as conn:
        _ensure_poc_tables(conn)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. 创建扫描批次
        cursor = conn.execute(
            "INSERT INTO poc_scans (target, scan_time, template_count, finding_count, elapsed_sec) VALUES (?, ?, ?, ?, ?)",
            (target, now, template_count, len(results), elapsed)
        )
        scan_id = cursor.lastrowid

        # 2. 获取该目标的历史发现
        existing = conn.execute(
            "SELECT template_id, url, id FROM poc_findings WHERE target = ? ORDER BY last_seen DESC",
            (target,)
        ).fetchall()
        existing_keys = {(r["template_id"], r["url"]) for r in existing}
        existing_map = {(r["template_id"], r["url"]): r["id"] for r in existing}

        # 3. 保存发现结果
        new_count = 0
        for r in results:
            if not r.get("matched", True):
                continue

            key = (r.get("template_id", ""), r.get("url", ""))
            is_new = key not in existing_keys
            if is_new:
                new_count += 1

            if key in existing_map:
                # 更新已有记录
                conn.execute(
                    "UPDATE poc_findings SET last_seen = ?, seen_count = seen_count + 1, is_new = 0 WHERE id = ?",
                    (now, existing_map[key])
                )
            else:
                # 插入新记录
                conn.execute(
                    """INSERT INTO poc_findings 
                    (scan_id, target, template_id, template_name, severity, url, matched,
                     matcher_name, extracted, response_status, response_size, request_url,
                     tags, description, first_seen, last_seen, is_new)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, target,
                     r.get("template_id", ""),
                     r.get("template_name", ""),
                     r.get("severity", "info"),
                     r.get("url", ""),
                     1 if r.get("matched") else 0,
                     r.get("matcher_name", ""),
                     json.dumps(r.get("extracted", {}), ensure_ascii=False),
                     r.get("response_status", 0),
                     r.get("response_size", 0),
                     r.get("request_url", ""),
                     json.dumps(r.get("tags", []), ensure_ascii=False),
                     r.get("description", ""),
                     now, now, 1 if is_new else 0)
                )

        # 更新扫描批次的新发现数
        conn.execute(
            "UPDATE poc_scans SET new_count = ? WHERE id = ?",
            (new_count, scan_id)
        )

        return scan_id


def get_history(target: str, limit: int = 10) -> List[Dict]:
    """获取目标的扫描历史"""
    with get_db() as conn:
        _ensure_poc_tables(conn)
        rows = conn.execute(
            "SELECT * FROM poc_scans WHERE target = ? ORDER BY scan_time DESC LIMIT ?",
            (target, limit)
        ).fetchall()
        return [dict(r) for r in rows]


def get_findings(target: str, only_new: bool = False,
                 severity: str = "") -> List[Dict]:
    """获取目标的漏洞发现"""
    with get_db() as conn:
        _ensure_poc_tables(conn)

        query = "SELECT * FROM poc_findings WHERE target = ?"
        params = [target]

        if only_new:
            query += " AND is_new = 1"
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY first_seen DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def compare_with_last(target: str, current_results: list) -> FindingDiff:
    """
    对比本次扫描与上次扫描的结果

    Returns:
        FindingDiff: 新增/已存在/消失
    """
    with get_db() as conn:
        _ensure_poc_tables(conn)

        # 获取上次扫描的发现
        last_scan = conn.execute(
            "SELECT id FROM poc_scans WHERE target = ? ORDER BY scan_time DESC LIMIT 1",
            (target,)
        ).fetchone()

        diff = FindingDiff()

        if not last_scan:
            # 首次扫描，所有结果都是新的
            diff.new_findings = [r for r in current_results if r.get("matched", True)]
            return diff

        # 获取上次的发现
        last_findings = conn.execute(
            "SELECT template_id, url FROM poc_findings WHERE scan_id = ?",
            (last_scan["id"],)
        ).fetchall()
        last_keys = {(r["template_id"], r["url"]) for r in last_findings}

        # 本次发现
        current_keys = set()
        for r in current_results:
            if not r.get("matched", True):
                continue
            key = (r.get("template_id", ""), r.get("url", ""))
            current_keys.add(key)
            if key in last_keys:
                diff.existing_findings.append(r)
            else:
                diff.new_findings.append(r)

        # 消失的发现
        for key in last_keys - current_keys:
            diff.disappeared.append({"template_id": key[0], "url": key[1]})

        return diff


def get_target_stats(target: str) -> Dict:
    """获取目标统计信息"""
    with get_db() as conn:
        _ensure_poc_tables(conn)

        # 扫描次数
        scan_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM poc_scans WHERE target = ?",
            (target,)
        ).fetchone()["cnt"]

        # 漏洞统计
        severity_counts = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM poc_findings WHERE target = ? GROUP BY severity",
            (target,)
        ).fetchall():
            severity_counts[row["severity"]] = row["cnt"]

        # 最新扫描
        last_scan = conn.execute(
            "SELECT * FROM poc_scans WHERE target = ? ORDER BY scan_time DESC LIMIT 1",
            (target,)
        ).fetchone()

        return {
            "target": target,
            "scan_count": scan_count,
            "total_findings": sum(severity_counts.values()),
            "severity_counts": severity_counts,
            "last_scan": dict(last_scan) if last_scan else None,
        }


def print_history(target: str):
    """打印目标扫描历史"""
    from src.utils.output import Out

    history = get_history(target)
    if not history:
        Out.info(f"{target} 无扫描历史")
        return

    Out.section(f"扫描历史: {target}", "📜")
    for h in history:
        icon = "🆕" if h["new_count"] > 0 else "  "
        Out._print(f"    {icon} [{h['scan_time']}] "
              f"发现:{h['finding_count']} 新增:{h['new_count']} "
              f"耗时:{h['elapsed_sec']:.1f}s")


def print_findings(target: str, only_new: bool = False):
    """打印目标漏洞发现"""
    from src.utils.output import Out

    findings = get_findings(target, only_new=only_new)
    if not findings:
        Out.info(f"{target} 无{'新增' if only_new else ''}漏洞发现")
        return

    label = "新增" if only_new else "所有"
    Out.section(f"{label}漏洞发现: {target}", "🔥")
    for f in findings:
        icon = Out.severity_icon(f["severity"])
        new_tag = " 🆕" if f.get("is_new") else ""
        Out._print(f"    {icon} [{f['severity'].upper()}] {f['template_name']}{new_tag}")
        Out._print(f"      ID:  {f['template_id']}")
        Out._print(f"      URL: {f['request_url'] or f['url']}")
        if f["seen_count"] > 1:
            Out._print(f"      首次: {f['first_seen']}  最近: {f['last_seen']}  (出现{f['seen_count']}次)")
        else:
            Out._print(f"      时间: {f['first_seen']}")
