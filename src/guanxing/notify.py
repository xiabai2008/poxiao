"""观星 — 变化告警与本地变更日志（P2-2 / D9 / X3 / R4）

约束：
- 仅本地：webhook（用户自配 URL）+ 本地 JSONL 日志；无邮件、无服务端（X3/R4）。
- 解耦：notify 任何失败均被调用方吞掉，绝不中断 DB 写入。
"""

import json
import os
import threading
from pathlib import Path
from typing import Optional

import httpx

from src.config import get_config


def _log_path() -> Path:
    return Path(os.environ.get("POXIAO_GUANXING_LOG", "scan_results/guanxing_changes.log"))


def push_change_event(change: dict) -> None:
    """若配置了 webhook_url，则异步推送变更事件；否则 no-op。

    使用后台守护线程 fire-and-forget，避免阻塞 DB 写入；
    推送失败仅打印告警，绝不抛出异常。
    """
    try:
        url = get_config().get("monitor", "webhook_url", "") or ""
    except Exception:
        return
    if not url:
        return
    threading.Thread(target=_post_webhook, args=(url, change), daemon=True).start()


def _post_webhook(url: str, change: dict) -> None:
    """实际执行 webhook POST（在后台线程中调用）。"""
    try:
        resp = httpx.post(url, json=change, timeout=5.0)
        if resp.status_code >= 400:
            print(f"[guanxing] webhook 返回非 2xx: {resp.status_code}")
    except Exception as e:
        print(f"[guanxing] webhook 推送失败（已忽略）: {e}")


def append_change_log(change: dict) -> None:
    """将变更追加入本地 JSONL 日志（scan_results/guanxing_changes.log）。"""
    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(change, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[guanxing] 变更日志写入失败（已忽略）: {e}")
