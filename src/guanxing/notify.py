"""观星 — 变化告警与本地变更日志（P2-2 / D9 / X3 / R4；P1-B 飞书/钉钉适配）

约束：
- 仅本地：webhook（用户自配 URL）+ 本地 JSONL 日志；无邮件、无服务端（X3/R4）。
- 解耦：notify 任何失败均被调用方吞掉，绝不中断 DB 写入。
- 消息格式：按 webhook URL 自动识别 飞书(open.feishu.cn)/钉钉(oapi.dingtalk.com)，
  或配置 `monitor.webhook_type`（feishu|dingtalk|raw）强制指定。
"""

import json
import os
import threading
from pathlib import Path

import httpx

from src.config import get_config


def _log_path() -> Path:
    """变更 JSONL 日志路径（支持环境变量覆盖）"""
    return Path(os.environ.get("POXIAO_GUANXING_LOG", "scan_results/guanxing_changes.log"))


def _webhook_type(url: str) -> str:
    """识别 webhook 类型：feishu / dingtalk / raw（按 URL 或配置）"""
    try:
        configured = get_config().get("monitor", "webhook_type", "") or ""
        if configured in ("feishu", "dingtalk", "raw"):
            return configured
    except Exception:
        pass
    low = url.lower()
    if "open.feishu.cn" in low or "open.larksuite.com" in low:
        return "feishu"
    if "oapi.dingtalk.com" in low:
        return "dingtalk"
    return "raw"


def _change_to_text(change: dict) -> str:
    """变更事件 → 人类可读文本"""
    return (
        f"【观星资产变更】\n"
        f"- 目标ID: {change.get('target_id', '?')}\n"
        f"- 类型: {change.get('change_type', '?')}\n"
        f"- 变更: {change.get('old_value', '')} → {change.get('new_value', '')}\n"
        f"- 时间: {change.get('changed_at', '?')}"
    )


def _build_payload(url: str, change: dict) -> dict:
    """按 webhook 类型构建消息载荷"""
    wtype = _webhook_type(url)
    text = _change_to_text(change)

    if wtype == "feishu":
        return {
            "msg_type": "text",
            "content": {"text": text},
        }
    if wtype == "dingtalk":
        return {
            "msgtype": "markdown",
            "markdown": {"title": "观星资产变更", "text": text.replace("\n", "\n\n")},
        }
    # raw: 原样 JSON（向后兼容）
    return change


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
        payload = _build_payload(url, change)
        resp = httpx.post(url, json=payload, timeout=5.0)
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
