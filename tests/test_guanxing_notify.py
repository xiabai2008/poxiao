"""P2-2 / D9 / X3 / R4：观星变化告警 + 本地导出（无邮件/无服务端）"""

import json
import sys
from unittest.mock import MagicMock

from src.guanxing import notify, db
from src.commands.monitor import cmd_monitor
from src.commands import CMD_MAP
from src.cli import main as cli_main


def test_push_change_event_noop_without_webhook(monkeypatch):
    class FakeCfg:
        def get(self, *a, **k):
            return ""
    monkeypatch.setattr(notify, "get_config", lambda: FakeCfg())
    started = []
    monkeypatch.setattr(notify.threading, "Thread",
                        type("T", (), {"__init__": lambda self, *a, **k: started.append(1),
                                       "start": lambda self: None}))
    notify.push_change_event({"change_type": "x"})
    assert started == []  # 无 webhook → no-op，未启动线程


def test_push_change_event_fires_webhook_thread(monkeypatch):
    class FakeCfg:
        def get(self, *a, **k):
            return "http://hook"
    monkeypatch.setattr(notify, "get_config", lambda: FakeCfg())
    captured = {}
    class FakeThread:
        def __init__(self, target, args, daemon):
            captured["target"] = target
            captured["args"] = args
            captured["daemon"] = daemon
        def start(self):
            captured["started"] = True
    monkeypatch.setattr(notify.threading, "Thread", FakeThread)
    notify.push_change_event({"change_type": "tech_change", "target_id": 1})
    assert captured.get("started") is True
    assert captured["target"] is notify._post_webhook
    assert captured["args"][0] == "http://hook"


def test_post_webhook_posts_json(monkeypatch):
    calls = {}
    def fake_post(url, json=None, timeout=None):
        calls["url"] = url
        calls["json"] = json
        calls["timeout"] = timeout
        return MagicMock(status_code=200)
    monkeypatch.setattr(notify.httpx, "post", fake_post)
    notify._post_webhook("http://hook", {"target_id": 1, "change_type": "tech_change"})
    assert calls["url"] == "http://hook"
    assert calls["json"]["change_type"] == "tech_change"
    assert calls["timeout"] == 5.0


def test_post_webhook_swallows_errors(monkeypatch):
    def fake_post(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(notify.httpx, "post", fake_post)
    notify._post_webhook("http://hook", {"a": 1})  # 不应抛异常


def test_append_change_log_writes_jsonl(tmp_path, monkeypatch):
    log = tmp_path / "guanxing_changes.log"
    monkeypatch.setenv("POXIAO_GUANXING_LOG", str(log))
    notify.append_change_log({"target_id": 1, "change_type": "tech_change"})
    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["change_type"] == "tech_change"


def test_record_change_triggers_notify(tmp_path, monkeypatch):
    monkeypatch.setenv("POXIAO_GUANXING_DB", str(tmp_path / "gx.db"))
    db._initialized = False
    events = []
    monkeypatch.setattr(notify, "push_change_event", lambda c: events.append(("push", c)))
    monkeypatch.setattr(notify, "append_change_log", lambda c: events.append(("log", c)))
    db.upsert_target("http://a.com", "a.com", "alive", ["Apache"], 0, 0)
    db.upsert_target("http://a.com", "a.com", "alive", ["Nginx"], 0, 0)  # 触发 tech_change
    assert any(k == "push" for k, _ in events)
    assert any(k == "log" for k, _ in events)


def test_export_data_csv_and_json(tmp_path, monkeypatch):
    monkeypatch.setenv("POXIAO_GUANXING_DB", str(tmp_path / "gx.db"))
    db._initialized = False
    db.upsert_target("http://a.com", "a.com", "alive", ["Apache"], 2, 1)

    csv_content, mime, fname = db.export_data("csv")
    assert "text/csv" in mime and fname.endswith(".csv")
    lines = csv_content.splitlines()
    assert "url" in lines[0]               # 表头
    assert "http://a.com" in csv_content   # 数据行

    json_content, mime2, fname2 = db.export_data("json")
    assert "application/json" in mime2 and fname2.endswith(".json")
    data = json.loads(json_content)
    assert data["targets"][0]["url"] == "http://a.com"


def test_cli_monitor_export(tmp_path, monkeypatch):
    monkeypatch.setenv("POXIAO_GUANXING_DB", str(tmp_path / "gx.db"))
    db._initialized = False
    db.upsert_target("http://a.com", "a.com", "alive", ["Apache"], 1, 1)

    out = tmp_path / "out.json"
    monkeypatch.setitem(CMD_MAP, "monitor", cmd_monitor)
    monkeypatch.setattr(sys, "argv",
                        ["poxiao", "monitor", "export", "--format", "json", "-o", str(out)])
    cli_main()
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8"))["targets"][0]["url"] == "http://a.com"
