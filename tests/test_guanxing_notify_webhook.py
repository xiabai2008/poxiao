"""观星 Webhook 通知 — 飞书/钉钉格式适配测试（P1-B）"""

import json
import threading

import httpx
import pytest

from src.guanxing import notify


SAMPLE_CHANGE = {
    "target_id": 1,
    "change_type": "tech_stack",
    "old_value": "nginx/1.18.0",
    "new_value": "nginx/1.25.3",
    "changed_at": "2026-08-08T10:00:00.000",
}


class _Cfg:
    """模拟 Config.get(section, key, default)"""

    def __init__(self, values=None):
        self._values = values or {}

    def get(self, section, key=None, default=None):
        if key is None:
            return self._values.get(section, {})
        return self._values.get(f"{section}.{key}", default)


class TestWebhookType:
    def test_auto_feishu(self, monkeypatch):
        monkeypatch.setattr(notify, "get_config", lambda: _Cfg())
        assert notify._webhook_type("https://open.feishu.cn/open-apis/bot/v2/hook/abc") == "feishu"
        assert notify._webhook_type("https://open.larksuite.com/xxx") == "feishu"

    def test_auto_dingtalk(self, monkeypatch):
        monkeypatch.setattr(notify, "get_config", lambda: _Cfg())
        assert notify._webhook_type("https://oapi.dingtalk.com/robot/send?access_token=x") == "dingtalk"

    def test_raw_default(self, monkeypatch):
        monkeypatch.setattr(notify, "get_config", lambda: _Cfg())
        assert notify._webhook_type("https://example.com/webhook") == "raw"

    def test_configured_override(self, monkeypatch):
        monkeypatch.setattr(notify, "get_config",
                            lambda: _Cfg({"monitor.webhook_type": "dingtalk"}))
        assert notify._webhook_type("https://open.feishu.cn/x") == "dingtalk"


class TestBuildPayload:
    def test_feishu_payload(self):
        p = notify._build_payload("https://open.feishu.cn/open-apis/bot/v2/hook/x", SAMPLE_CHANGE)
        assert p["msg_type"] == "text"
        assert "观星资产变更" in p["content"]["text"]
        assert "nginx/1.18.0" in p["content"]["text"]

    def test_dingtalk_payload(self):
        p = notify._build_payload("https://oapi.dingtalk.com/robot/send?access_token=x", SAMPLE_CHANGE)
        assert p["msgtype"] == "markdown"
        assert "nginx/1.25.3" in p["markdown"]["text"]

    def test_raw_payload_backward_compatible(self):
        p = notify._build_payload("https://example.com/hook", SAMPLE_CHANGE)
        assert p == SAMPLE_CHANGE


class TestPostWebhook:
    def test_posts_feishu_payload(self, monkeypatch):
        captured = {}

        class FakeResp:
            status_code = 200

        def fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["payload"] = json
            return FakeResp()

        monkeypatch.setattr(httpx, "post", fake_post)
        notify._post_webhook("https://open.feishu.cn/open-apis/bot/v2/hook/x", SAMPLE_CHANGE)
        assert captured["url"].startswith("https://open.feishu.cn")
        assert captured["payload"]["msg_type"] == "text"

    def test_failure_silently_ignored(self, monkeypatch, capsys):
        def boom(url, json=None, timeout=None):
            raise ConnectionError("network down")

        monkeypatch.setattr(httpx, "post", boom)
        notify._post_webhook("https://oapi.dingtalk.com/robot/send?access_token=x", SAMPLE_CHANGE)
        out = capsys.readouterr().out
        assert "推送失败" in out  # 仅告警不抛出

    def test_push_change_event_no_url_noop(self, monkeypatch):
        monkeypatch.setattr(notify, "get_config", lambda: _Cfg())
        notify.push_change_event(SAMPLE_CHANGE)  # 不应启动线程/抛错
