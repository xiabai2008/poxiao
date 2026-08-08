"""AI 模板生成测试（A1：mock LLM API，无真实网络）"""

import asyncio

import pytest

from tools import ai_template


def _llm_resp(content):
    class _Resp:
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": content}}]}

    return _Resp()


GOOD_TEMPLATE = """```yaml
id: test-ai-detection
info:
  name: "Test AI Detection"
  author: "poxiao-ai"
  severity: high
  description: "Detects test marker"
  tags: "test,detect"
http:
  method: GET
  path:
    - "{{BaseURL}}/check"
  matchers:
    - type: word
      words:
        - "vulnerable-marker"
"""
BAD_TEMPLATE = """```yaml
id: bad-template
info:
  name: "Bad"
  severity: critical
http:
  method: GET
  path:
    - "{{BaseURL}}/"
  matchers:
    - type: xpath
      xpath: ["//a"]
"""


class TestExtractYaml:
    def test_fenced_yaml(self):
        out = ai_template._extract_yaml("explain\n```yaml\nid: x\n```\n")
        assert out == "id: x"

    def test_unfenced(self):
        out = ai_template._extract_yaml("id: x\ninfo:\n  name: n\n")
        assert out.startswith("id: x")

    def test_empty(self):
        assert ai_template._extract_yaml("```yaml\n```") == ""


class TestValidateGenerated:
    def test_valid_template(self):
        raw = {"id": "t", "info": {"severity": "high"}, "http": {"method": "GET"}}
        check = ai_template.validate_generated(raw, "id: t\ninfo:\n  severity: high\nhttp:\n  method: GET\n")
        assert check["ok"] is True

    def test_missing_id(self):
        check = ai_template.validate_generated({"info": {}}, "info:\n  name: x\n")
        assert check["ok"] is False
        assert "id" in " ".join(check["issues"])

    def test_unsupported_matcher(self):
        raw = {"id": "t", "info": {"severity": "high"},
               "http": {"matchers": [{"type": "xpath"}]}}
        check = ai_template.validate_generated(raw, "")
        assert check["ok"] is False
        assert any("xpath" in i for i in check["issues"])

    def test_unknown_severity(self):
        raw = {"id": "t", "info": {"severity": "mega"}, "http": {"method": "GET"}}
        check = ai_template.validate_generated(raw, "")
        assert check["ok"] is False


class TestGenerateTemplate:
    def test_success_flow(self, monkeypatch):
        async def fake_post(url, headers=None, json=None):
            return _llm_resp(GOOD_TEMPLATE)

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = fake_post
        result = asyncio.run(ai_template.generate_template(
            "test", api_key="sk-test", base_url="https://api.example.com/v1"))
        assert result["ok"] is True
        assert result["id"] == "test-ai-detection"
        assert "vulnerable-marker" in result["template"]

    def test_no_api_key(self):
        result = asyncio.run(ai_template.generate_template("test"))
        assert result["ok"] is False
        assert "POXIAO_LLM_API_KEY" in result["issues"][0]

    def test_bad_template_rejected(self, monkeypatch):
        async def fake_post(url, headers=None, json=None):
            return _llm_resp(BAD_TEMPLATE)

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = fake_post
        result = asyncio.run(ai_template.generate_template(
            "test", api_key="k", base_url="https://api.example.com/v1"))
        assert result["ok"] is False
        assert any("xpath" in i for i in result["issues"])

    def test_api_error(self, monkeypatch):
        class _ErrResp:
            status_code = 401

            def json(self):
                return {"error": {"message": "invalid key"}}

        async def fake_post(url, headers=None, json=None):
            return _ErrResp()

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = fake_post
        result = asyncio.run(ai_template.generate_template(
            "test", api_key="bad", base_url="https://api.example.com/v1"))
        assert result["ok"] is False
        assert "invalid key" in result["issues"][0]

    def test_network_error(self, monkeypatch):
        async def boom(url, headers=None, json=None):
            raise ConnectionError("offline")

        monkeypatch.setattr("httpx.AsyncClient", _FakeClient)
        _FakeClient.handler = boom
        result = asyncio.run(ai_template.generate_template(
            "test", api_key="k", base_url="https://api.example.com/v1"))
        assert result["ok"] is False


class TestSaveTemplate:
    def test_save(self, tmp_path):
        p = ai_template.save_template("id: x\n", str(tmp_path), "my-template")
        assert "my-template.yaml" in p
        assert "id: x" in open(p, encoding="utf-8").read()

    def test_save_sanitizes_id(self, tmp_path):
        p = ai_template.save_template("id: x\n", str(tmp_path), "Bad: ID/name!")
        name = p.split("\\")[-1].split("/")[-1]
        assert not name.startswith("-") and not name.endswith("-")
        assert " " not in name and ":" not in name


class _FakeClient:
    """替换 httpx.AsyncClient（async with 上下文 + post）"""

    handler = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        return await type(self).handler(url, headers=headers, json=json)
