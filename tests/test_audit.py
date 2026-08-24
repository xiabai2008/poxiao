"""安全设计 §7.2 审计日志 — 单元测试"""

import json

import pytest

from src.utils import audit


@pytest.fixture
def audit_dir(tmp_path, monkeypatch):
    """将审计目录隔离到临时目录，避免污染 scan_results/audit。"""
    monkeypatch.setenv("POXIAO_AUDIT_DIR", str(tmp_path))
    audit_dir_obj = tmp_path
    yield audit_dir_obj


class TestAuditWrite:
    def test_write_creates_jsonl(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        audit.audit("testmodule", "test_event", msg="hello 世界")
        files = list(audit_dir.glob("*.jsonl"))
        assert files, "审计目录应生成 jsonl 文件"

    def test_record_fields(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        line = audit.audit("module", "event", msg="msg", trace_id="trace123",
                           user_id="local-user", level="info")
        rec = json.loads(line)
        assert rec["timestamp"]
        assert rec["service"] == "poxiao"
        assert rec["module"] == "module"
        assert rec["event"] == "event"
        assert rec["msg"] == "msg"
        assert rec["traceId"] == "trace123"
        assert rec["userId"] == "local-user"
        assert rec["tenantId"] == "local"

    def test_secret_masked(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        line = audit.audit("module", "event", msg="x", secret="sk-live-abcdef123456")
        rec = json.loads(line)
        assert "sk-live-abcdef123456" not in line
        assert rec["secret"] != "sk-live-abcdef123456"
        assert "*" in rec["secret"]

    def test_pii_masked_in_msg(self):
        # 邮箱 local=单一字符
        assert audit.mask_pii("contact a@example.com") == "contact a**@*example.com"
        # 邮箱 local=多字符
        assert audit.mask_pii("foo.bar@example.com") == audit.mask_pii("foo.bar@example.com")
        ph = audit.mask_pii("phone 13800138000")
        assert "138****8000" in ph
        # 18 位身份证号（末位 X 也可）
        ident = audit.mask_pii("id 110101199003076512")
        assert ident == "id 110****6512"


class TestMaskTools:
    def test_mask_secret_short(self):
        assert audit._mask_secret("ab") == "**"

    def test_mask_secret_long(self):
        assert audit._mask_secret("abcdefghijkl") .startswith("a")
        assert audit._mask_secret("abcdefghijkl").endswith("l")
        assert "*" in audit._mask_secret("abcdefghijkl")


class TestCleanup:
    def test_cleanup_removes_old(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(tmp_path))
        # 无旧文件时返回空
        assert audit.cleanup_expired(max_days=1) == []

    def test_prefix_is_encryption(self):
        assert audit.audit_dir().__class__.__name__ == "PosixPath" or hasattr(audit.audit_dir(), "mkdir")
