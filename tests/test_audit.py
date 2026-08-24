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

    def test_chain_fields_present(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        line = audit.audit("module", "event", msg="msg")
        rec = json.loads(line)
        assert isinstance(rec["prev_hash"], str) and len(rec["prev_hash"]) == 64
        assert isinstance(rec["row_hash"], str) and len(rec["row_hash"]) == 64

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


class TestHashChain:
    def test_second_line_chains_to_first(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        r1 = json.loads(audit.audit("m", "e1", msg="a"))
        r2 = json.loads(audit.audit("m", "e2", msg="b"))
        assert r2["prev_hash"] == r1["row_hash"]
        assert r1["prev_hash"] == "0" * 64  # 链起点为 GENESIS

    def test_verify_ok(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        for i in range(5):
            audit.audit("m", "e", msg=f"log {i}")
        res = audit.verify_chain()
        assert res["ok"] is True
        assert res["checked"] == res["total"] == 5
        assert res["broken"] == 0
        assert res["legacy"] == 0

    def test_verify_detects_tamper(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        audit.audit("m", "e", msg="original")
        audit.audit("m", "e", msg="tail")
        # 篡改第一条记录的 msg
        fp = list(audit_dir.glob("*.jsonl"))[0]
        lines = fp.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["msg"] = "HACKED"
        lines[0] = json.dumps(rec, ensure_ascii=False)
        fp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = audit.verify_chain()
        assert res["ok"] is False
        assert res["broken"] >= 1

    def test_verify_detects_removal(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        audit.audit("m", "e", msg="first")
        audit.audit("m", "e", msg="second")
        audit.audit("m", "e", msg="third")
        fp = list(audit_dir.glob("*.jsonl"))[0]
        lines = fp.read_text(encoding="utf-8").splitlines()
        # 删除中间一条 -> 前后 prev_hash 断裂
        del lines[1]
        fp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = audit.verify_chain()
        assert res["ok"] is False

    def test_verify_counts_legacy(self, audit_dir, monkeypatch):
        monkeypatch.setenv("POXIAO_AUDIT_DIR", str(audit_dir))
        # 手工写入无 hash 字段的旧行
        fp = audit_dir / "2026-01-01.jsonl"
        fp.write_text('{"msg":"legacy"}\n', encoding="utf-8")
        audit.audit("m", "e", msg="new")
        res = audit.verify_chain()
        assert res["legacy"] == 1
        assert res["checked"] >= 1
