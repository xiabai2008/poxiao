"""观星数据库层单元测试（CRUD / 查询 / 统计 / 导出）"""

import json

import pytest

from src.guanxing import db


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """为每个测试提供独立的临时数据库，并重置迁移哨兵"""
    db_file = tmp_path / "guanxing.db"
    monkeypatch.setattr(db, "DB_PATH", db_file)
    monkeypatch.setattr(db, "_initialized", False)
    db.init_db()
    yield db_file
    # 清理 WAL 产生的附属文件
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / f"guanxing.db{suffix}"
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass


class TestUpsertTarget:
    def test_insert_new(self, temp_db):
        tid = db.upsert_target("http://a.com", "a.com", "alive", ["nginx"], 2, 1)
        assert isinstance(tid, int) and tid > 0

    def test_update_existing_returns_same_id(self, temp_db):
        tid1 = db.upsert_target("http://a.com", "a.com", "alive")
        tid2 = db.upsert_target("http://a.com", "a.com", "dead")
        assert tid1 == tid2

    def test_tech_change_records_change(self, temp_db):
        db.upsert_target("http://a.com", "a.com", "alive", ["nginx"])
        db.upsert_target("http://a.com", "a.com", "alive", ["apache"])
        changes = db.get_changes(limit=100)
        assert any(c["change_type"] == "tech_change" for c in changes)


class TestQueries:
    def test_get_target_by_id_missing(self, temp_db):
        assert db.get_target_by_id(999) is None

    def test_get_target_by_id(self, temp_db):
        tid = db.upsert_target("http://a.com", "a.com", "alive")
        row = db.get_target_by_id(tid)
        assert row["url"] == "http://a.com"
        assert row["tech_stack"] == []  # 默认空列表已反序列化

    def test_get_targets_total(self, temp_db):
        db.upsert_target("http://a.com", "a.com", "alive")
        db.upsert_target("http://b.com", "b.com", "dead")
        rows, total = db.get_targets()
        assert total == 2
        assert len(rows) == 2

    def test_get_targets_filter_status(self, temp_db):
        db.upsert_target("http://a.com", "a.com", "alive")
        db.upsert_target("http://b.com", "b.com", "dead")
        rows, total = db.get_targets(status="alive")
        assert total == 1
        assert rows[0]["host"] == "a.com"

    def test_get_targets_search(self, temp_db):
        db.upsert_target("http://example.com", "example.com", "alive")
        db.upsert_target("http://other.net", "other.net", "alive")
        rows, total = db.get_targets(search="example")
        assert total == 1

    def test_get_targets_pagination(self, temp_db):
        for i in range(5):
            db.upsert_target(f"http://t{i}.com", f"t{i}.com", "alive")
        rows, total = db.get_targets(limit=2, offset=0)
        assert total == 5
        assert len(rows) == 2


class TestScans:
    def test_add_and_get_scans(self, temp_db):
        tid = db.upsert_target("http://a.com", "a.com", "alive")
        db.add_scan(tid, True, ["nginx"], ["/admin"], ["CVE-1"], 0.5)
        scans = db.get_scans(tid)
        assert len(scans) == 1
        assert scans[0]["alive"] == 1
        assert scans[0]["sensitive_paths"] == ["/admin"]


class TestStats:
    def test_empty_stats(self, temp_db):
        stats = db.get_stats()
        assert stats["total"] == 0
        assert stats["alive"] == 0
        assert stats["tech_distribution"] == {}

    def test_populated_stats(self, temp_db):
        db.upsert_target("http://a.com", "a.com", "alive", ["nginx", "php"], 3, 2)
        db.upsert_target("http://b.com", "b.com", "dead", ["nginx"], 0, 0)
        stats = db.get_stats()
        assert stats["total"] == 2
        assert stats["alive"] == 1
        assert stats["with_findings"] == 1
        assert stats["tech_distribution"] == {"nginx": 2, "php": 1}


class TestExport:
    def test_export_json(self, temp_db):
        db.upsert_target("http://a.com", "a.com", "alive", ["nginx"])
        content, mime, fname = db.export_data("json")
        assert mime == "application/json; charset=utf-8"
        data = json.loads(content)
        assert data["stats"]["total"] == 1

    def test_export_csv(self, temp_db):
        db.upsert_target("http://a.com", "a.com", "alive", ["nginx"])
        content, mime, fname = db.export_data("csv")
        assert mime.startswith("text/csv")
        assert "url,host" in content or "id,url" in content
        assert "http://a.com" in content


class TestRowToDict:
    def test_none_row(self, temp_db):
        assert db._row_to_dict(None) == {}


class TestImportFromSummary:
    def test_import(self, temp_db, tmp_path):
        summary = {
            "targets": [
                {"target_url": "http://x.com", "alive": True,
                 "tech": {"nginx": "1.0"}, "sensitive_paths": ["/a"],
                 "cve_matches": ["CVE-1"], "duration_sec": 1.5},
            ]
        }
        p = tmp_path / "summary.json"
        p.write_text(json.dumps(summary), encoding="utf-8")
        db.import_from_summary(str(p))
        rows, total = db.get_targets()
        assert total == 1
        assert rows[0]["status"] == "alive"
        scans = db.get_scans(rows[0]["id"])
        assert len(scans) == 1
