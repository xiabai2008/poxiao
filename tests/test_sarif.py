"""SARIF 2.1.0 输出测试（P1-A：对齐 GitHub Code Scanning 格式）"""

import json

from src.utils.sarif import build_sarif, write_sarif, SARIF_SCHEMA, SARIF_VERSION


def _sample_summary():
    return {
        "scan_time": "2026-08-08 10:00:00",
        "session_id": "20260808_100000",
        "total": 2,
        "targets": [
            {
                "target_url": "https://example.com",
                "host": "example.com",
                "alive": True,
                "status_code": 200,
                "tech_tags": ["nginx/1.18.0"],
                "cve_matches": [
                    {"cve": "CVE-2025-24813", "severity": "CRITICAL",
                     "description": "Apache Tomcat 反序列化 RCE"},
                    {"cve": "CVE-2023-1234", "severity": "medium",
                     "description": "demo medium cve"},
                ],
                "sensitive_paths": [
                    {"url": "https://example.com/.git/config", "status": 200,
                     "size": 100, "category": "git"},
                    {"url": "https://example.com/swagger-ui.html", "status": 200,
                     "size": 200, "category": "swagger"},
                ],
                "error": "",
            },
            {
                "target_url": "https://dead.example.com",
                "host": "dead.example.com",
                "alive": False,
                "error": "timeout",
            },
        ],
    }


class TestBuildSarif:
    def test_schema_and_version(self):
        doc = build_sarif(_sample_summary())
        assert doc["$schema"] == SARIF_SCHEMA
        assert doc["version"] == SARIF_VERSION
        assert doc["runs"][0]["tool"]["driver"]["name"] == "poxiao"

    def test_rules_deduplicated_and_sorted(self):
        doc = build_sarif(_sample_summary())
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        assert ids == sorted(ids)
        # cve/ + sensitive/ 规则各 2 条（去重）
        assert "cve/CVE-2025-24813" in ids
        assert "sensitive/git" in ids
        assert len(ids) == 4

    def test_dead_targets_excluded(self):
        doc = build_sarif(_sample_summary())
        results = doc["runs"][0]["results"]
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]
        assert all("dead.example.com" not in u for u in uris)
        assert len(uris) == 4  # 2 CVE + 2 sensitive

    def test_severity_to_level(self):
        doc = build_sarif(_sample_summary())
        results = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
        assert results["cve/CVE-2025-24813"] == "error"
        assert results["cve/CVE-2023-1234"] == "warning"
        assert results["sensitive/git"] == "warning"
        assert results["sensitive/swagger"] == "note"

    def test_rule_default_configuration_level(self):
        doc = build_sarif(_sample_summary())
        rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert rules["cve/CVE-2025-24813"]["defaultConfiguration"]["level"] == "error"
        assert "cve" in rules["cve/CVE-2025-24813"]["properties"]

    def test_empty_summary(self):
        doc = build_sarif({"targets": []})
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []


class TestWriteSarif:
    def test_write_file(self, tmp_path):
        out = tmp_path / "report.sarif"
        path = write_sarif(_sample_summary(), str(out))
        assert path == str(out)
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"
