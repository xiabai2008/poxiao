"""模板精选筛选测试（P2-4：community → 正式库候选）"""

import pytest

from tools.template_select import (
    select_candidates, is_high_value, has_high_risk_type, recent_cve,
)


def _write(d, name, content):
    f = d / name
    f.write_text(content, encoding="utf-8")
    return f


@pytest.fixture
def community(tmp_path):
    d = tmp_path / "community"
    d.mkdir()
    # 国内组件 high（seeyon 未授权）
    _write(d, "seeyon.yaml",
           'id: seeyon-unauth\ninfo:\n  name: "Seeyon Unauthorized"\n'
           '  severity: high\n  tags: "seeyon,unauth,cn"\n'
           'http:\n  method: GET\n  path:\n    - "{{BaseURL}}/seeyon/x"\n')
    # CVE 2025 critical
    _write(d, "cve2025.yaml",
           'id: CVE-2025-10001\ninfo:\n  name: "CVE-2025 RCE"\n'
           '  severity: critical\n  tags: "cve,rce"\n'
           'http:\n  method: GET\n  path:\n    - "{{BaseURL}}/poc"\n')
    # 低危（不应入选）
    _write(d, "low.yaml",
           'id: low-info\ninfo:\n  name: "Low"\n  severity: low\n'
           'http:\n  method: GET\n  path:\n    - "{{BaseURL}}/"\n')
    # 中危 CVE（min_score 门槛下可能入选）
    _write(d, "cve2020.yaml",
           'id: CVE-2020-9999\ninfo:\n  name: "Old CVE"\n'
           '  severity: high\n  tags: "cve"\n'
           'http:\n  method: GET\n  path:\n    - "{{BaseURL}}/old"\n')
    return d


class TestHeuristics:
    def test_is_high_value(self):
        assert is_high_value({"info": {"tags": "seeyon,unauth"}}, "x") is True
        assert is_high_value({"info": {"tags": "cve,misc"}}, "x") is False

    def test_high_risk_type(self):
        assert has_high_risk_type({"info": {"tags": "cve,rce"}}) is True
        assert has_high_risk_type({"info": {"tags": "info"}}) is False

    def test_recent_cve(self):
        assert recent_cve("CVE-2024-1234") == 2024
        assert recent_cve("no-cve-here") == 0


class TestSelectCandidates:
    def test_filters_low_severity(self, community):
        c = select_candidates(community)
        ids = {x["id"] for x in c}
        assert "low-info" not in ids
        assert "seeyon-unauth" in ids
        assert "CVE-2025-10001" in ids

    def test_min_score_filters_old_cve(self, community):
        c = select_candidates(community, min_score=6)
        ids = {x["id"] for x in c}
        # CVE-2020-9999: score = cve(1) + high(0) = 1 < 6 → 不入选
        assert "CVE-2020-9999" not in ids

    def test_cn_forced_despite_low_score(self, community):
        """国内组件强制入选：seeyon 仅命中关键词（score 3），min_score=6 仍入选"""
        c = select_candidates(community, min_score=6)
        ids = {x["id"] for x in c}
        assert "seeyon-unauth" in ids

    def test_priority_order(self, community):
        c = select_candidates(community)
        assert c[0]["score"] >= c[-1]["score"]
