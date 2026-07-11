"""CVE 匹配器单元测试（版本范围解析 / 组件匹配 / 漏洞结果）"""

import pytest

from src.dawn.cve_match import CVEMatcher, VulnMatch


@pytest.fixture
def matcher():
    return CVEMatcher()


class TestParseVersion:
    def test_simple(self):
        assert CVEMatcher._parse_version("1.18.0") == ([1, 18, 0], "")

    def test_leading_v(self):
        assert CVEMatcher._parse_version("v1.18.0") == ([1, 18, 0], "")

    def test_suffix_rc(self):
        assert CVEMatcher._parse_version("1.18.0-rc1") == ([1, 18, 0], "-rc1")

    def test_no_digits(self):
        assert CVEMatcher._parse_version("notaversion") == ([], "")

    def test_empty(self):
        assert CVEMatcher._parse_version("") == ([], "")


class TestSuffixPenalty:
    def test_none(self):
        assert CVEMatcher._suffix_penalty("") == 0

    def test_rc(self):
        assert CVEMatcher._suffix_penalty("-rc1") == -1

    def test_alpha(self):
        assert CVEMatcher._suffix_penalty("-alpha") == -1

    def test_patch(self):
        assert CVEMatcher._suffix_penalty("-p1") == 1

    def test_pl(self):
        assert CVEMatcher._suffix_penalty("-pl1") == 1

    def test_unknown(self):
        assert CVEMatcher._suffix_penalty("-mystery") == -1


class TestVersionInRange:
    def test_less_than_true(self):
        assert CVEMatcher._version_in_range("1.18.0", "< 1.20.1") is True

    def test_less_than_false(self):
        assert CVEMatcher._version_in_range("1.21.0", "< 1.20.1") is False

    def test_less_equal_true(self):
        assert CVEMatcher._version_in_range("1.20.1", "<= 1.20.1") is True

    def test_greater_than_true(self):
        assert CVEMatcher._version_in_range("1.20.1", "> 1.20.0") is True

    def test_greater_equal_true(self):
        assert CVEMatcher._version_in_range("1.20.1", ">= 1.20.1") is True

    def test_plus_shorthand(self):
        assert CVEMatcher._version_in_range("1.20.2", "1.20.1+") is True

    def test_range_inside(self):
        assert CVEMatcher._version_in_range("1.3.0", "1.2.3 - 1.5.0") is True

    def test_range_outside(self):
        assert CVEMatcher._version_in_range("1.1.0", "1.2.3 - 1.5.0") is False

    def test_exact_match(self):
        assert CVEMatcher._version_in_range("2.4.49", "2.4.49") is True

    def test_exact_mismatch(self):
        assert CVEMatcher._version_in_range("2.4.50", "2.4.49") is False

    def test_multi_branch_match(self):
        assert CVEMatcher._version_in_range("7.50", "/ < 7.58 / < 8.5.1") is True

    def test_multi_branch_no_match(self):
        assert CVEMatcher._version_in_range("9.0", "/ < 7.58 / < 8.5.1") is False

    def test_unparseable_version(self):
        assert CVEMatcher._version_in_range("abc", "< 1.20.1") is False

    def test_unparseable_affected(self):
        assert CVEMatcher._version_in_range("1.20.1", "garbage") is False


class TestIsCritical:
    def test_critical(self):
        assert VulnMatch(severity="CRITICAL").is_critical is True

    def test_high(self):
        assert VulnMatch(severity="HIGH").is_critical is True

    def test_medium(self):
        assert VulnMatch(severity="MEDIUM").is_critical is False

    def test_cvss_threshold(self):
        assert VulnMatch(cvss_score=7.5).is_critical is True

    def test_low(self):
        assert VulnMatch(severity="LOW", cvss_score=3.0).is_critical is False


class TestMatch:
    def test_match_with_version(self, matcher):
        res = matcher.match("nginx", "1.18.0")
        assert isinstance(res, list) and len(res) > 0
        assert all(isinstance(r, VulnMatch) for r in res)
        assert all(r.component == "nginx" for r in res)

    def test_match_without_version_lists_all(self, matcher):
        res = matcher.match("nginx")
        assert len(res) > 1

    def test_match_unknown_component(self, matcher):
        assert matcher.match("does-not-exist") == []

    def test_match_batch(self, matcher):
        res = matcher.match_batch({"nginx": "1.18.0", "php": "7.4.0"})
        assert len(res) > 0

    def test_to_vuln(self, matcher):
        vm = matcher._to_vuln({
            "cve": "CVE-X", "component": "x", "description": "d",
            "severity": "HIGH", "cvss": 9.0, "affected": "< 1.0", "fixed": "1.0",
        })
        assert vm.cve_id == "CVE-X"
        assert vm.match_type == "local"


class TestDbMeta:
    def test_db_size(self, matcher):
        assert matcher.db_size > 0

    def test_db_components(self, matcher):
        assert "nginx" in matcher.db_components()
