"""P2-5 SRC 报告平台格式增强单测：butian / vulbox / cnvd 专属字段"""

from src.dawn.src_reporter import SRCReporter


def _reporter():
    return SRCReporter()


def test_platform_fields_distinct():
    r = _reporter()
    bt = r.platform_fields("butian")
    vb = r.platform_fields("vulbox")
    cv = r.platform_fields("cnvd")
    # 每个平台至少声明 3 个专属字段
    assert len(bt) >= 3 and len(vb) >= 3 and len(cv) >= 3
    # 三平台字段 key 不完全相同（体现格式差异）
    bt_keys = {k for _, k in bt}
    vb_keys = {k for _, k in vb}
    cv_keys = {k for _, k in cv}
    assert "vendor" in bt_keys
    assert "condition" in vb_keys
    assert "affected_product" in cv_keys
    # 平台差异
    assert bt_keys != vb_keys


def test_butian_includes_vendor_field():
    r = _reporter()
    out = r.generate_vuln_report(
        title="[t] 测试漏洞",
        severity="high",
        vuln_url="http://example.com/a",
        vuln_type="git",
        description="desc",
        steps=["1.x", "2.y"],
        platform="butian",
        meta={"vendor": "示例厂商", "vuln_type_cn": "Git泄露", "submit_type": "事件型"},
    )
    assert "厂商名称" in out
    assert "示例厂商" in out
    assert "提交类型" in out


def test_vulbox_includes_condition_field():
    r = _reporter()
    out = r.generate_vuln_report(
        title="[t] 测试漏洞",
        severity="high",
        vuln_url="http://example.com/a",
        vuln_type="api",
        description="desc",
        steps=["1.x"],
        platform="vulbox",
        meta={"title": "示例漏洞", "condition": "无需认证", "impact": "信息泄露"},
    )
    assert "利用条件" in out
    assert "无需认证" in out
    assert "漏洞危害" in out


def test_cnvd_includes_affected_product():
    r = _reporter()
    out = r.generate_vuln_report(
        title="[t] 测试漏洞",
        severity="high",
        vuln_url="http://example.com/a",
        vuln_type="actuator",
        description="desc",
        steps=["1.x"],
        platform="cnvd",
        meta={"affected_product": "Spring Boot 2.x", "vuln_type_cn": "配置不当", "severity_cn": "高危"},
    )
    assert "影响产品" in out
    assert "Spring Boot 2.x" in out
    assert "危害级别" in out  # cnvd 平台 title 字段


def test_meta_empty_no_extra_lines():
    r = _reporter()
    out = r.generate_vuln_report(
        title="[t] 测试",
        severity="low",
        vuln_url="http://x/a",
        vuln_type="info_leak",
        description="d",
        steps=["1"],
        platform="butian",
    )
    # 未提供 meta 时不应出现平台专属 label
    assert "厂商名称" not in out


def test_batch_uses_platform_field():
    r = _reporter()
    scan = [{
        "host": "example.com",
        "target_url": "http://example.com",
        "sensitive_paths": [
            {"category": "git", "url": "http://example.com/.git/config", "status": 200,
             "content_preview": "repositoryformatversion"}
        ],
        "cve_matches": [],
    }]
    res = r.generate_batch(scan, output_dir="scan_results", platform="cnvd")
    assert res["platform"] == "cnvd"
    assert res["total"] >= 1
    # cnvd 报告应含影响产品字段（来自 meta 透传需显式，这里校验平台格式 header）
    assert "危害级别" in res["reports"][0]["report"]
