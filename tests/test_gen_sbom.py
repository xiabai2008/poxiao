"""P3-1 SBOM 生成测试（CycloneDX 结构 + 组件完整性）"""
import json
from pathlib import Path

from tools.gen_sbom import build_sbom


def test_sbom_structure_valid():
    sbom = build_sbom(with_hashes=False)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert isinstance(sbom["components"], list)
    assert sbom["metadata"]["component"]["name"] == "poxiao"
    assert "timestamp" in sbom["metadata"]


def test_sbom_components_well_formed():
    sbom = build_sbom(with_hashes=False)
    comps = sbom["components"]
    if not comps:
        # 未安装poxiao包时退化为空（仍合法），跳过字段断言
        return
    for c in comps:
        assert c["type"] == "library"
        assert c["name"]
        assert c["purl"].startswith("pkg:pypi/")
        if "version" in c:
            assert c["purl"].endswith("@" + c["version"])


def test_sbom_hashes_optional():
    sbom = build_sbom(with_hashes=True)
    comps = sbom["components"]
    if comps:
        # 有哈希时结构正确
        for c in comps:
            if "hashes" in c:
                assert c["hashes"][0]["alg"] == "SHA-256"
                assert len(c["hashes"][0]["content"]) == 64


def test_sbom_write_file(tmp_path):
    out = tmp_path / "sbom.json"
    from tools.gen_sbom import main
    code = main(["--out", str(out), "--no-hashes"])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    Path(out).unlink(missing_ok=True)
