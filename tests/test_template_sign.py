"""模板 ECDSA 签名/校验测试（P1-C：防供应链投毒）"""

import json
from pathlib import Path

import pytest

from src.xiazhi import template_sign
from src.xiazhi.template_sign import (
    generate_keypair, sign_file, verify_file,
    sign_directory, verify_directory, SIG_FILENAME,
)


@pytest.fixture
def keys(tmp_path):
    priv = str(tmp_path / "private.pem")
    pub = str(tmp_path / "public.pem")
    generate_keypair(priv, pub)
    return priv, pub


@pytest.fixture
def sample_template(tmp_path):
    d = tmp_path / "templates"
    d.mkdir()
    f = d / "test-vuln.yaml"
    f.write_text('id: test-vuln\ninfo:\n  name: "Test"\n  severity: high\nhttp:\n  method: GET\n  path:\n    - "{{BaseURL}}/x"\n', encoding="utf-8")
    return d, f


class TestKeypair:
    def test_generates_pem_files(self, tmp_path):
        priv, pub = generate_keypair(str(tmp_path / "a.pem"), str(tmp_path / "b.pem"))
        assert Path(priv).read_bytes().startswith(b"-----BEGIN")
        assert Path(pub).read_bytes().startswith(b"-----BEGIN")


class TestFileSignVerify:
    def test_roundtrip(self, keys, sample_template, tmp_path):
        _, f = sample_template
        sig = sign_file(f, keys[0])
        assert len(sig) > 40  # ECDSA P-256 签名 hex
        assert verify_file(f, sig, keys[1]) is True

    def test_tamper_detected(self, keys, sample_template):
        _, f = sample_template
        sig = sign_file(f, keys[0])
        f.write_text(f.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
        assert verify_file(f, sig, keys[1]) is False

    def test_wrong_key_rejected(self, keys, sample_template, tmp_path):
        _, f = sample_template
        sig = sign_file(f, keys[0])
        # 另一对密钥
        generate_keypair(str(tmp_path / "x.pem"), str(tmp_path / "y.pem"))
        assert verify_file(f, sig, str(tmp_path / "y.pem")) is False

    def test_garbage_signature_rejected(self, keys, sample_template):
        _, f = sample_template
        assert verify_file(f, "zznothex", keys[1]) is False


class TestDirectoryManifest:
    def test_sign_and_verify_ok(self, keys, sample_template, tmp_path):
        d, _ = sample_template
        sign_directory(d, keys[0])
        manifest = d / SIG_FILENAME
        assert manifest.exists()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        assert "test-vuln.yaml" in data

        status = verify_directory(d, keys[1])
        assert status == {"test-vuln.yaml": "ok"}

    def test_tamper_marks_bad(self, keys, sample_template):
        d, f = sample_template
        sign_directory(d, keys[0])
        f.write_text(f.read_text(encoding="utf-8") + "#x\n", encoding="utf-8")
        status = verify_directory(d, keys[1])
        assert status["test-vuln.yaml"] == "bad"

    def test_unsigned_file_marked(self, keys, sample_template):
        d, _ = sample_template
        sign_directory(d, keys[0])
        (d / "extra.yaml").write_text('id: extra\ninfo:\n  name: "X"\n', encoding="utf-8")
        status = verify_directory(d, keys[1])
        assert status["extra.yaml"] == "unsigned"
        assert status["test-vuln.yaml"] == "ok"

    def test_missing_manifest_empty(self, keys, sample_template):
        d, _ = sample_template
        assert verify_directory(d, keys[1]) == {}


class TestLoaderIntegration:
    def _make_loader_dir(self, tmp_path):
        d = tmp_path / "tpls"
        d.mkdir()
        good = d / "good.yaml"
        good.write_text(
            'id: good\ninfo:\n  name: "Good"\n  severity: info\n'
            'http:\n  method: GET\n  path:\n    - "{{BaseURL}}/"\n',
            encoding="utf-8",
        )
        return d, good

    def test_verify_signatures_filters_bad(self, tmp_path, keys):
        from src.xiazhi.loader import TemplateLoader
        d, good = self._make_loader_dir(tmp_path)
        sign_directory(d, keys[0])
        # 篡改 good → 全部被拒
        good.write_text(good.read_text(encoding="utf-8") + "#t\n", encoding="utf-8")

        loader = TemplateLoader(str(d))
        loaded = loader.load_all(verify_signatures=True, public_key_path=keys[1])
        assert loaded == []

    def test_verify_signatures_allows_ok(self, tmp_path, keys):
        from src.xiazhi.loader import TemplateLoader
        d, _ = self._make_loader_dir(tmp_path)
        sign_directory(d, keys[0])

        loader = TemplateLoader(str(d))
        loaded = loader.load_all(verify_signatures=True, public_key_path=keys[1])
        assert [t.id for t in loaded] == ["good"]

    def test_verify_off_by_default(self, tmp_path, keys):
        from src.xiazhi.loader import TemplateLoader
        d, good = self._make_loader_dir(tmp_path)
        good.write_text(good.read_text(encoding="utf-8") + "#t\n", encoding="utf-8")
        loader = TemplateLoader(str(d))
        assert len(loader.load_all()) == 1  # 默认不校验
