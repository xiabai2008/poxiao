"""模板同步工具测试（P1-G：nuclei-templates 拉取 → 解压 → 兼容性统计）"""

import io
import zipfile

import pytest

sys_path_hack = None


class TestSyncTemplates:
    def _make_zip(self):
        """构造 nuclei-templates 风格的 zip 归档"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("nuclei-templates-main/http/cves/http-cve.yaml",
                        'id: http-cve\ninfo:\n  name: "CVE"\n  severity: high\n'
                        'http:\n  method: GET\n  path:\n    - "{{BaseURL}}/"\n')
            zf.writestr("nuclei-templates-main/dns/cves/dns-cve.yaml",
                        'id: dns-cve\ninfo:\n  name: "DNS"\n  severity: high\n'
                        'dns:\n  name: "{{FQDN}}"\n')
            zf.writestr("nuclei-templates-main/http/misc/other.yaml",
                        'id: other\ninfo:\n  name: "Other"\n  severity: info\n'
                        'http:\n  method: GET\n')
        return buf.getvalue()

    def _fake_urlopen(self, zip_bytes):
        class _Resp:
            def __init__(self, data):
                self._data = data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a, **k):
                return self._data

        def urlopen(url, timeout=None):
            assert "codeload.github.com" in url
            return _Resp(zip_bytes)

        return urlopen

    def test_sync_extracts_http_only_and_stats(self, tmp_path, monkeypatch):
        from tools import template_sync as ts
        zip_bytes = self._make_zip()
        monkeypatch.setattr("urllib.request.urlopen", self._fake_urlopen(zip_bytes))

        target = tmp_path / "community"
        ok = ts.sync_templates(target, subdirs=["http"])
        assert ok is True

        # 只解压 http 子目录
        extracted = sorted(p.relative_to(target).as_posix()
                           for p in target.rglob("*.yaml"))
        assert "http/cves/http-cve.yaml" in extracted
        assert "dns/cves/dns-cve.yaml" not in extracted

        # zip 归档保留
        assert (target / "nuclei-templates-main.zip").exists()

    def test_sync_incompatible_stats(self, tmp_path, monkeypatch):
        from tools import template_sync as ts
        zip_bytes = self._make_zip()
        monkeypatch.setattr("urllib.request.urlopen", self._fake_urlopen(zip_bytes))

        target = tmp_path / "community"
        ts.sync_templates(target, subdirs=["http", "dns"])

        # 兼容性统计：http 模板可加载，dns 模板不兼容（无 http/requests 块）
        stats = {}
        # 直接验证：http 模板可被 loader 加载
        from src.xiazhi.loader import TemplateLoader
        loader = TemplateLoader(str(target))
        loaded = loader.load_all()
        assert any(t.id == "http-cve" for t in loaded)
        assert all(t.id != "dns-cve" for t in loaded)

    def test_download_failure_returns_false(self, tmp_path, monkeypatch):
        from tools import template_sync as ts

        def boom(url, timeout=None):
            raise ConnectionError("offline")

        monkeypatch.setattr("urllib.request.urlopen", boom)
        assert ts.sync_templates(tmp_path / "c") is False
