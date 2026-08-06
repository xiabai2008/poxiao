"""惊蛰漏洞验证器单元测试（jingzhe/jingzhe.py）— mock HTTP，覆盖纯逻辑与验证分支

低 ROI 模块（基线 11%）覆盖率提升：phpinfo/DS_Store 解析、评分、各专项检测
（git/swagger/actuator/config/dir_listing/server_info/api/default_creds/路径扫描）、
verify 编排。
"""

import asyncio
from unittest.mock import AsyncMock, patch

from src.jingzhe.jingzhe import JingZhe, VerifiedFinding


# ── 假响应 / 假客户端 ──────────────────────────────────────

class _Resp:
    def __init__(self, status=200, text="", content=None, headers=None):
        self.status_code = status
        self.text = text
        self.content = content if content is not None else text.encode("utf-8", "ignore")
        self.headers = headers or {}


class _Client:
    def __init__(self, routes=None):
        self.routes = routes or {}

    async def get(self, url, **kw):
        for key, resp in self.routes.items():
            if key in url:
                return resp
        return _Resp(404, "")

    async def post(self, url, **kw):
        # 记录入参，便于断言默认口令尝试
        self.last_post_data = kw.get("data")
        for key, resp in self.routes.items():
            if key in url:
                return resp
        return _Resp(404, "")


class _AsyncClientCtx:
    def __init__(self, client):
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *a):
        return False


# ── phpinfo 解析 ───────────────────────────────────────────

class TestParsePhpInfo:
    def test_extract(self):
        html = (
            "<tr><td class='e'>PHP Version</td><td class='v'>8.1.2</td></tr>"
            "<tr><td class='e'>Server API</td><td class='v'>FPM/FastCGI</td></tr>"
            "<tr><td class='e'>DOCUMENT_ROOT</td><td class='v'>/var/www</td></tr>"
            "<h2>Core</h2><h2>ctype</h2><h2>json</h2>"
        )
        info = JingZhe()._parse_phpinfo(html)
        assert info["php_version"] == "8.1.2"
        assert info["server_api"] == "FPM/FastCGI"
        assert info["doc_root"] == "/var/www"
        assert "ctype" in info["extensions"]


# ── DS_Store 解析 ──────────────────────────────────────────

class TestParseDsStore:
    def test_extract_filenames(self):
        name = "secret.txt"
        body = b""
        for ch in name:
            body += bytes([0, ord(ch)])
        content = b"\x00\x00\x00\x01" + body + b"\x00" * 100
        names = JingZhe()._parse_ds_store(content)
        assert "secret.txt" in names

    def test_empty(self):
        assert JingZhe()._parse_ds_store(b"\x01\x02\x03\x04") == []


# ── 评分 ───────────────────────────────────────────────────

class TestScore:
    def test_empty(self):
        s = JingZhe().score([])
        assert s["total_score"] == 0
        assert "安全" in s["risk"]

    def test_high(self):
        s = JingZhe().score([
            VerifiedFinding(url="u", finding_type="t", exploitable=True, confidence="HIGH"),
            VerifiedFinding(url="u", finding_type="t", exploitable=True, confidence="MEDIUM"),
            VerifiedFinding(url="u", finding_type="t", exploitable=False, confidence="LOW"),
        ])
        assert s["high"] == 1 and s["medium"] == 1 and s["low"] == 1
        assert s["total_score"] == 10 + 5 + 2
        assert "中风险" in s["risk"]

    def test_low_risk(self):
        s = JingZhe().score([VerifiedFinding(url="u", finding_type="t",
                                             exploitable=False, confidence="LOW")])
        assert s["total_score"] == 2
        assert "低风险" in s["risk"]


# ── 专项检测 ───────────────────────────────────────────────

class TestChecks:
    def test_git(self):
        client = _Client({"/.git/HEAD": _Resp(200,
                            text="ref: refs/heads/master\n" + "x" * 40,
                            content=b"ref: refs/heads/master\n" + b"x" * 40),
                           "/.git/config": _Resp(200,
                            text="[core]\n" + "x" * 40,
                            content=b"[core]\n" + b"x" * 40)})
        f = asyncio.run(JingZhe()._check_git("http://t", client))
        assert f is not None
        assert f.finding_type == "git"
        assert f.confidence == "HIGH"  # 2 个文件

    def test_git_none(self):
        client = _Client()
        assert asyncio.run(JingZhe()._check_git("http://t", client)) is None

    def test_swagger(self):
        client = _Client({"/v2/api-docs": _Resp(
            200, text='{"swagger":"2.0","paths":{"/a":{}}}',
            content=b'{"swagger":"2.0","paths":{"/a":{}}}')})
        f = asyncio.run(JingZhe()._check_swagger("http://t", client))
        assert f is not None and f.finding_type == "api"

    def test_actuator(self):
        client = _Client({"/actuator/health": _Resp(
            200, text='{"status":"UP"}' * 3, content=b'{"status":"UP"}' * 3)})
        f = asyncio.run(JingZhe()._check_actuator("http://t", client))
        assert f is not None and f.exploitable is True

    def test_actuator_403(self):
        client = _Client({"/actuator/health": _Resp(403)})
        f = asyncio.run(JingZhe()._check_actuator("http://t", client))
        assert f is not None
        assert f.exploitable is False  # 仅 [403]，非 [200]

    def test_config(self):
        text = "<?php\n$db = new PDO('mysql:host=localhost', 'root', 'x');\n" * 4
        client = _Client({"/config.php": _Resp(200, text=text,
                                               content=text.encode())})
        f = asyncio.run(JingZhe()._check_config("http://t/config.php", client))
        assert f is not None and f.finding_type == "config"

    def test_config_html_excluded(self):
        client = _Client({"/config.php": _Resp(200,
                        text="<!doctype html><html>not config</html>")})
        assert asyncio.run(JingZhe()._check_config("http://t/config.php",
                                                   client)) is None

    def test_dir_listing(self):
        client = _Client({"http://t": _Resp(200,
                        text="<title>Index of /</title>\nDirectory listing")})
        f = asyncio.run(JingZhe()._check_dir_listing("http://t", client))
        assert f is not None and f.finding_type == "dir_listing"

    def test_dir_listing_none(self):
        client = _Client({"http://t": _Resp(200, text="<h1>Home</h1>")})
        assert asyncio.run(JingZhe()._check_dir_listing("http://t",
                                                        client)) is None

    def test_server_info(self):
        client = _Client({"http://t": _Resp(200, text="",
                        headers={"server": "nginx", "x-powered-by": "PHP/7"})})
        f = asyncio.run(JingZhe()._check_server_info("http://t", client))
        assert f is not None and f.finding_type == "info_leak"

    def test_server_info_insufficient(self):
        client = _Client({"base": _Resp(200, text="", headers={"server": "nginx"})})
        assert asyncio.run(JingZhe()._check_server_info("http://t",
                                                        client)) is None

    def test_api_endpoints(self):
        client = _Client({"/api/user": _Resp(200, text='{"id":1}',
                        content=b'{"id":1}' * 20)})
        fs = asyncio.run(JingZhe()._check_api_endpoints("http://t", client))
        assert any(f.finding_type == "api" for f in fs)

    def test_default_creds(self):
        # 登录成功特征
        client = _Client({"http://t": _Resp(200, text="welcome 后台 dashboard 欢迎")})
        fs = asyncio.run(JingZhe()._check_default_creds("http://t", client))
        assert fs and fs[0].exploitable is True


# ── 路径扫描 ───────────────────────────────────────────────

class TestScanSinglePath:
    def test_gitignore(self):
        text = "passwords.txt\nconfig.yml\nsecrets/\n" * 5
        client = _Client({"/.gitignore": _Resp(200, text=text,
                                               content=text.encode())})
        fs = asyncio.run(JingZhe()._scan_single_path(
            "http://t", "/.gitignore", client, lambda r: False))
        assert any(f.finding_type == "git" for f in fs)

    def test_config_php(self):
        text = "<?php\n$conn = new PDO('mysql:host=localhost', 'root', 'x');\n" * 4
        client = _Client({"/config.php": _Resp(200, text=text,
                                               content=text.encode())})
        fs = asyncio.run(JingZhe()._scan_single_path(
            "http://t", "/config.php", client, lambda r: False))
        assert any(f.finding_type == "config" for f in fs)

    def test_ds_store(self):
        name = "secret.txt"
        body = b""
        for ch in name:
            body += bytes([0, ord(ch)])
        content = b"\x00\x00\x00\x01" + body + b"\x00" * 100
        client = _Client({"/.DS_Store": _Resp(200, content=content)})
        fs = asyncio.run(JingZhe()._scan_single_path(
            "http://t", "/.DS_Store", client, lambda r: False))
        assert any(f.finding_type == "source" for f in fs)

    def test_backup_zip(self):
        content = b"PK\x03\x04" + b"\x00" * 100
        client = _Client({"/backup.zip": _Resp(200, content=content)})
        fs = asyncio.run(JingZhe()._scan_single_path(
            "http://t", "/backup.zip", client, lambda r: False))
        assert any(f.finding_type == "backup" for f in fs)

    def test_admin_login_low(self):
        # 登录表单存在，但默认口令失败
        text = "<form><input type=password>登录</form>"
        client = _Client({"/admin/login": _Resp(200, text=text),
                          "base": _Resp(200, text="密码错误 用户名不存在")})
        fs = asyncio.run(JingZhe()._scan_single_path(
            "http://t", "/admin/login", client, lambda r: False))
        assert any(f.finding_type == "admin" for f in fs)

    def test_phpinfo(self):
        html = ("<tr><td class='e'>PHP Version</td><td class='v'>8.1.2</td></tr>"
                "<tr><td class='e'>Server API</td><td class='v'>FPM/FastCGI</td></tr>")
        client = _Client({"/phpinfo.php": _Resp(200, text=html)})
        fs = asyncio.run(JingZhe()._scan_single_path(
            "http://t", "/phpinfo.php", client, lambda r: False))
        assert any(f.finding_type == "debug" for f in fs)

    def test_catchall_skipped(self):
        client = _Client({"/test.php": _Resp(200, text="<html>catchall</html>")})
        fs = asyncio.run(JingZhe()._scan_single_path(
            "http://t", "/test.php", client, lambda r: True))  # 总是 catch-all
        assert fs == []


# ── verify 编排 ────────────────────────────────────────────

class TestVerify:
    def test_verify_no_findings(self):
        client = _Client()  # 全部 404
        with patch("src.jingzhe.jingzhe.httpx.AsyncClient",
                   return_value=_AsyncClientCtx(client)):
            fs = asyncio.run(JingZhe().verify("http://t"))
        assert fs == []

    def test_verify_with_git(self):
        client = _Client({
            "/.git/HEAD": _Resp(200, text="ref: refs/heads/master\n" + "x" * 40,
                                content=b"ref: refs/heads/master\n" + b"x" * 40),
            "/.git/config": _Resp(200, text="[core]\n" + "x" * 40,
                                  content=b"[core]\n" + b"x" * 40),
        })
        with patch("src.jingzhe.jingzhe.httpx.AsyncClient",
                   return_value=_AsyncClientCtx(client)):
            fs = asyncio.run(JingZhe().verify("http://t"))
        assert any(f.finding_type == "git" for f in fs)

    def test_verify_from_scan(self, tmp_path):
        jz = JingZhe()
        jz.verify = AsyncMock(return_value=[VerifiedFinding(url="http://t",
                                                            finding_type="t",
                                                            exploitable=True,
                                                            confidence="HIGH")])
        summary = tmp_path / "scan.json"
        summary.write_text('{"targets": [{"target_url": "http://t"}]}',
                            encoding="utf-8")
        fs = asyncio.run(jz.verify_from_scan(str(summary)))
        assert len(fs) == 1
