"""版本单一事实源一致性测试 (Phase 4)

断言 src/_version.py、pyproject.toml、README 头部版本、SARIF TOOL_VERSION
四方一致，防止版本号漂移。
"""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_pyproject_version() -> str:
    with open(ROOT / "pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    return data["project"]["version"]


def _load_readme_version() -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    first = text.splitlines()[0] if text.splitlines() else ""
    m = re.search(r"v(\d+\.\d+\.\d+)", first)
    return m.group(1) if m else ""


class TestVersionConsistency:
    def test_pyproject_matches_module(self):
        from src._version import VERSION
        assert VERSION == _load_pyproject_version()

    def test_sarif_tool_version_matches(self):
        from src.utils import sarif
        assert sarif.TOOL_VERSION == _load_pyproject_version()

    def test_readme_title_version_matches(self):
        from src._version import VERSION
        readme_v = _load_readme_version()
        assert readme_v and readme_v == VERSION, f"README 标题版本 {readme_v} ≠ {VERSION}"
