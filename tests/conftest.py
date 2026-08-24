"""破晓测试配置"""

import os
import tempfile

import pytest
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session", autouse=True)
def _isolate_audit_dir():
    """把审计目录隔离到临时目录，避免测试污染仓库 `scan_results/audit`。

    会话级设置环境变量；函数级测试可用 monkeypatch 覆盖，结束后回退本值。
    """
    tmp = tempfile.mkdtemp(prefix="poxiao_audit_")
    old = os.environ.get("POXIAO_AUDIT_DIR")
    os.environ["POXIAO_AUDIT_DIR"] = tmp
    yield
    if old is None:
        os.environ.pop("POXIAO_AUDIT_DIR", None)
    else:
        os.environ["POXIAO_AUDIT_DIR"] = old
