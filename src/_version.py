"""破晓 版本单一事实源 (Phase 4)

所有版本引用（pyproject.toml / SARIF TOOL_VERSION / README 徽章）应对齐本文件。
pyproject.toml 保持静态 version 以保障构建；测试断言三者一致防止漂移。
"""

__version__ = "3.1.0"

VERSION = __version__
