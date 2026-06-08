"""
破晓 · POC 模板引擎
====================
类 Nuclei 的 YAML 模板漏洞检测系统

模块:
  - template   模板数据模型
  - engine     执行引擎
  - matcher    匹配器 (status/body/regex/header/word/DSL)
  - extractor  提取器 (regex/kval/json)
  - loader     模板加载器
  - variables  内置变量

CLI:
  poxiao poc scan example.com -t templates/
  poxiao poc scan example.com -t templates/cves/ -c 20
  poxiao poc list -t templates/
"""

from .engine import POCEngine
from .loader import TemplateLoader

__all__ = ["POCEngine", "TemplateLoader"]
