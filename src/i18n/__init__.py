"""国际化 (i18n) 框架 — D13

轻量文案层：默认语言 zh_CN，键即中文原文，未翻译时回退到原文，
保证对既有中文输出零破坏。

语言解析优先级：
  1. ``set_locale()`` 显式设置（CLI ``--lang``）
  2. 环境变量 ``POXIAO_LANG``（zh/en/zh_CN/en_US/中文/英语 均可）
  3. 默认 ``zh_CN``

用法::

    from src.i18n import _
    Out.info(_("正在收集 DNS 记录..."))

    from src.i18n import set_locale
    set_locale("en")          # 切换到英文
    set_locale("zh")          # 切回中文

新增译文只需在 ``src/i18n/messages.py`` 的 ``EN`` 目录追加
``"中文原文": "English text"``，不影响中文默认输出，也不要求全量翻译。
"""

import os

from src.i18n.messages import EN

DEFAULT_LOCALE = "zh_CN"

# locale 简写 / 别名 → 规范值
_LOCALE_ALIASES = {
    "zh": "zh_CN", "zh_cn": "zh_CN", "chinese": "zh_CN", "中文": "zh_CN",
    "en": "en", "en_us": "en", "english": "en", "英语": "en",
}


def _normalize(locale: str) -> str:
    """将任意 locale 写法规范为 zh_CN / en / 原值"""
    return _LOCALE_ALIASES.get(locale.strip().lower(), locale.strip().lower())


def _resolve_default() -> str:
    """从环境变量解析默认 locale"""
    env = (os.environ.get("POXIAO_LANG") or "").strip().lower()
    return _normalize(env) if env else DEFAULT_LOCALE


_current_locale = _resolve_default()


def get_locale() -> str:
    """返回当前 locale 规范值（zh_CN / en / ...）"""
    return _current_locale


def is_english() -> bool:
    """当前是否为英文模式"""
    return _current_locale == "en"


def set_locale(locale: str) -> str:
    """设置当前 locale，返回生效的规范值"""
    global _current_locale
    if locale:
        _current_locale = _normalize(locale)
    else:
        _current_locale = DEFAULT_LOCALE
    return _current_locale


def _(text: str) -> str:
    """翻译：当前为 en 且存在译文时返回英文，否则回退到原文（中文）"""
    if _current_locale == "en" and text in EN:
        return EN[text]
    return text


__all__ = ["_", "set_locale", "get_locale", "is_english", "DEFAULT_LOCALE"]
