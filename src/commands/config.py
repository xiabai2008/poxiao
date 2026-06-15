"""破晓配置管理命令"""

import yaml
from pathlib import Path

from src.config import Config, DEFAULT_CONFIG
from src.utils.output import Out


def cmd_config(args):
    """配置管理"""
    action = getattr(args, "config_action", None)

    if action == "init":
        _config_init()
    elif action == "show":
        _config_show()
    elif action == "path":
        _config_path()
    else:
        Out.info("用法: poxiao config <init|show|path>")


def _config_init():
    """创建默认配置文件"""
    config_path = Path.home() / ".poxiao" / "config.yaml"

    if config_path.exists():
        Out.warning(f"配置文件已存在: {config_path}")
        Out.info("如需重置，请先手动删除该文件")
        return

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)

    Out.success(f"配置文件已创建: {config_path}")
    Out.dim("编辑该文件自定义配置，或使用环境变量覆盖")


def _config_show():
    """显示当前生效的配置"""
    cfg = Config()
    config_path = Path.home() / ".poxiao" / "config.yaml"

    Out.section("当前配置", "⚙")

    if config_path.exists():
        Out.info(f"配置文件: {config_path}")
    else:
        Out.info("配置文件: (未创建，使用内置默认值)")

    Out.blank()

    # Print each section
    for section in DEFAULT_CONFIG:
        sec_data = cfg.get(section)
        Out._print(f"  [{section}]")
        for key, val in sec_data.items():
            # Mask sensitive values
            if _is_sensitive(section, key) and val:
                display_val = val[:3] + "***"
            else:
                display_val = val
            Out._print(f"    {key}: {display_val}")


def _config_path():
    """显示配置文件路径"""
    config_path = Path.home() / ".poxiao" / "config.yaml"
    Out.info(f"配置文件路径: {config_path}")

    if config_path.exists():
        Out.success("文件存在")
    else:
        Out.warning("文件不存在，运行 poxiao config init 创建")


def _is_sensitive(section: str, key: str) -> bool:
    """判断是否为敏感字段"""
    sensitive_keys = {
        ("cve", "nvd_api_key"),
        ("monitor", "password"),
        ("recon", "shodan_api_key"),
        ("recon", "fofa_key"),
        ("recon", "fofa_email"),
    }
    return (section, key) in sensitive_keys
