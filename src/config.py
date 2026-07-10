"""
破晓统一配置系统
================
配置优先级: CLI 参数 > 环境变量 > 配置文件 > 默认值
配置文件路径: ~/.poxiao/config.yaml (Linux/Mac) 或 %USERPROFILE%\\.poxiao\\config.yaml (Windows)
"""

import os
import yaml
from pathlib import Path
from typing import Any, Optional

# Default config values
DEFAULT_CONFIG = {
    "scan": {
        "concurrency": 5,
        "timeout": 5.0,
        "retry": 2,
        "verify_ssl": False,
    },
    "poc": {
        "concurrency": 10,
        "timeout": 10.0,
        "max_redirects": 5,
    },
    "stealth": {
        "proxy_file": "",
        "global_qps": 10.0,
        "per_domain_qps": 3.0,
        "max_retries": 3,
    },
    "cve": {
        "nvd_api_key": "",
        "osv_enabled": True,
        "cache_ttl_hours": 24,
    },
    "monitor": {
        "port": 5099,
        "host": "127.0.0.1",  # Changed from 0.0.0.0 for security
        "auth": False,
        "username": "admin",
        "password": "",
    },
    "recon": {
        "shodan_api_key": "",
        "fofa_key": "",
        "fofa_email": "",
        "timeout": 10.0,
    },
    "report": {
        "output_dir": "scan_results",
        "platform": "butian",
    },
}


class Config:
    """Unified configuration manager"""

    _instance: Optional["Config"] = None
    _config: dict = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._config is None:
            self._config = dict(DEFAULT_CONFIG)
            self._config_file = self._find_config_file()
            if self._config_file and self._config_file.exists():
                self._load_from_file(self._config_file)
            self._load_from_env()

    def _find_config_file(self) -> Path:
        # Windows: %USERPROFILE%\.poxiao\config.yaml
        # Linux/Mac: ~/.poxiao/config.yaml
        home = Path.home()
        return home / ".poxiao" / "config.yaml"

    def _load_from_file(self, path: Path):
        """Load config from YAML file, merging with defaults"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
            self._deep_merge(self._config, user_config)
        except yaml.YAMLError as e:
            import sys
            print(f"[!] 配置文件解析错误 {path}: {e}", file=sys.stderr)
            print("[!] 使用默认配置继续", file=sys.stderr)
        except Exception:
            pass  # Silently fall back to defaults if config file is malformed

    def _load_from_env(self):
        """Load config from environment variables (POXIAO_* prefix)"""
        env_map = {
            "POXIAO_SCAN_CONCURRENCY": ("scan", "concurrency", int),
            "POXIAO_SCAN_TIMEOUT": ("scan", "timeout", float),
            "POXIAO_POC_CONCURRENCY": ("poc", "concurrency", int),
            "POXIAO_POC_TIMEOUT": ("poc", "timeout", float),
            "POXIAO_PROXY_FILE": ("stealth", "proxy_file", str),
            "POXIAO_GLOBAL_QPS": ("stealth", "global_qps", float),
            "POXIAO_DOMAIN_QPS": ("stealth", "per_domain_qps", float),
            "SHODAN_API_KEY": ("recon", "shodan_api_key", str),
            "FOFA_KEY": ("recon", "fofa_key", str),
            "FOFA_EMAIL": ("recon", "fofa_email", str),
            "POXIAO_NVD_API_KEY": ("cve", "nvd_api_key", str),
            "POXIAO_MONITOR_PORT": ("monitor", "port", int),
            "POXIAO_MONITOR_HOST": ("monitor", "host", str),
            "POXIAO_REPORT_DIR": ("report", "output_dir", str),
        }
        for env_key, (section, key, cast) in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                try:
                    self._config[section][key] = cast(val)
                except (ValueError, KeyError):
                    pass

    def _deep_merge(self, base: dict, override: dict):
        """Deep merge override into base"""
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """Get config value. Usage: config.get("scan") or config.get("scan", "timeout")"""
        sec: dict = self._config.get(section, {})
        if key is None:
            return sec
        return sec.get(key, default)

    def __getitem__(self, section: str) -> dict:
        return self._config.get(section, {})

    @staticmethod
    def create_default_config():
        """Create default config file at ~/.poxiao/config.yaml"""
        config_path = Path.home() / ".poxiao" / "config.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        if not config_path.exists():
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(
                    DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True
                )
        return config_path


# Convenience function
def get_config() -> Config:
    return Config()
