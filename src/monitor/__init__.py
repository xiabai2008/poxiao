"""观星 — 资产监控平台"""

from .db import init_db, import_from_summary, get_stats
from .web import start_server
