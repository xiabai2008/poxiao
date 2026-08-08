"""目标管理 — 加载、去重、存活检测、分类"""

from .manager import TargetManager, Target
from .discovery import DomainDiscovery, DomainCandidate

__all__ = [
    "TargetManager",
    "Target",
    "DomainDiscovery",
    "DomainCandidate"
]

