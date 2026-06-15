"""破晓 Dawn — 核心扫描器：技术栈指纹 + CVE 匹配 + 三层降噪"""

from .engine import ScanEngine, ScanResult
from .tech_stack import TechStackDetector, TechFingerprint
from .sensitive import SensitivePathDetector, PathFind
from .version_extract import VersionExtractor, VersionInfo
from .cve_match import CVEMatcher, VulnMatch
from .reporter import Reporter
from .src_reporter import SRCReporter
