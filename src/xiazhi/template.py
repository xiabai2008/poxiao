r"""
POC 模板数据模型
================
定义 YAML 模板的完整数据结构

模板格式 (兼容 Nuclei 风格):
```yaml
id: CVE-2021-44228
info:
  name: Apache Log4j2 RCE
  severity: critical
  description: Log4j2 JNDI RCE 漏洞
  tags: log4j,rce,java
  author: poxiao

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/test"
    headers:
      User-Agent: "Mozilla/5.0"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["vulnerable"]
        part: body
    extractors:
      - type: regex
        regex: ['version["\s:=]+([0-9.]+)']
        group: 1
```
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Matcher:
    """匹配器 — 判断响应是否符合漏洞特征"""
    type: str = "word"                  # word / status / regex / size / dsl / binary / header
    # word 匹配
    words: List[str] = field(default_factory=list)
    case_sensitive: bool = False
    # status 匹配
    status: List[int] = field(default_factory=list)
    # regex 匹配
    regex: List[str] = field(default_factory=list)
    # size 匹配
    size: List[int] = field(default_factory=list)       # 响应体大小范围 [min, max]
    # header 匹配
    header: str = ""                    # 匹配的 header 名
    header_value: str = ""              # header 值包含
    # DSL 表达式
    dsl: List[str] = field(default_factory=list)
    # binary 匹配 (十六进制)
    binary: List[str] = field(default_factory=list)
    # 匹配位置
    part: str = "body"                  # body / header / all
    # 取反
    negative: bool = False              # 匹配取反 (not)
    # 条件
    condition: str = "or"               # or / and (多个 words/regex 之间的关系)

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()
                if v and v != [] and v is not False and v != "word" and v != "body" and v != "or"}


@dataclass
class Extractor:
    """提取器 — 从响应中提取数据"""
    type: str = "regex"                 # regex / kval / json / xpath
    # regex 提取
    regex: List[str] = field(default_factory=list)
    group: int = 0                      # 正则捕获组
    # kval 提取 (key-value from headers/cookies)
    kval: List[str] = field(default_factory=list)    # header/cookie 名
    # json 提取
    json: List[str] = field(default_factory=list)    # JSONPath 表达式
    # 匹配位置
    part: str = "body"                  # body / header / all
    # 输出名称
    name: str = ""

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if v and v != [] and v != "regex" and v != "body"}


@dataclass
class HTTPRequest:
    """单个 HTTP 请求模板"""
    method: str = "GET"
    path: List[str] = field(default_factory=list)           # 请求路径 (支持变量)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""                       # 请求体
    content_type: str = ""               # Content-Type
    raw: str = ""                        # P2-1: nuclei raw HTTP 报文原文（解析后仍保留）
    # 匹配逻辑
    matchers_condition: str = "and"      # and / or (多个 matcher 之间)
    matchers: List[Matcher] = field(default_factory=list)
    extractors: List[Extractor] = field(default_factory=list)
    # 请求配置
    timeout: float = 10.0
    follow_redirects: bool = True
    max_redirects: int = 3
    cookie_reuse: bool = True
    # 并发控制
    stop_at_first_match: bool = False    # 首次匹配即停止
    # 自定义
    matchers_logic: str = ""             # 高级 DSL 逻辑

    def to_dict(self):
        return {
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
            "raw": self.raw[:200] if self.raw else "",
            "matchers_condition": self.matchers_condition,
            "matchers": [m.to_dict() for m in self.matchers],
            "extractors": [e.to_dict() for e in self.extractors],
        }


@dataclass
class TemplateInfo:
    """模板元信息"""
    name: str = ""
    author: str = "poxiao"
    severity: str = "info"              # critical / high / medium / low / info
    description: str = ""
    reference: List[str] = field(default_factory=list)   # 参考链接
    tags: List[str] = field(default_factory=list)         # 标签
    classification: Dict[str, str] = field(default_factory=dict)  # CVE/CWE/CVSS 等

    @property
    def severity_icon(self) -> str:
        icons = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]", "low": "[-]", "info": "[.]"}
        return icons.get(self.severity, "[.]")

    @property
    def severity_score(self) -> int:
        scores = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return scores.get(self.severity, 0)


@dataclass
class Template:
    """完整的 POC 模板"""
    id: str = ""
    info: TemplateInfo = field(default_factory=TemplateInfo)
    requests: List[HTTPRequest] = field(default_factory=list)
    # 全局变量
    variables: Dict[str, str] = field(default_factory=dict)
    # 元数据
    raw_yaml: dict = field(default_factory=dict)
    file_path: str = ""

    @property
    def severity(self) -> str:
        return self.info.severity

    @property
    def tags_str(self) -> str:
        return ",".join(self.info.tags)

    def to_dict(self):
        return {
            "id": self.id,
            "info": {
                "name": self.info.name,
                "severity": self.info.severity,
                "description": self.info.description,
                "tags": self.info.tags,
                "author": self.info.author,
            },
            "requests": [r.to_dict() for r in self.requests],
        }


@dataclass
class MatchResult:
    """单次匹配结果"""
    template_id: str
    template_name: str
    severity: str = "info"
    url: str = ""
    matched: bool = False
    matcher_name: str = ""              # 哪个 matcher 触发
    extracted: Dict[str, str] = field(default_factory=dict)  # 提取的数据
    response_status: int = 0
    response_size: int = 0
    response_time: float = 0.0          # 响应时间 (秒)
    request_url: str = ""               # 实际请求的完整 URL
    request_method: str = ""
    tags: List[str] = field(default_factory=list)
    description: str = ""
    error: str = ""

    @property
    def severity_icon(self) -> str:
        icons = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]", "low": "[-]", "info": "[.]"}
        return icons.get(self.severity, "[.]")

    def to_dict(self):
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity,
            "url": self.url,
            "matched": self.matched,
            "matcher_name": self.matcher_name,
            "extracted": self.extracted,
            "response_status": self.response_status,
            "response_size": self.response_size,
            "request_url": self.request_url,
            "tags": self.tags,
            "description": self.description,
        }
