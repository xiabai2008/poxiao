"""
破晓 · 帮助示例
================
每个命令的使用示例和详细说明
"""

# ── 命令帮助示例 ──────────────────────────────────────

EXAMPLES = {
    "main": """
示例:
  poxiao                              # 显示主 banner
  poxiao --help                       # 查看所有命令
  poxiao poc --help                   # 查看 POC 子命令帮助
""",

    "scan": """
示例:
  poxiao scan https://example.com              # 扫描单个目标
  poxiao scan https://example.com -c 10        # 10 并发
  poxiao scan targets.txt                      # 批量扫描
  poxiao scan https://example.com --depth full # 深度扫描 (含 SQLi/XSS)
  poxiao scan https://example.com -o results/  # 自定义输出目录
""",

    "discover": """
示例:
  poxiao discover "北京百度网讯科技有限公司"      # 单个公司
  poxiao discover -f companies.txt              # 批量公司
  poxiao discover "腾讯" --search               # 启用搜索引擎辅助
""",

    "subdomain": """
示例:
  poxiao subdomain example.com                 # 全量收集
  poxiao subdomain example.com --no-crtsh      # 跳过 crt.sh
  poxiao subdomain example.com --no-brute      # 跳过 DNS 爆破
  poxiao subdomain example.com -o subs.txt     # 保存结果
""",

    "recon": """
示例:
  poxiao recon example.com                     # 全量被动收集
  poxiao recon example.com --quick             # 快速模式 (跳过 IP 深度)
  poxiao recon example.com --shodan-key KEY    # 带 Shodan
  poxiao recon example.com -o recon.json       # 保存报告
""",

    "poc": """
示例:
  poxiao poc scan example.com                      # 全模板扫描
  poxiao poc scan example.com --severity critical  # 仅 critical
  poxiao poc scan example.com --tags rce,sqli      # 按标签
  poxiao poc scan example.com --history            # 历史对比
  poxiao poc scan example.com --loop --interval 3600  # 持续扫描
  poxiao poc scan example.com --stealth            # 隐匿模式
  poxiao poc scan example.com --proxies proxies.txt  # 使用代理
  poxiao poc list                                   # 列出所有模板
  poxiao poc list --severity critical,high          # 列出高危模板
  poxiao poc history example.com                    # 查看历史
  poxiao poc history example.com --findings         # 查看漏洞详情
""",

    "stealth": """
示例:
  poxiao stealth gen-ua                            # 生成 5 个随机 UA
  poxiao stealth gen-ua -n 10 --category mobile    # 10 个移动端 UA
  poxiao stealth check-waf https://target.com      # 检测 WAF
  poxiao stealth proxy-test proxies.txt             # 测试代理
  poxiao stealth proxy-test proxies.txt -c 50       # 50 并发测试
""",

    "util": """
示例:
  # 编码
  poxiao util encode base64 "hello"            # aGVsbG8=
  poxiao util encode hex "hello"               # 68656c6c6f
  poxiao util encode url "<script>alert(1)</script>"

  # 解码
  poxiao util decode base64 "aGVsbG8="         # hello
  poxiao util decode hex "68656c6c6f"          # hello
  poxiao util decode jwt "eyJhbGciOi..."       # JWT payload

  # 哈希
  poxiao util hash md5 "admin123"
  poxiao util hash sha256 "password"

  # 自动识别
  poxiao util auto "aGVsbG8="                  # → base64: hello
  poxiao util auto "68656c6c6f"                # → hex: hello
  poxiao util auto "%3Cscript%3E"              # → url: <script>
""",

    "verify": """
示例:
  poxiao verify https://example.com            # 验证单个目标
  poxiao verify scan_results/summary_xxx.json  # 从扫描结果批量验证
""",

    "monitor": """
示例:
  poxiao monitor stats                         # 查看统计
  poxiao monitor serve                         # 启动 Web 面板 (端口 5099)
  poxiao monitor import scan_results/summary_xxx.json  # 导入扫描结果
""",

    "report": """
示例:
  poxiao report                                # 使用最新扫描结果
  poxiao report scan_results/summary_xxx.json  # 指定扫描结果
  poxiao report -o reports/                    # 自定义输出目录
""",

    "config": """
示例:
  poxiao config init                           # 创建默认配置文件 (~/.poxiao/config.yaml)
  poxiao config show                           # 显示当前生效的配置
  poxiao config path                           # 显示配置文件路径
""",
    "mcp": """
示例 (stdio 接入 AI 助手):
  poxiao mcp                                   # 启动 stdio MCP 服务端
  poxiao mcp --transport stdio                 # 同上（默认）

示例 (SSE / HTTP 网络接入):
  poxiao mcp --transport sse                   # 监听 127.0.0.1:8765
  poxiao mcp --transport sse --host 0.0.0.0 --port 9000

stdio 客户端配置 (Claude Desktop / CodeBuddy 等):
  {
    "mcpServers": {
      "poxiao": { "command": "poxiao", "args": ["mcp"] }
    }
  }
SSE 客户端配置 (Cursor / 支持 SSE 的客户端):
  {
    "mcpServers": {
      "poxiao": { "url": "http://127.0.0.1:8765/sse" }
    }
  }
可用工具: scan_targets / check_alive / subdomain_enum /
         passive_recon / verify_target / poc_scan / util_codec
""",
}


def get_examples(command: str) -> str:
    """获取命令示例"""
    return EXAMPLES.get(command, "")


def print_examples(command: str):
    """打印命令示例"""
    examples = get_examples(command)
    if examples:
        print(examples)
