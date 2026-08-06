# 破晓 (PoXiao) v3.0.0

**二十四节气安全工具链** — SRC 挖洞全流程自动化

[![CI](https://img.shields.io/github/actions/workflow/status/xiabai2008/poxiao/ci.yml?label=CI&logo=github)](https://github.com/xiabai2008/poxiao/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/github/license/xiabai2008/poxiao)](LICENSE)
[![Release](https://img.shields.io/github/v/release/xiabai2008/poxiao)](https://github.com/xiabai2008/poxiao/releases)

> 破晓是凌晨的第一道光，霜月是清冷的收集，春分是全面的侦察，惊蛰是万物的验证，观星是持续的监控，夏至是隐匿的扫描。

> ⚠️ **法律与道德声明**：PoXiao 是安全研究工具，**仅限对您拥有合法授权或已获书面许可的目标使用**。
> 未经授权的扫描可能违反当地法律，使用者须自行承担全部责任。开发者不对任何滥用行为负责。
> 相关漏洞报告指引见 [SECURITY.md](SECURITY.md)。

---

## 核心理念

**先识别技术栈，再匹配 CVE，三层降噪消除假阳性。**

不盲目 payload 轰炸，不追求模板数量，只追求高置信度结果。

---

## 工具链生态

```
                    ┌─────────────┐
                    │   破晓 Dawn  │
                    │  核心扫描器  │
                    │  指纹+CVE+  │
                    │   降噪+报告  │
                    └──────┬──────┘
                           │ 编排
          ┌────────┬───────┼───────┬────────┐
          ▼        ▼       ▼       ▼        ▼
       ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐
       │ 霜月  │ │ 春分  │ │ 惊蛰  │ │ 观星  │ │ 夏至  │
       │ 子域名│ │ 侦察  │ │ 验证  │ │ 监控  │ │ 隐匿  │
       └──────┘ └──────┘ └──────┘ └──────┘ └──────┘
```

| 工具 | 命令 | 定位 |
|------|------|------|
| **破晓 Dawn** | `poxiao scan` | 核心扫描器：技术栈指纹 + CVE 精确匹配 + 三层降噪 + SRC 报告 |
| **霜月 FrostMoon** | `frostmoon` | 子域名收集：crt.sh + certspotter + OTX + DNS 爆破 + 泛解析检测 |
| **春分 VernalEquinox** | `vernalequinox` | 被动侦察：WHOIS + ICP + DNS + 证书 + IP 情报 + Wayback + GitHub 泄露 |
| **惊蛰 JingZhe** | `jingzhe` | 漏洞验证：默认凭据 + Git 泄露 + Swagger + Actuator + 配置文件检测 |
| **观星 GuanXing** | `guanxing` | 资产监控：Web 仪表盘 + 变化追踪 + 认证 + 分页 |
| **夏至 XiaZhi** | `xiazhi` | 隐匿扫描：POC 模板引擎 + 代理池 + UA 轮换 + WAF 绕过 |

---

## 快速开始

```bash
# 安装（源码）
git clone https://github.com/xiabai2008/poxiao.git
cd poxiao
pip install -e ".[dev]"

# 核心扫描
poxiao scan targets.txt                    # 扫描目标列表
poxiao scan example.com --report butian    # 生成补天报告

# 独立工具
frostmoon example.com --brute              # 子域名收集
vernalequinox example.com                  # 被动侦察
jingzhe https://example.com                # 漏洞验证
guanxing serve                             # 启动监控仪表盘
xiazhi scan example.com -t templates/      # POC 扫描
xiazhi scan example.com -t templates/ --stealth  # 隐匿扫描

# 配置管理
poxiao config init                         # 创建配置文件
poxiao config show                         # 查看当前配置

# MCP 服务端（AI 助手接入）
poxiao mcp                                 # 启动 stdio MCP 服务端，供 Claude/CodeBuddy 等调用
```

---

## MCP 服务端（AI 辅助）

破晓支持 **MCP (Model Context Protocol)**，以 **stdio** 与 **SSE(HTTP)** 两种传输暴露核心能力，让 AI 助手直接调用扫描能力并消费结构化 JSON 结果（纯 stdlib，无额外依赖）。

```bash
poxiao mcp                                 # stdio 传输（本地 AI 助手接入，默认）
poxiao mcp --transport sse                 # SSE/HTTP 传输，监听 127.0.0.1:8765
poxiao mcp --transport sse --host 0.0.0.0 --port 9000
```

stdio 客户端配置（Claude Desktop / CodeBuddy 等）：

```json
{
  "mcpServers": {
    "poxiao": { "command": "poxiao", "args": ["mcp"] }
  }
}
```

SSE 客户端配置（Cursor / 支持 SSE 的客户端）：

```json
{
  "mcpServers": {
    "poxiao": { "url": "http://127.0.0.1:8765/sse" }
  }
}
```

> SSE 默认仅监听回环地址 `127.0.0.1`（私有化定位，避免误暴露）；如需局域网接入再显式指定 `--host`。

暴露的 7 个工具：

| 工具 | 说明 |
|------|------|
| `scan_targets` | 核心扫描：存活+技术栈+CVE+敏感路径（三层降噪） |
| `check_alive` | 快速存活检测 |
| `subdomain_enum` | 霜月子域名收集（证书透明+DNS 爆破+泛解析） |
| `passive_recon` | 春分被动情报（Whois/备案/DNS/证书/IP/历史/GitHub） |
| `verify_target` | 惊蛰漏洞自动验证（默认口令/Swagger/Git/Actuator…） |
| `poc_scan` | 夏至 POC 模板扫描 |
| `util_codec` | 编解码/加解密（base64/hex/jwt/auto…） |

---

## 三层降噪（核心差异化）

```
层1: 内容特征 — 配置文件返回了 HTML → 假阳性
层2: 尺寸聚类 — 3+ 路径同尺寸（±8%容差）→ CDN catch-all
层3: 校准匹配 — 随机探测路径匹配 → 统一错误页

效果: 误报率从 94% → ~5%
```

---

## 项目结构

```
破晓/
├── src/
│   ├── dawn/              # 核心扫描器 (7 模块)
│   │   ├── engine.py      # HTTP 扫描 + 技术栈识别
│   │   ├── tech_stack.py  # 指纹库 (Server/Language/CMS/CDN/WAF)
│   │   ├── cve_match.py   # CVE 匹配 (257 条内置 + NVD 在线)
│   │   ├── sensitive.py   # 敏感路径 + 三层降噪
│   │   └── reporter.py    # SRC 报告生成
│   ├── frostmoon/         # 霜月 — 子域名收集
│   ├── vernalequinox/     # 春分 — 被动侦察 (10 模块)
│   ├── jingzhe/           # 惊蛰 — 漏洞验证
│   ├── guanxing/          # 观星 — 资产监控
│   ├── xiazhi/            # 夏至 — 隐匿扫描 + POC 引擎 (10 模块)
│   ├── config.py          # 统一配置系统
│   ├── target/            # 目标管理
│   └── utils/             # 共享工具
│
├── templates/             # POC 模板库 (215 个)
├── configs/               # 配置文件
│   └── brands.json        # 补天品牌数据库 (107 品牌)
│
├── poxiao.py              # 破晓入口
├── frostmoon.py           # 霜月入口
├── vernalequinox.py       # 春分入口
├── jingzhe.py             # 惊蛰入口
├── guanxing.py            # 观星入口
├── xiazhi.py              # 夏至入口
└── pyproject.toml
```

---

## 配置系统

```bash
# 创建配置文件
poxiao config init

# 配置文件位置
# Windows: %USERPROFILE%\.poxiao\config.yaml
# Linux/Mac: ~/.poxiao/config.yaml
```

```yaml
# ~/.poxiao/config.yaml
scan:
  concurrency: 5
  timeout: 5.0
poc:
  concurrency: 10
  timeout: 10.0
stealth:
  proxy_file: "~/.poxiao/proxies.txt"
  global_qps: 10.0
cve:
  nvd_api_key: ""           # NVD API Key (可选)
recon:
  shodan_api_key: ""        # Shodan (可选)
monitor:
  host: "127.0.0.1"         # 默认只监听本地
  port: 5099
```

---

## 环境变量

| 变量 | 用途 |
|------|------|
| `POXIAO_SCAN_CONCURRENCY` | 扫描并发数 |
| `POXIAO_SCAN_TIMEOUT` | 扫描超时 |
| `POXIAO_NVD_API_KEY` | NVD API Key |
| `SHODAN_API_KEY` | Shodan API Key |
| `FOFA_KEY` / `FOFA_EMAIL` | FOFA API |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys API |
| `GITHUB_TOKEN` | GitHub 代码泄露扫描 |
| `POXIAO_MONITOR_USER` / `POXIAO_MONITOR_PASS` | 仪表盘认证 |

---

## 项目规模

```
内置 CVE 漏洞库:  257 条唯一 CVE ID（+ NVD 在线查询）
POC 模板:         224 个（Nuclei 风格）
补天品牌库:       107 个
扫描性能:         约 7.6 秒 / 30 目标（示例测试集）
降噪效果:         误报率从 94% → 约 5%
```

---

## 技术栈

| 组件 | 技术 |
|------|------|
| HTTP | httpx（异步） |
| DNS | dnspython |
| 证书透明 | crt.sh / certspotter / AlienVault OTX |
| IP 情报 | Shodan / Censys / FOFA |
| 历史 URL | Wayback Machine |
| 代码泄露 | GitHub Search API |
| 数据库 | SQLite |
| Web | Flask + Bootstrap 5 |
| 配置 | YAML + 环境变量 |
| 语言 | Python 3.10+ |

---

## 设计原则

- **异步优先** — 所有网络 I/O 用 asyncio
- **无外部依赖** — 不用 Docker、不用 Redis、SQLite 单文件
- **渐进输出** — 扫完一个出结果，不等全部
- **工具独立** — 每个工具可单独使用，也可编排协作
- **高置信度** — 三层降噪，误报率 < 5%

---

## 文档与贡献

- [用户手册](docs/USER_GUIDE.md) — 安装、配置、各工具详细用法
- [开发者指南](docs/DEVELOPER.md) — 仓库结构、CI、类型化、模板贡献
- [更新日志](CHANGELOG.md) — 版本历史与变更
- [贡献指南](CONTRIBUTING.md) — 如何参与贡献
- [安全策略](SECURITY.md) — 漏洞报告流程
- [行为准则](CODE_OF_CONDUCT.md) — 社区规范

---

*"破晓是凌晨的第一道光，"*
*"霜月是十一月的清冷，"*
*"春分是万物的开始，"*
*"惊蛰是万物的复苏，"*
*"观星是仰望天空，"*
*"夏至是最长的白昼。"*
