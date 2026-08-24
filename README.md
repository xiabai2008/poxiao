# 破晓 (PoXiao) v3.1.0

**二十四节气安全工具链** — SRC 挖洞全流程自动化工作台

[![CI](https://img.shields.io/github/actions/workflow/status/xiabai2008/poxiao/ci.yml?label=CI&logo=github)](https://github.com/xiabai2008/poxiao/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/github/license/xiabai2008/poxiao)](LICENSE)
[![Release](https://img.shields.io/github/v/release/xiabai2008/poxiao)](https://github.com/xiabai2008/poxiao/releases)
[![Code style: ruff](https://img.shields.io/badge/code_style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/tests-866%20passed-green)](https://github.com/xiabai2008/poxiao/actions)
[![Coverage](https://img.shields.io/badge/coverage-73%25-brightgreen)](https://github.com/xiabai2008/poxiao/actions)
[![Platform](https://img.shields.io/badge/windows%20%7C%20linux%20%7C%20macos-1f425f)](https://github.com/xiabai2008/poxiao/releases)

> 破晓是凌晨的第一道光，霜月是清冷的收集，春分是全面的侦察，惊蛰是万物的验证，观星是持续的监控，夏至是隐匿的扫描。

> ⚠️ **法律与道德声明**：PoXiao 是安全研究工具，**仅限对您拥有合法授权或已获书面许可的目标使用**。
> 未经授权的扫描可能违反当地法律，使用者须自行承担全部责任。开发者不对任何滥用行为负责。
> 相关漏洞报告指引见 [SECURITY.md](SECURITY.md)。

---

## 核心理念

**破晓不是又一个扫描器，而是一个 SRC 挖洞工作台** —— 它把从「资产侦察」到「报告提交」的完整漏洞挖掘链路收进一条命令。

| 阶段 | 工具 | 一句话 |
|---|---|---|
| 资产侦察 | 霜月/春分/破晓 | 域名发现、子域收集、技术栈+版本指纹 |
| 研判降噪 | 三层降噪 + CVE 精确匹配 | 先识别技术栈，再匹配 CVE，砍掉假阳性 |
| 主动验证 | 惊蛰 / POC 引擎 | 默认凭据、Git 泄露、Swagger/Actuator、模板库扫描 |
| 带外验证 | OAST | 盲注 / XXE / SSRF 回调确认 |
| 持续监控 | 观星 | 资产变更告警 + Web 面板 |
| 报告提交 | 补天 / SRC / SARIF | 一键生成厂商可读报告 |

**三层降噪 + CVE 精确匹配消除假阳性**——不盲目 payload 轰炸，不追求模板数量，只追求高置信度、可直接提交的结果。

## 授权红线（区别于其他工具的关键）

作为一款安全工具，破晓把「免责声明」升级为**可执行的授权控制**：

- `poxiao scope add example.com` 声明已授权范围
- 启用后，所有扫描命令会对越界目标**硬阻断**并写入审计日志
- 配套 §6.2 API Key 加密落盘、§7.2 五维度审计日志、§2.1 面板表单认证

> ⚠️ **法律与道德声明**：PoXiao 是安全研究工具，**仅限对您拥有合法授权或已获书面许可的目标使用**。
> 未授权扫描可能违反当地法律，使用者须自行承担全部责任。请先 `poxiao scope add` 声明范围。

## 快速开始

```bash
# 方式一：源码安装
git clone https://github.com/xiabai2008/poxiao.git
cd poxiao
pip install -e ".[dev]"

# 方式二：单文件二进制（免 Python 环境）
# 从 Release 下载 poxiao-win-x64.exe / poxiao-linux-x64 / poxiao-macos-x64

# 核心扫描
poxiao scope add example.com            # （推荐）先声明授权范围，启用的越界阻断
poxiao scan targets.txt                    # 扫描目标列表
poxiao scan example.com --report butian    # 生成补天报告
poxiao scan example.com --sarif            # 同时输出 SARIF（对接 GitHub Code Scanning）

# 被动侦察（FOFA / Quake / Hunter 三测绘引擎合并资产）
poxiao recon example.com --quake-token $QUAKE_TOKEN --hunter-key $KEY --hunter-email you@mail.com

# 漏洞验证
jingzhe https://example.com                # 默认凭据/Git 泄露/Swagger/Actuator 验证
poxiao poc scan example.com -t templates/  # POC 模板扫描
poxiao poc scan example.com --history      # 与上次扫描对比（新增/消失）

# 带外回调（盲注/XXE/SSRF 验证）
poxiao oast serve --port 8899              # 公网机/内网穿透后配 POXIAO_OAST_BASE
poxiao poc scan https://target -t templates/ --oast --oast-check

# 被动代理（xray 式：浏览器挂代理自动记录流量）
poxiao proxy serve --port 8080
poxiao proxy query --domain example.com

# 资产监控
guanxing serve                             # 观星 Web 仪表盘（变化告警可推飞书/钉钉）

# 模板签名（防供应链投毒）
python tools/template_sync.py genkey priv.pem pub.pem
python tools/template_sync.py sign templates --key priv.pem
python tools/template_sync.py verify templates --key pub.pem

# 社区模板同步（nuclei-templates，独立目录不污染默认库）
python tools/template_sync.py sync community --subdirs http,cves

# MCP 服务端（AI 助手接入）
poxiao mcp                                 # stdio（Claude/CodeBuddy）
poxiao mcp --transport sse --token xxx     # SSE（Cursor 等，token 鉴权）
```

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
| **春分 VernalEquinox** | `vernalequinox` | 被动侦察：WHOIS + ICP + DNS + 证书 + IP 情报 + Wayback + GitHub 泄露 + FOFA/Quake/Hunter |
| **惊蛰 JingZhe** | `jingzhe` | 漏洞验证：默认凭据 + Git 泄露 + Swagger + Actuator + 配置文件检测 |
| **观星 GuanXing** | `guanxing` | 资产监控：Web 仪表盘 + 变化追踪 + 认证 + 分页 + Webhook 告警 |
| **夏至 XiaZhi** | `xiazhi` | 隐匿扫描：POC 模板引擎 + 代理池 + UA 轮换 + WAF 绕过 |
| **OAST** | `poxiao oast` | 带外回调：盲注/XXE/SSRF 验证基础设施（本地自建，无外部服务） |
| **被动代理** | `poxiao proxy` | xray 式工作流：浏览器挂代理记录流量 + 敏感参数标记 |

---

## 新能力速览

### SARIF 2.1.0 输出（对接 GitHub Code Scanning / GitLab SAST）
```bash
poxiao report --format sarif            # 从最近扫描汇总生成
poxiao scan example.com --sarif         # 扫描完成自动生成
```
CVE 按严重级别映射 error/warning/note，规则自动去重，含 partialFingerprints。

### 模板 ECDSA 签名（防供应链投毒）
模板以原始字节签名（ECDSA P-256），任何改动即失效。签名清单 `.signatures.json` 随模板目录存放：
```bash
python tools/template_sync.py genkey priv.pem pub.pem
python tools/template_sync.py sign templates --key priv.pem      # 224 个模板一键签名
python tools/template_sync.py verify templates --key pub.pem     # 校验（bad 即失败）
poxiao poc scan example.com --verify-signatures --public-key pub.pem  # 引擎侧可选校验
```

### OAST 带外回调（盲注/XXE/SSRF 验证）
POC 模板可用 `{{oast-url}}`/`{{oast-domain}}` 变量生成随机子域；目标若触发回调（DNS/HTTP），`--oast-check` 自动确认命中：
```bash
POXIAO_OAST_BASE=http://your-oast.example.com poxiao oast serve   # 公网机
poxiao poc scan https://target --oast --oast-check                # 扫描机
```

### 测绘引擎闭环
FOFA + Quake + Hunter 三引擎被动资产合并（密钥按源隔离、限流、失败降级），查询结果自动并入侦察报告与资产库。

### Webhook 告警（飞书/钉钉）
观星监控到资产变化时自动推送（URL 自动识别或 `monitor.webhook_type` 强制指定）：
```yaml
monitor:
  webhook_url: "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
  webhook_type: "feishu"   # feishu | dingtalk | raw（留空按 URL 自动识别）
```

---

## MCP 服务端（AI 辅助）

破晓支持 **MCP (Model Context Protocol)**，以 **stdio** 与 **SSE(HTTP)** 两种传输暴露核心能力，让 AI 助手直接调用扫描能力并消费结构化 JSON 结果（纯 stdlib，无额外依赖）。

```bash
poxiao mcp                                 # stdio 传输（本地 AI 助手接入，默认）
poxiao mcp --transport sse                 # SSE/HTTP 传输，监听 127.0.0.1:8765
poxiao mcp --transport sse --host 0.0.0.0 --port 9000 --token <密钥>  # 远程接入（token 鉴权）
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
    "poxiao": { "url": "http://127.0.0.1:8765/sse", "headers": { "Authorization": "Bearer <token>" } }
  }
}
```

> SSE 默认仅监听回环地址 `127.0.0.1`；设置 `--token` 后 GET /sse 与 POST /messages 均须携带 Bearer 令牌或 `?token=` 参数（恒时比较）。令牌也可经环境变量 `POXIAO_MCP_TOKEN` 提供。

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
│   ├── dawn/              # 核心扫描器
│   │   ├── engine.py      # HTTP 扫描 + 技术栈识别（连接池复用）
│   │   ├── tech_stack.py  # 指纹库 (Server/Language/CMS/CDN/WAF)
│   │   ├── cve_match.py   # CVE 匹配 (257 条内置 + NVD 在线)
│   │   ├── sensitive.py   # 敏感路径 + 三层降噪
│   │   └── reporter.py    # SRC 报告生成
│   ├── frostmoon/         # 霜月 — 子域名收集
│   ├── vernalequinox/     # 春分 — 被动侦察（DNS/WHOIS/ICP/证书/IP/FOFA/Quake/Hunter）
│   ├── jingzhe/           # 惊蛰 — 漏洞验证
│   ├── guanxing/          # 观星 — 资产监控（SQLite + Web + Webhook）
│   ├── xiazhi/            # 夏至 — 隐匿扫描 + POC 引擎 + 模板签名
│   ├── oast/              # OAST 带外回调服务器
│   ├── proxy/             # 被动代理
│   ├── mcp/               # MCP 服务端（stdio + SSE）
│   ├── config.py          # 统一配置系统
│   ├── target/            # 目标管理
│   └── utils/             # 共享工具（sarif/html_report/i18n…）
│
├── templates/             # POC 模板库 (224 个)
├── configs/               # 配置文件
│   └── brands.json        # 补天品牌数据库 (107 品牌)
├── tools/                 # 运维工具链（ci_audit/template_sync/type_check/bench/gen_sbom）
│
├── poxiao.py              # 破晓入口
├── poxiao.spec            # PyInstaller 单文件打包配置
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
  webhook_url: ""           # 变化告警（飞书/钉钉/自建，留空关闭）
  webhook_type: ""          # feishu | dingtalk | raw（留空按 URL 自动识别）
```

---

## 环境变量

| 变量 | 用途 |
|------|------|
| `POXIAO_SCAN_CONCURRENCY` / `POXIAO_SCAN_TIMEOUT` | 扫描并发/超时 |
| `POXIAO_NVD_API_KEY` | NVD API Key |
| `SHODAN_API_KEY` | Shodan API Key |
| `FOFA_KEY` / `FOFA_EMAIL` | FOFA API |
| `QUAKE_TOKEN` | Quake API Token |
| `HUNTER_API_KEY` / `HUNTER_EMAIL` | Hunter API |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys API |
| `GITHUB_TOKEN` | GitHub 代码泄露扫描 |
| `POXIAO_OAST_BASE` | OAST 公网域名基址（`{{oast-url}}` 变量） |
| `POXIAO_MCP_TOKEN` | MCP SSE 访问令牌 |
| `POXIAO_MONITOR_USER` / `POXIAO_MONITOR_PASS` | 仪表盘认证 |

---

## 项目规模

```
内置 CVE 漏洞库:  257 条唯一 CVE ID（+ NVD 在线查询）
POC 模板:         741 个（Nuclei 风格，含 517 个精选社区模板，ECDSA 签名校验）
                  精选流程: template_select.py（国内组件/CVE 热榜/高危类型评分）
补天品牌库:       107 个
测试:             787 passed（覆盖率 72%，fail_under=60 硬门槛）
质量门禁:         ruff 全绿 · bandit 0 issue · mypy 10 模块零错误 · ci_audit PASS
分发:             wheel + 单文件二进制（Windows/Linux/macOS）
性能:             约 142 目标/秒（合成压测，P99 516ms）
降噪效果:         误报率从 94% → 约 5%
```

## 模板精选（P2-4）

从 nuclei-templates 社区库筛选高价值模板进正式库（国内组件/CVE 近三年/高危类型评分，high/critical 才入选）：

```bash
python tools/template_sync.py sync community --subdirs http,cves,exposures,misconfig,default-logins
python tools/template_select.py community --min-score 6 --apply   # 精选合入 templates/nuclei_selected/
python tools/template_sync.py validate templates/nuclei_selected   # 校验（硬门禁）
python tools/template_sync.py sign templates --key priv.pem        # 签名
```

---

## 技术栈

| 组件 | 技术 |
|------|------|
| HTTP | httpx（异步，连接池复用） |
| DNS | dnspython |
| 证书透明 | crt.sh / certspotter / AlienVault OTX |
| 测绘引擎 | FOFA / Quake / Hunter / Shodan / Censys |
| 历史 URL | Wayback Machine |
| 代码泄露 | GitHub Search API |
| 模板签名 | cryptography（ECDSA P-256） |
| 数据库 | SQLite |
| Web | Flask + Bootstrap 5 |
| 配置 | YAML + 环境变量 |
| 语言 | Python 3.10+ |

---

## 设计原则

- **异步优先** — 所有网络 I/O 用 asyncio，连接池复用
- **无外部依赖** — 不用 Docker、不用 Redis、SQLite 单文件；OAST 本地自建
- **渐进输出** — 扫完一个出结果，不等全部
- **工具独立** — 每个工具可单独使用，也可编排协作
- **高置信度** — 三层降噪，误报率 < 5%
- **安全默认值** — 令牌/端口可配、SSE 默认回环、模板签名可选

---

## 文档与贡献

- [用户手册](docs/USER_GUIDE.md) — 安装、配置、各工具详细用法
- [开发者指南](docs/DEVELOPER.md) — 仓库结构、CI 四件套、类型化渐进、模板贡献
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
