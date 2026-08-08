# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [3.1.0] - 2026-08-08

### 新增
- **模板生态 3.3 倍扩容**：正式库 224 → **741 个**（精选 517 个社区高价值模板：国内 OA 组件 seeyon/泛微/致远/用友/CNVD 系列、CVE 热榜、高危类型；`tools/template_select.py` 评分筛选 + 防撞号）。
- **raw HTTP 报文支持**：nuclei raw 模板格式（含多请求、顶层 matchers 共享），社区库 11k 模板兼容率 **99.9%**。
- **DSL 函数子集（~26 个）**：白名单求值器（无 eval），嵌套调用 + `&&`/`||` 组合，对齐 nuclei DSL。
- **OAST 带外回调**：`poxiao oast serve/query/flush`，`{{oast-url}}`/`{{oast-domain}}` 变量，`poc scan --oast --oast-check` 自动验证盲注/XXE/SSRF（部署见 docs/OAST_DEPLOY.md）。
- **被动代理**：`poxiao proxy serve/query`，xray 式浏览器代理工作流 + 敏感参数标记。
- **SARIF 2.1.0 输出**：`report --format sarif` / `scan --sarif`，对接 GitHub Code Scanning/GitLab SAST。
- **模板 ECDSA 签名**：`template_sync genkey/sign/verify` + 引擎 `--verify-signatures` 可选校验（741 模板已签名）。
- **AI 模板生成**：`tools/ai_template.py generate "漏洞描述"`（OpenAI 兼容 API）→ 校验 → 入库。
- **测绘引擎闭环**：Quake / Hunter 接入，FOFA/Quake/Hunter 三引擎资产合并。
- **Webhook 告警**：观星变化事件推飞书/钉钉（自动识别 URL 或 `monitor.webhook_type`）。
- **社区库开关**：`poc scan --include-community`（11k 模板实验性全量启用）。
- **单文件二进制**：`poxiao.spec` PyInstaller 打包，三平台 Release 自动构建（34.8MB Windows 实测）。

### 修复
- SRC 报告文件名 Windows 崩溃（`:` 等非法字符清洗）。
- `poc scan --history` 历史对比取错批次（新增/消失恒空）。
- 技术栈→CVE 兜底匹配静默 0 命中（标签归一化）。
- 二进制响应匹配失效（改原始字节）、MCP SSE 未授权调用面（token 鉴权）。
- extractors-only 请求恒判匹配（"always pass" 误报归零）。
- 13 条死 CVE 数据（含 CVE-2025-24813 Tomcat 匹配修复、CVE-2022-26945 组件归属）。
- loader 健壮性（`method: null` / `severity: null` 崩溃）。

### 工程化
- **ruff 全仓 lint 接入**（176 处修复，`[tool.ruff]` 配置）与 **bandit 安全扫描**（0 issue，skips 注释化）。
- HTTP 连接池复用（ScanEngine 共享客户端 + 浏览器 UA）。
- GitHub Release 流水线（tag → wheel + 三平台二进制 + 自动 Release Notes）。
- PyPI 发布就绪（包名未注册，wheel 构建验证通过）。
- 性能基线：142 目标/秒（P99 516ms）。

### 安全
- MCP SSE token 鉴权（`--token` / `POXIAO_MCP_TOKEN`，恒时比较）。
- 模板签名防供应链投毒；社区库默认隔离、实验性标注。
- bandit 全量扫描 0 issue；skips 均注释化设计理由。

## [3.0.0] - 2026-07-11

### 新增
- **六工具链**：破晓 Dawn（核心扫描）、霜月 FrostMoon（子域名）、春分 VernalEquinox（被动侦察）、惊蛰 JingZhe（漏洞验证）、观星 GuanXing（资产监控）、夏至 XiaZhi（隐匿扫描）。
- **MCP Server**：`poxiao mcp` 以 stdio 与 SSE(HTTP) 两种传输暴露扫描能力，供 AI 助手（Claude / CodeBuddy / Cursor）调用。
- **国际化（i18n）**：`--lang {zh,en}` 全局选项，SRC 报告/HTML 报告/输出层英文化闭环。
- **SBOM**：`tools/gen_sbom.py` 生成 CycloneDX 1.5 清单。

### 核心能力
- 内置 CVE 漏洞库 **257 条**（唯一 ID）+ NVD 在线查询。
- POC 模板库 **224 个**（Nuclei 风格，含 cves / exposures / misconfig / vulnerabilities / default-logins）。
- 补天品牌库 **107 个**。
- 三层降噪算法，误报率从 94% 降至约 5%。

### 工程化
- GitHub Actions CI：Python 3.10/3.11/3.12 审计 + 测试 + 覆盖率门槛（≥60%）+ mypy 渐进门禁 + wheel 构建。
- 数据治理硬门禁 `tools/ci_audit.py`（CVE 唯一性 / 模板校验）。
- wheel 打包：`pip install -e .` 或 `python -m build --wheel`。

### 安全
- 默认仅监听回环地址；WAF 绕过默认关闭（显式 `--waf-bypass`）。
- 启动安全红线自检（`src/utils/redline.py`）。

## [2.0.0] - 2026-06

### 新增
- 春分被动侦察扩展（Censys / Wayback / GitHub Leak）。
- 观星资产监控 Web 仪表盘。

## [1.0.0] - 2026-05

### 新增
- 破晓核心扫描器：技术栈指纹 + CVE 匹配 + 三层降噪 + SRC 报告。
- 霜月子域名收集、惊蛰漏洞验证、夏至 POC 引擎初版。