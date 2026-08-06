# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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