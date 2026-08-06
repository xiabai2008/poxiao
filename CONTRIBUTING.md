# 贡献指南

欢迎为 PoXiao（破晓）贡献！请先阅读本指南，并遵守 [行为准则](CODE_OF_CONDUCT.md)。

## 项目哲学

PoXiao 的差异化在于**高置信度而非模板数量**：先识别技术栈，再匹配 CVE，以三层降噪消除假阳性。
贡献时应遵循这一哲学，避免"payload 盲打"和"把路径发现算作漏洞"的做法。

## 开发环境

- Python 3.10+（CI 覆盖 3.10 / 3.11 / 3.12）
- 安装依赖：`pip install -e ".[dev]"`

## 本地验证（提交前必须通过）

```bash
# 1. 数据治理硬门禁：CVE 唯一性 / 模板字段校验
python tools/ci_audit.py

# 2. 全量测试 + 覆盖率（fail_under=60）
python -m pytest

# 3. 渐进式类型门禁（核心模块 mypy）
python tools/type_check.py
```

## 贡献类型

### 漏洞/CVE 规则（`src/dawn/cve_match.py`）

- 新增条目须保证 CVE ID 全局唯一（撞号会被 CI 驳回）。
- 必须附真实来源（官方公告 / 权威 CVE 库），禁止虚构条目。
- 版本区间匹配需准确，避免误报。

### POC 模板（`templates/**`）

- 须包含 Nuclei 必填字段：`id` / `info` / `info.name` / `info.severity` / `http` 或 `requests`。
- `id` 必须全局唯一。
- 提交前运行：`python tools/template_sync.py validate <文件或目录>`。
- **不要**在 PR 中硬编码模板数量作为通过条件（计数仅作指标）。

### 代码功能 / 修复

- 保持**零外部运行时依赖**（守 MVP 边界，仅 stdlib + 现有依赖）。新增依赖须在 PR 说明理由。
- 网络 I/O 优先 `asyncio`。
- 涉及核心模块时通过 `tools/type_check.py`。

## Pull Request 流程

1. Fork 仓库并创建特性分支。
2. 提交前完成上述本地验证。
3. 提出 PR，填写 [PR 模板](.github/PULL_REQUEST_TEMPLATE.md)。
4. CI（`ci.yml` + `pr_check.yml`）全绿后等待评审合并。

## 报告问题

发现 Bug 或安全漏洞，请先阅读 [SECURITY.md](SECURITY.md)；一般问题请使用 [Bug 报告模板](.github/ISSUE_TEMPLATE/bug_report.md)。