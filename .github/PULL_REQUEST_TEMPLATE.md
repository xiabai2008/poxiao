# Pull Request 模板

## 变更类型
- [ ] 漏洞/指纹规则（CVE、模板）
- [ ] 代码功能/修复
- [ ] 工程化（CI、文档、工具）
- [ ] 其他

## 模板贡献（如涉及 `templates/**` 改动，必读）
- [ ] 已运行 `python tools/template_sync.py validate <文件或目录>` 并修复字段告警
- [ ] 模板 `id` 全局唯一（撞号将被 CI 驳回）
- [ ] 包含 Nuclei 必填字段：`id` / `info` / `info.name` / `info.severity` / `http` 或 `requests`
- [ ] **未**在 PR 中硬编码模板数量（如 215/224）作为通过条件——计数仅作指标，以代码为准（守 X1）
- [ ] 模板经由代码/数据提供，未引入需要服务端或邮件的能力

## 代码改动
- [ ] 通过 `python tools/ci_audit.py`（CVE 唯一性 / 模板治理）
- [ ] 通过 `python -m pytest`（或 `pytest`）
- [ ] 涉及核心模块时通过 `python tools/type_check.py`（渐进 mypy 门禁）
- [ ] 未扩大外部运行时依赖（守 MVP 边界）；新增依赖须说明理由

## 说明
（简述动机、影响面、测试方式）
