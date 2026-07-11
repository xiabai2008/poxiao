# CONTEXT.md — 破晓（PoXiao）v3.0.0 架构冻结决议（ADR 基线）

> 本文档是破晓 PoXiao v3.0.0 架构方案的**唯一事实源（Single Source of Truth）**，
> 由 AICoding 架构专家团于 2026-07-09 产出并冻结，研发团队须以此为准。
> 完整架构文档归档于 `.workbuddy/delivery/`（高层架构 / 系统设计 / UserStory / 部署设计 / 安全设计 / 资料摘要 / 行业调研 + G6 交付汇总）。

---

## 1. 项目定位（不可推翻）

- **破晓 PoXiao v3.0.0** —— 二十四节气 SRC 安全工具链（本地 CLI / 私有化 / 无 SaaS / 无外部依赖 / 无云组件）。
- 核心哲学：**先识别技术栈 → 再匹配 CVE → 三层降噪消除假阳性**，追求高置信度而非模板数量。
- 六件套：破晓 Dawn（核心）+ 霜月 / 春分 / 惊蛰 / 观星 / 夏至（5 独立工具）。

---

## 2. 冻结决议（X1–X3、Q5、MVP）

| 编号 | 决议 | 代码/文档落点 | 状态 |
|------|------|--------------|------|
| **X1** | POC 模板库 = **215** 个（Phase 1 基线；以 `templates/` 目录实测 yaml 数为准，**计数作指标非门禁**） | `templates/*.yaml`（Phase 1 实测 215 → Phase 2 P2-5 扩充 +9 = 实测 224） | ✅ 已核实 |
| **X1** | 内置 CVE 漏洞库 = **257** 条唯一 CVE ID（以 `src/dawn/cve_match.py` 的 `BUILTIN_VULNS` 去重计数为准） | `src/dawn/cve_match.py` | ✅ 已核实（见 §4 已知缺陷） |
| **X2** | WAF 绕过 = **可选模块，默认关闭**，不进入 MVP 主链路 | `xiazhi` 的 `waf_bypass.py` 经 `--stealth` 挂载 | ✅ 冻结 |
| **X3** | 存储 = GuanXing 监控 **SQLite 单文件（WAL）** + 报告 **JSON/Markdown 文件**；**禁用 Postgres / Redis / Docker** | 系统设计 §4.4；安全设计 §3 | ✅ 冻结 |
| **Q5** | 报告引擎 = **Python 标准库（json + 字符串模板），不引入 Jinja2**（无 Web 服务依赖） | 系统设计；安全设计 §4.1 | ✅ 冻结 |
| **MVP** | F1~F13 + N1~N2 全部 MVP✅ | — | ✅ |
| **Out-of-Scope** | O1 GuanXing Web 界面（auth 默认关）/ O2 WAF 绕过 / O3 SaaS / O4 HTML 报告 | 高层架构 §4.3/§6.1 | ✅ 冻结 |

---

## 3. 关键默认配置（与安全设计对齐）

| 项 | 默认值 | 说明 |
|----|--------|------|
| `monitor.auth` | **false** | GuanXing 仅绑 `127.0.0.1:5099` 回环，关闭 auth 不构成未授权访问；**生产/团队机须置 true → 改密 → Token → 可选 MFA** |
| `scan.verify_ssl` | **false** | 便于内网/自签场景；**安全设计建议生产置 true**（否则存在 MITM 篡改情报响应风险） |
| 出站白名单 | NVD/OSV/Shodan/Censys/FOFA/Wayback/crt.sh/certspotter/OTX/GitHub | 新增 E-xx 须登记 |
| 限速 | `global_qps=10` / `per_domain_qps=3` / `scan.concurrency=5` | 防 WAF 封禁 / 防反噬 |

---

## 4. 已知数据缺陷与已执行修正

### ⚠️ CVE-2022-21661 编号碰撞 — 已核实结论（2026-07-09 深挖）

`src/dawn/cve_match.py` 中 `CVE-2022-21661` 曾出现两处：

1. `component: wordpress` — "WordPress Core WP_Query SQL 注入"（affected < 5.8.3）—— **真正的 CVE-2022-21661**（5+ 独立来源佐证）。✅ 保留。
2. `component: php` — "PHP mbstring crafted input DoS"（affected < 8.0.16 / < 8.1.3）—— **虚构/错挂记录，已于 2026-07-09 删除**。

**核实依据（拉取 PHP 官方 changelog 确认）：**
- PHP 8.0.16 / 8.1.3 安全发布**唯一真实 CVE 是 `CVE-2021-21708`**（`filter` 扩展 `FILTER_VALIDATE_FLOAT` 的 Use-After-Free，由畸形数字字符串触发，可致服务崩溃，CVSS 7.5）。
- 该版本 mbstring 的修复是 bug **#GH-7902**「`mb_send_mail` 可能只用 LF 分隔邮件头」——**邮件头注入 bug，无 CVE 编号**，并非 DoS。
- 结论：**不存在** "PHP mbstring crafted input DoS" 这一 CVE；第 2 条记录三个字段全错（CVE 编号错挂 WordPress、组件描述错误、漏洞类型不存在），属虚构记录。

**正确 remediation（已执行）：删除该虚构记录。**
- 错误 remediation（原 carry-over 误判）：当作"重复条目去重" —— 实为虚构记录，删除方向碰巧一致，但原判定理由（以为是真漏洞重复）不准确。
- 删除后：`BUILTIN_VULNS` 由 257 条记录 / 256 唯一 → **256 条记录 / 256 唯一**（CVE-2022-21661 仅余 WordPress 1 处）。

**增强（已执行，2026-07-09）：** 为覆盖 PHP 8.0.16/8.1.3 真实安全修复，已**新增**独立条目 `CVE-2021-21708`（component=php，UAF via FILTER_VALIDATE_FLOAT，affected < 8.0.16 / < 8.1.3，CVSS 7.5；核实来源 php.net / php.watch）。
- 新增后：`BUILTIN_VULNS` 现为 **257 条记录 / 257 唯一**，README "256 条内置" 已同步更新为 **257 条内置**（见 §2 X1）。

---

## 5. 修订记录

| 日期 | 修订人 | 说明 |
|------|--------|------|
| 2026-07-09 | AICoding 架构专家团（主理人） | 初版冻结：X1–X3 / Q5 / MVP / Out-of-Scope / 默认配置 / 已知缺陷登记 |
| 2026-07-09 | 主理人（深挖核实） | §4 修正：CVE-2022-21661 第 2 条确认为虚构记录并已删除；PHP 8.0.16/8.1.3 真实 CVE=CVE-2021-21708（filter UAF），未注入 |
| 2026-07-09 | 主理人 | §4/§2 增强：补入真实条目 `CVE-2021-21708`（filter UAF）；BUILTIN_VULNS 现为 257 条记录 / 257 唯一，README 与 X1 同步为 257 |
| 2026-07-10 | 主理人 | §6 新增升级路线图索引；落实评审修订 F1~F3 / R1~R4（详见 `.workbuddy/delivery/后续开发升级方案.md`） |
| 2026-07-10 | 主理人 | Phase 2 全 5 任务（P2-1~P2-5）落地：FOFA 接入/观星告警导出/WAF 默认关/HTML 报告/惊蛰模板+平台格式；pytest 124 passed、ci_audit PASS、mypy 核心零错误；§6.2.1/§6.3 同步 |
| 2026-07-11 | 主理人 | Phase 3 全 4 任务（P3-1~P3-4）落地：SBOM(CycloneDX)/模板工具链(validate+diff)/渐进类型门禁扩至9模块/性能压测基准；新增 tools/gen_sbom|template_sync|type_check|bench 与 3 测试文件；pytest 135 passed、ci_audit PASS、type_check 9 模块零错误；§6.2.2/§6.4 同步 |
| 2026-07-11 | 主理人 | Phase 4 全 4 任务（P4-1~P4-4）落地：wheel 打包（补 build-system/修正 scripts 入口为唯一 `poxiao`/CI `build-wheel` job）/PR 模板+pr_check 校验 CI/用户+开发者文档/i18n deferred；`.gitignore` 补忽略（.coverage/dist/_*.txt）；本地 `python -m build --wheel` 成功 + `poxiao --help` 可运行；pytest 135 passed、ci_audit PASS、type_check 9 模块零错误；§6.5/§6.6 同步 |
| 2026-07-11 | 主理人 | Phase 5 覆盖率提升落地：补齐命令层/工具层/引擎纯逻辑单测（poc_engine/guanxing_db/tech_stack/cve_match/crypto/matcher/vernalequinox 多模块/user_agents/wayback/rate_limiter 等）；修复 2 个真实产品 bug（`Config` 空配置路径、`DomainDiscovery.close` 缺失、`cert_info` 弃用 `utcnow`）；整体覆盖率由基线约 33% → **60.05%**，`pyproject.toml` 设 `fail_under=60` 硬门槛；pytest **505 passed**、ci_audit PASS、type_check 9 模块零错误；§6.7/§6.8 同步 |
| 2026-07-11 | 主理人 | Phase 6 i18n 落地（D13，路线图最后一项未启动交付物闭环）：新增 `src/i18n`（`_`/`set_locale`/`get_locale` + `EN` 目录，键即中文回退零破坏）；`Out` 输出层 + CLI `--lang {zh,en}`（兼 `POXIAO_LANG`）接入；`src_reporter`/`html_report` 严重级别/类型/章节/表头 locale 化（英文报告验证）；`tests/test_i18n.py`（12 passed，i18n 92%）；pytest **517 passed**、整体覆盖率 **60.50%**、ci_audit PASS、type_check 9 模块零错误；§6.9/§6.10 同步 |
| 2026-07-11 | 主理人 | Phase 6 延伸（D13 收口）：SRC 报告自由文本全量英文化闭环——`_finding_title`/`_finding_description`/`_finding_steps`/`_default_suggestion`/`generate_from_cve` 经 `_()` + `{0}/{1}` 占位符 `.format` 接入（新增 ~110 条 EN 自由文本译文，键即中文原文回退，中文输出零破坏）；`tests/test_i18n.py` 增 3 用例校验 zh 保留/en 翻译/CVE；pytest **520 passed**、整体覆盖率 **60.60%**、ci_audit PASS；§6.9 已知限制项已消除 |

---

## 6. 升级路线图索引（权威入口）

后续开发路线以 `.workbuddy/delivery/后续开发升级方案.md` 为唯一权威入口，本文档不重复展开。

### 6.1 评审修订（2026-07-10，已落实于路线图文档）
- **事实更正 F1**：WAF 绕过 `waf_bypass.py` 已实现（非占位），Phase 2 为接线默认关。
- **事实更正 F2**：仓库无 `validate_template_compliance.py`，P1-1 治理脚本 `tools/ci_audit.py` 从零新建。
- **事实更正 F3**：测试基线已落地（92 测试通过），缺覆盖率门禁(≥60%)与 CI；P1-2 补 GitHub Actions + 覆盖率指标。
- **风险修正 R1**：`verify_ssl` 保持默认 false（守内网），启动红线告警而非翻转默认；已落地 `src/utils/redline.py`。
- **风险修正 R2**：全仓 `mypy --strict` 零错误被高估，改为渐进式（先核心模块非 strict）。
- **风险修正 R3**：HTML 报告须提前决断 Q5（Jinja2 须重裁决，或 Python data-driven + f-string）。
- **风险修正 R4**：观星告警砍掉邮件，仅本地 webhook/文件/CSV 导出。

### 6.2 已落地工程化（截至 2026-07-10）
- `tools/ci_audit.py`：CVE 唯一性/撞号 + 模板校验硬门禁；计数作指标非门禁（不硬编码 257/215）。
- `.github/workflows/ci.yml`：GitHub Actions（Python 3.10/3.11/3.12），ci_audit + pytest 为硬门禁，覆盖率作指标。
- `src/utils/redline.py`：启动安全红线自检（verify_ssl / auth / 弱口令告警，不阻断运行）。
- 修复 2 个损坏 POC 模板（xxl-job-unauthorized / slowloris-detect 的 YAML 语法错误）。
- **类型注解起步 (P1-4 / R2)**：`[tool.mypy]` 渐进式配置（非 `--strict`）；`config.py` / `redline.py` / `guanxing/db.py` / `guanxing/web.py` 已 mypy 零错误；CI 新增 `type-check` job 作为核心模块硬门禁。全仓约 150+ 处类型错误（多为隐式 Optional 默认值 + 少量真实类型问题），按 R2 逐模块收紧，不承诺近期 `--strict` 零错误。
- **GuanXing schema 迁移**：`db.py` 增加 `SCHEMA_VERSION` 常量 + `_meta` 版本表 + 幂等 `_migrate()` 框架（CREATE TABLE IF NOT EXISTS + 版本号 guard），解决 WAL 之外缺失的 schema 演进能力。
- 顺带修复 `guanxing/web.py:33` 真实类型 bug：`auth.username/password` 为 `str | None`，原本传给 `str` 参数；已放宽为 `Optional[str]`。
- 覆盖率现状：基线约 10%（92 测试仅覆盖 `xiazhi` 子包）；**已于 Phase 5 达成路线图目标 ≥60%（实测 60.05%，`fail_under=60` 硬门槛）**，详见 §6.7。
- **Phase 2 规格已定**：详见 `.workbuddy/delivery/Phase2_规格.md`（权威）。含 5 任务 P2-1~P2-5，并对原路线图做事实校正：① WAF 绕过在 `stealth_client.py` 默认 `True`（违反 X2），须翻转为默认关 + 显式 `--waf-bypass`；② 被动侦察 Censys/Wayback/GitHubLeak 已满足 ≥3，P2-1 重点补 FOFA + 密钥隔离/降级；③ HTML 报告锁定 Q5（仅 stdlib，`html.escape` + f-string，不引 Jinja2）。

### 6.2.1 Phase 2 落地（2026-07-10，全绿）
- **P2-1 FOFA 接入**：`src/vernalequinox/fofa_query.py` 新增 `FofaQuery`（`FofaResult` dataclass），密钥仅读 `FOFA_EMAIL`/`FOFA_KEY` 环境变量（按源隔离）；最小请求间隔限流 + 单源异常降级（warning 不中断整体 recon）；接入 `ReconEngine.full_recon` 的 `ext_tasks`，补齐 `ReconReport.fofa` 字段与 `to_dict`/`print_report`。`tests/test_fofa_query.py`（6 passed）。
- **P2-2 观星告警/导出**：`src/guanxing/notify.py` 新增 `push_change_event`（本地 webhook，异步 fire-and-forget，5s 超时，失败仅 warning）+ `append_change_log`（JSONL 本地留存）；`db.py` 变更路径解耦调用并新增 `export_data(format)`（CSV/JSON）；`web.py` 新增 `/api/export` 路由；CLI `guanxing export --format csv|json -o`。无邮件/Postgres/Redis（守 X3/R4）。`tests/test_guanxing_notify.py`（8 passed）。
- **P2-3 WAF 接线修正**：`stealth_client.py` `enable_waf_bypass` 默认 `False`（修正 X2）；`poc_engine.py` 加 `enable_waf_bypass` 参数；CLI `poc scan --waf-bypass` 显式开关；默认不进入 MVP 主链路。`tests/test_stealth_client.py`（6 passed）。
- **P2-4 HTML 报告**：`src/utils/html_report.py` 新增 `render_html_report`（纯 stdlib `html`，所有动态字段 `html.escape` 防 XSS，不引 Jinja2 守 Q5）；CLI `report --format html` 输出 `report_<ts>.html`。`tests/test_html_report.py`（6 passed，覆盖 `<script>` 注入转义）。
- **P2-5 惊蛰模板扩充 + 平台格式增强**：新增 9 个 Nuclei 风格模板（默认凭据×3：jenkins/grafana/phpmyadmin；Git 泄露×3：HEAD/index/.gitignore；Swagger×1：openapi-v3；Actuator×2：env/heapdump），均通过 `ci_audit.py`；`src/dawn/src_reporter.py` 新增 `PLATFORM_META` 平台专属字段（butian 厂商名/提交类型、vulbox 利用条件/危害、cnvd 影响产品/危害级别）+ `platform_fields()` + `generate_vuln_report(meta=...)` + `generate_batch(platform=...)`。`tests/test_src_reporter.py`（6 passed）。
- **总体验收 M2**：`ci_audit.py` exit 0（模板 224 / CVE 257 唯一）；pytest **124 passed**（Phase 1 基线 92 + Phase 2 新增 32）；mypy 核心模块（`config.py`/`redline.py`/`guanxing/db.py`/`guanxing/web.py`）零错误。
- 遗留（Phase 2 不解决，仅记录）：测试覆盖率约 10%（长期补测试工程）。git 提交已于 2026-07-10 完成（`0918dd6` 推送 origin/main）。

### 6.2.2 Phase 3 落地（2026-07-11，全绿）
- **P3-1 SBOM 与供应链（D12 / A08）**：`tools/gen_sbom.py` 生成 **CycloneDX 1.5** SBOM JSON（基于 `importlib.metadata` 解析已安装版本 + `purl`，可选 SHA-256 完整性指纹）；`--include-dev` / `--no-hashes` / `--deps-file` 可控；纯 stdlib + setuptools，`mypy` 零错误（守 X3/Q5 精神）。`tests/test_gen_sbom.py`（4 passed）。
- **P3-2 POC 模板工具链（D1 / X1）**：`tools/template_sync.py` 提供 `validate`（Nuclei 字段校验，不修改模板）与 `diff`（两目录按相对路径 + sha256 比对，added/removed/modified **计数作指标不判失败**，守 X1 不硬编码 215）；与 `ci_audit.py` 硬门禁互补。`tests/test_template_sync.py`（5 passed）。
- **P3-3 类型化推进（D10 / R2）**：新增 `tools/type_check.py` 作为渐进式门禁**单一事实来源**（CI 与本地共用）；门禁模块由 4 核心扩展到 **9**（新增 `html_report`/`notify`/`jingzhe` + 两个 `tools/*`），全部零错误；不承诺全仓 `--strict`（R2）。`pyproject.toml` dev 依赖补 `mypy`；`.github/workflows/ci.yml` type-check job 改为调用 `type_check.py`。
- **P3-4 性能压测（D11）**：`tools/bench.py` 合成 asyncio 并发基准（不触网），指标含吞吐/时延 P50~P99/错误率，并检测"超时雪崩"（错误率超阈值 exit 2，仅提示不阻断）。`tests/test_bench.py`（2 passed）。
- **总体验收 M3**：`ci_audit.py` exit 0（CVE 257 / 模板 224）；`pytest` **135 passed**（Phase 2 基线 124 + Phase 3 新增 11）；`tools/type_check.py` 9 模块零错误；`bench.py --targets 100` 产出吞吐/时延指标无崩溃。

### 6.3 Phase 2 任务清单（✅ 全部完成，见 §6.2.1）

| 任务 | 目标 | 关联约束 | 状态 |
| --- | --- | --- | --- |
| P2-1 被动侦察源扩展 | FOFA 接入 + 密钥隔离/限流/降级 | D8 | ✅ |
| P2-2 观星告警/导出 | 本地 webhook + JSONL 日志 + CSV/JSON 导出（无邮件） | D9 / X3 / R4 | ✅ |
| P2-3 WAF 接线修正 | 默认关（修正 X2）+ 显式 `--waf-bypass` | D7 / X2 / F1 | ✅ |
| P2-4 HTML 报告 | stdlib 生成、动态文本转义 | D6 / Q5 / R3 | ✅ |
| P2-5 惊蛰验证增强 | 默认凭据/Git/Swagger/Actuator 模板 + 平台格式增强 | F10~F12 | ✅ |

### 6.4 Phase 3 任务清单（✅ 全部完成，见 §6.2.2）

| 任务 | 目标 | 关联约束 | 状态 |
| --- | --- | --- | --- |
| P3-1 SBOM 与供应链 | CycloneDX SBOM + 依赖哈希（可审计） | D12 / A08 / X3 | ✅ |
| P3-2 POC 模板工具链 | 模板 schema 校验 CLI + 社区模板增量 diff（计数作指标） | D1 / X1 | ✅ |
| P3-3 类型化推进 | 渐进式门禁扩展到 9 模块零错误（不承诺全 strict） | D10 / R2 | ✅ |
| P3-4 性能压测 | asyncio 合成基准 + 吞吐/雪崩指标 | D11 | ✅ |

### 6.5 Phase 4 落地（2026-07-11，全绿）— 协作与分发（M4）
- **P4-1 打包分发（D12 延续 / M4）**：`pyproject.toml` 新增 `[build-system]`（`setuptools>=61`+`wheel`）；修正 `[project.scripts]` 为唯一真实入口 `poxiao = "src.cli:main"`（全仓经 `search_content` 确认仅 `src/cli.py` 有 `main()`，原 `frostmoon/...:main` 入口不实）；补全 `readme`/`license`(SPDX `MIT`)/`authors`/`keywords`/`classifiers`；`.github/workflows/ci.yml` 新增 `build-wheel` job（ubuntu + `python -m build --wheel` + 安装冒烟 `poxiao --help`）。**本地验证**：`python -m build --wheel` 成功产出 `poxiao-3.0.0-py3-none-any.whl`，`pip install` 后 `poxiao --help` 正常列出全部 12 子命令。模板本阶段不进 wheel（运行时用源码 `templates/` 或 `--templates-dir`），文档已说明。
- **P4-2 模板贡献流程（D1 / X1 / M4）**：新增 `.github/PULL_REQUEST_TEMPLATE.md`（模板须过 `template_sync validate`、id 唯一、必填字段、不硬编码数量）；新增 `.github/workflows/pr_check.yml`（PR 改动 `templates/**` 时跑 `template_sync validate` + `ci_audit` 硬门禁），与 `ci.yml` 主 CI 互补。
- **P4-3 文档体系（M4）**：新增 `docs/USER_GUIDE.md`（安装/快速上手/模块速览/观星/红线）+ `docs/DEVELOPER.md`（仓库结构/CI 三件套/类型化渐进/模板贡献/SBOM/压测/i18n 方向），以 `CONTEXT.md` 为 ADR 基线。
- **P4-4 i18n（D13，可选 / deferred）**：本阶段不实装代码改动；`docs/DEVELOPER.md` 记录后续方向（抽取文案层 + 验证英文报告/社区模板兼容）；HTML 报告已用 `html.escape` 守 Q5，天然兼容 UTF-8。
- **工程改进**：`.gitignore` 新增忽略 `.coverage`、`dist/`、`*.egg-info/`、`_*.txt`（提交临时文件），杜绝误提交（此前 `_msg.txt` 曾误纳入）。
- **总体验收 M4**：`python -m build --wheel` 成功且 `poxiao --help` 可运行；`ci_audit.py` PASS（CVE 257 / 模板 224）；`pytest` **135 passed**；`tools/type_check.py` 9 模块零错误；`pr_check.yml` + PR 模板到位；用户/开发者文档齐备。

### 6.6 Phase 4 任务清单（✅ 全部完成，见 §6.5）
| 任务 | 目标 | 关联约束 | 状态 |
| --- | --- | --- | --- |
| P4-1 打包分发 | wheel 可构建 + `poxiao` 一键安装运行（修正虚假入口） | D12 / M4 | ✅ |
| P4-2 模板贡献流程 | PR 模板 + PR 校验 CI（template_sync validate + ci_audit） | D1 / X1 / M4 | ✅ |
| P4-3 文档体系 | 用户手册 + 开发者指南 | M4 | ✅ |
| P4-4 i18n | 框架 deferred（文档记录方向） | D13 | ⏸️（可选延后） |

### 6.7 Phase 5 落地（2026-07-11，全绿）— 覆盖率提升（路线图 ≥60% 达成，M5）
- **P5-1 命令层/工具层单测补齐（F3 收口）**：补齐 `test_commands.py`/`test_utils.py`/`test_config.py` 等，覆盖 CLI 调度（`CMD_MAP`/`BANNER_MAP`）、`Config` 单例（含空配置路径修复）、`output`/`banner`/`redline`/`html_report` 等纯逻辑。
- **P5-2 引擎纯逻辑单测补齐**：`test_poc_engine.py`（变量展开/端口解析/结果落盘打印）、`test_guanxing_db.py`（SQLite CRUD/统计/导入导出，89%）、`test_tech_stack.py`（95%）、`test_cve_match.py`（版本区间匹配，66%）、`test_matcher_extra.py`（94%）、`test_crypto_extra.py`（83%）、`test_vernalequinox.py`（DNS/Cert/IP/CDN/ReconEngine，78%）、`test_user_agents.py`（95%）、`test_wayback.py`（95%）、`test_rate_limiter.py`（100%）。
- **P5-3 真实产品 bug 修复**：① `Config` 空配置/缺键路径异常；② `DomainDiscovery.close()` 缺失导致资源泄漏；③ `cert_info.py` `datetime.utcnow()`（Python 3.12 弃用）改为 `datetime.now()`；④ `template.py` 模块文档字符串 `\s` 无效转义 SyntaxWarning 修复（改原始字符串）。
- **P5-4 覆盖率门禁落地**：`pyproject.toml` 新增 `[tool.coverage.report] fail_under = 60`，将路线图 ≥60% 目标变为 CI 次级硬门槛（首要门禁仍为 ci_audit + 测试全通过）。
- **总体验收 M5**：`pytest` **505 passed**（Phase 4 基线 135 + Phase 5 新增 ~370）；整体覆盖率 **60.05%**（6976 语句 / 2787 遗漏），`fail_under=60` 达成；`ci_audit.py` PASS（CVE 257 / 模板 224）；`tools/type_check.py` 9 模块零错误。
- 遗留（Phase 5 不解决，仅记录）：低 ROI 触网/重 IO 模块仍偏低（`poc.py`/`scan.py` 命令层 4~8%、`proxy_pool.py` 26%、`stealth_client.py` 31%、`whois_lookup.py` 36%、`icp_query.py` 40%、`frostmoon/collector.py` 17%、`jingzhe.py` 11%）；i18n 已于 Phase 6（D13）落地（见 §6.9）。

### 6.8 Phase 5 任务清单（✅ 全部完成，见 §6.7）

| 任务 | 目标 | 关联约束 | 状态 |
| --- | --- | --- | --- |
| P5-1 命令/工具层单测 | CLI 调度 + Config + 工具纯逻辑覆盖 | F3 | ✅ |
| P5-2 引擎纯逻辑单测 | 各引擎纯函数/数据模型高覆盖 | F3 | ✅ |
| P5-3 真实 bug 修复 | Config/close/utcnow/转义 4 处修复 | D10 | ✅ |
| P5-4 覆盖率门禁 | `fail_under=60` 硬门槛 | F3 | ✅ |

### 6.9 Phase 6 落地（2026-07-11，全绿）— 国际化 (i18n / D13，M6)

> 路线图唯一尚未启动的交付物（P4-4 deferred）于本阶段闭环。采用**「键即中文原文、未译回退」**轻量设计，对既有中文输出零破坏，译文增量补充即可，不要求全量翻译。

- **P6-1 文案层核心（D13）**：新增 `src/i18n/__init__.py`（`_()` / `set_locale()` / `get_locale()` / `is_english()`）与 `src/i18n/messages.py`（`EN` 英文目录，覆盖状态词/报告章节/严重级别/漏洞类型/HTML 表头共 ~50 条）。语言解析优先级：`--lang` > 环境变量 `POXIAO_LANG` > 默认 `zh_CN`；支持别名 `zh/en/zh_cn/en_us/中文/英语`。
- **P6-2 输出层接入**：`src/utils/output.py` 的 `Out` 状态/标题/章节/键值方法统一经 `_()` 翻译；`src/cli.py` 增加全局 `--lang {zh,en}` 选项（须在子命令前指定，如 `poxiao --lang en scan ...`）。
- **P6-3 英文报告（D13 验收）**：`src/dawn/src_reporter.py` 章节标题/平台字段标签 + 严重级别(`SEVERITY_EN`)/漏洞类型(`VULN_TYPE_EN`) locale 化，索引排序与 locale 解耦；`src/utils/html_report.py` 表头/风险/状态标签翻译 + `lang` 属性随 locale 切换（en → `lang="en"`）。
- **P6-4 测试（F3 收口）**：`tests/test_i18n.py`（12 passed）覆盖核心翻译/回退/别名/环境变量解析、`Out` 集成、SRC 报告英文渲染、HTML 报告英文渲染与中文默认；`src/i18n` 覆盖率 92%。
- **总体验收 M6**：`pytest` **517 passed**（Phase 5 基线 505 + Phase 6 新增 12）；整体覆盖率 **60.50%**，`fail_under=60` 达成；`ci_audit.py` PASS（CVE 257 / 模板 224）；`tools/type_check.py` 9 模块零错误。
- **P6-5 自由文本全量英文化（D13 收口）**：SRC 报告自由文本（`_finding_title`/`_finding_description`/`_finding_steps`/`_default_suggestion`/`generate_from_cve`）经 `_()` + `{0}/{1}` 占位符 `.format` 接入 `EN` 目录（新增 ~110 条自由文本译文，键即中文原文、未译回退，中文输出零破坏）；`tests/test_i18n.py` 增 3 用例（zh 保留 / en 翻译 / CVE 报告）。
- **总体验收 M6+**：`pytest` **520 passed**（Phase 6 基线 517 + 延伸新增 3）；整体覆盖率 **60.60%**，`fail_under=60` 达成；`ci_audit.py` PASS（CVE 257 / 模板 224）；`tools/type_check.py` 9 模块零错误。SRC 报告在 en 模式下已全英文化（结构标签 + 自由文本 + 级别 + 类型），中文默认输出零破坏；Nuclei 模板为数据文件未被改动。

### 6.10 Phase 6 任务清单（✅ 全部完成，见 §6.9）

| 任务 | 目标 | 关联约束 | 状态 |
| --- | --- | --- | --- |
| P6-1 文案层核心 | `src/i18n` + `EN` 目录 + locale 解析 | D13 | ✅ |
| P6-2 输出层接入 | `Out` 经 `_()` + CLI `--lang` | D13 | ✅ |
| P6-3 英文报告 | src_reporter/html_report locale 化 | D13 | ✅ |
| P6-4 测试 | `tests/test_i18n.py`（12 passed） | F3 | ✅ |
| P6-5 自由文本英文化 | SRC 标题/描述/步骤/建议/CVE 经 `_()` 全量 locale 化（~110 条译文） | D13 | ✅ |

