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
- 覆盖率现状：整体约 10%（92 测试仅覆盖 `xiazhi` 子包），路线图目标 ≥60% 待补测试。
- **Phase 2 规格已定**：详见 `.workbuddy/delivery/Phase2_规格.md`（权威）。含 5 任务 P2-1~P2-5，并对原路线图做事实校正：① WAF 绕过在 `stealth_client.py` 默认 `True`（违反 X2），须翻转为默认关 + 显式 `--waf-bypass`；② 被动侦察 Censys/Wayback/GitHubLeak 已满足 ≥3，P2-1 重点补 FOFA + 密钥隔离/降级；③ HTML 报告锁定 Q5（仅 stdlib，`html.escape` + f-string，不引 Jinja2）。

### 6.2.1 Phase 2 落地（2026-07-10，全绿）
- **P2-1 FOFA 接入**：`src/vernalequinox/fofa_query.py` 新增 `FofaQuery`（`FofaResult` dataclass），密钥仅读 `FOFA_EMAIL`/`FOFA_KEY` 环境变量（按源隔离）；最小请求间隔限流 + 单源异常降级（warning 不中断整体 recon）；接入 `ReconEngine.full_recon` 的 `ext_tasks`，补齐 `ReconReport.fofa` 字段与 `to_dict`/`print_report`。`tests/test_fofa_query.py`（6 passed）。
- **P2-2 观星告警/导出**：`src/guanxing/notify.py` 新增 `push_change_event`（本地 webhook，异步 fire-and-forget，5s 超时，失败仅 warning）+ `append_change_log`（JSONL 本地留存）；`db.py` 变更路径解耦调用并新增 `export_data(format)`（CSV/JSON）；`web.py` 新增 `/api/export` 路由；CLI `guanxing export --format csv|json -o`。无邮件/Postgres/Redis（守 X3/R4）。`tests/test_guanxing_notify.py`（8 passed）。
- **P2-3 WAF 接线修正**：`stealth_client.py` `enable_waf_bypass` 默认 `False`（修正 X2）；`poc_engine.py` 加 `enable_waf_bypass` 参数；CLI `poc scan --waf-bypass` 显式开关；默认不进入 MVP 主链路。`tests/test_stealth_client.py`（6 passed）。
- **P2-4 HTML 报告**：`src/utils/html_report.py` 新增 `render_html_report`（纯 stdlib `html`，所有动态字段 `html.escape` 防 XSS，不引 Jinja2 守 Q5）；CLI `report --format html` 输出 `report_<ts>.html`。`tests/test_html_report.py`（6 passed，覆盖 `<script>` 注入转义）。
- **P2-5 惊蛰模板扩充 + 平台格式增强**：新增 9 个 Nuclei 风格模板（默认凭据×3：jenkins/grafana/phpmyadmin；Git 泄露×3：HEAD/index/.gitignore；Swagger×1：openapi-v3；Actuator×2：env/heapdump），均通过 `ci_audit.py`；`src/dawn/src_reporter.py` 新增 `PLATFORM_META` 平台专属字段（butian 厂商名/提交类型、vulbox 利用条件/危害、cnvd 影响产品/危害级别）+ `platform_fields()` + `generate_vuln_report(meta=...)` + `generate_batch(platform=...)`。`tests/test_src_reporter.py`（6 passed）。
- **总体验收 M2**：`ci_audit.py` exit 0（模板 224 / CVE 257 唯一）；pytest **124 passed**（Phase 1 基线 92 + Phase 2 新增 32）；mypy 核心模块（`config.py`/`redline.py`/`guanxing/db.py`/`guanxing/web.py`）零错误。
- 遗留（Phase 2 不解决，仅记录）：测试覆盖率约 10%（长期补测试工程）；git 未提交（仓库未配置 `user.name/user.email`）。

### 6.3 Phase 2 任务清单（✅ 全部完成，见 §6.2.1）

| 任务 | 目标 | 关联约束 | 状态 |
| --- | --- | --- | --- |
| P2-1 被动侦察源扩展 | FOFA 接入 + 密钥隔离/限流/降级 | D8 | ✅ |
| P2-2 观星告警/导出 | 本地 webhook + JSONL 日志 + CSV/JSON 导出（无邮件） | D9 / X3 / R4 | ✅ |
| P2-3 WAF 接线修正 | 默认关（修正 X2）+ 显式 `--waf-bypass` | D7 / X2 / F1 | ✅ |
| P2-4 HTML 报告 | stdlib 生成、动态文本转义 | D6 / Q5 / R3 | ✅ |
| P2-5 惊蛰验证增强 | 默认凭据/Git/Swagger/Actuator 模板 + 平台格式增强 | F10~F12 | ✅ |

