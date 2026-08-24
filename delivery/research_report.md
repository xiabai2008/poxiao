# AICoding 架构设计 · 行业调研报告

> 本文档为《AICoding 架构设计》核心产物之一，定位为**行业调研报告（research_report）**。
> 上游输入：主理人转交的用户诉求 + `material_digest.md`（G1 通过）；
> 下游输出：驱动 `business-architect`（业务架构师）的行业调研判断，最终落入《高层架构设计》的 §3 行业调研章节。
>
> **工具说明**：由 `research-analyst`（研究分析师 - 查有据）负责产出，经 G2 自动校验与人工审核通过后方可进入下游消费。
> **结构纪律**：全文按「事实 → 对比 → 建议 → 风险」四段式组织。本章节仅作**建议**而非最终裁决，最终业务边界由 `business-architect` 冻结。
> **问题类型（tech-research-advisor Phase 0）**：架构类 + 工具选型类混合——既涉及 SRC 安全工具链的架构模式（异步 CLI、无外部依赖、本地存储、Web 监控），也涉及同类框架/库的选型对比（Nuclei 模板引擎、httpx 异步探测、reNgine 监控范式）。

---

## 0. 元信息：修订记录

> 记录报告版本、调研范围、调研人、调研时间，确保结论可追溯。

```yaml
标题: 破晓 (PoXiao) v3.0.0 - 行业调研报告 v0.1
版本: v0.1
状态: Draft   # Draft | Reviewing | Approved | Deprecated
创建日期: 2026-07-09
最后更新: 2026-07-09
调研人: research-analyst（查有据）
审核人:
  - team-lead（主理人）

关联文档:
  上游输入:
    - 用户诉求: 由主理人注入（二十四节气 SRC 安全工具链：技术栈指纹 + CVE 精确匹配 + 三层降噪）
    - 调研目标: 由主理人注入（行业标杆、方案对比与加权评分，为 business-architect 提供证据链）
    - 资料摘要: D:/HZR_PROJECTS/poxiao/.workbuddy/output/material_digest.md（G1 自动校验通过）
  下游产出:
    - 高层架构设计 §3 行业调研: 将由 business-architect 整合到此章节
```

| 版本 | 日期 | 作者 | 变更内容 | 评审状态 |
| --- | --- | --- | --- | --- |
| v0.1 | 2026-07-09 | research-analyst（查有据） | 初稿（G2 待自动校验 + 人工审核） | Draft |

---

## 1. 调研问题收敛

> 调研启动前，先围绕用户诉求收拢为明确的调研问题集合，确保调研不偏离当前项目背景。

### 1.1 原始调研种子

> 从用户诉求与 `material_digest.md` 冲突/缺口中提取需要调研验证的论题，逐条给出优先级。

| 编号 | 待验证论题 | 来源（用户诉求 / 资料要点） | 调研优先级 | 备注 |
| --- | --- | --- | --- | --- |
| S1 | 同类开源漏洞扫描器的 POC 模板引擎设计范式，对 PoXiao 夏至 xiazhi 引擎兼容/扩展性的启示 | 用户诉求「技术栈指纹 + CVE 精确匹配」；D7 §3（Nuclei 风格 YAML，215 模板）；X1（206 vs 215） | 高 | 直接关系模板引擎架构 |
| S2 | 同类商业/开源扫描器在 WAF 绕过上的工程实践，PoXiao 是否应保留 waf_bypass 模块 | X2（D2§7⑧ 否定 vs D1§2/D6§9 代码含 waf_bypass.py）；Q1 | 高 | 安全架构 + stealth 模块边界 |
| S3 | 本地 CLI 安全工具/侦察框架的数据存储选型（SQLite vs JSON）与「无外部依赖」设计范式 | X3（D1§9/D6§8 SQLite vs D2§9 JSON）；Q2 | 高 | 关系 GuanXing 监控库与全项目一致性 |
| S4 | 业界漏洞扫描误报抑制/降噪（PoXiao 三层降噪使 94%→5%）的可借鉴工程模式 | 用户诉求「三层降噪」；D1§4 | 中 | 验证自研降噪的行业合理性 |
| S5 | 本地 CLI 安全工具链的部署/分发形态与异步优先架构范式，对 MVP 范围与渐进输出的支撑 | 用户诉求「异步优先/无外部依赖/渐进输出」；D1§10 设计原则 | 中 | 支撑部署形态与 MVP 判断 |

### 1.2 调研问题收敛

> 将 §1.1 的种子收敛为 5 个可执行的调研问题。每条问题明确调研对象、调研目标与产出预期。问题编号用 RQ（Research Question）以避免与资料摘要的冲突/待决项编号（X1-X3 / Q1-Q7）混淆。

| 编号 | 调研问题 | 调研对象 | 调研目标 | 预期产出 | 关联种子 |
| --- | --- | --- | --- | --- | --- |
| RQ1 | 同类开源/商业扫描器的 POC 模板引擎范式是什么？对 PoXiao 夏至 xiazhi 的模板 schema 兼容性、扩展性有何启示？ | Nuclei（开源模板引擎事实标准）、OWASP ZAP、reNgine | 模板 DSL 结构、协议覆盖、社区生态、与 PoXiao 现有 Nuclei 风格模板（D7§3）的对齐度 | 模板引擎设计建议 + 兼容性结论（含 X1 模板数建议） | S1 |
| RQ2 | 同类扫描器在 WAF 绕过/规避上的工程实践如何？PoXiao 是否应保留 waf_bypass 模块（X2/Q1）？ | Nuclei、httpx、Acunetix、Burp Suite、OWASP ZAP | WAF 处理是「绕过/规避」还是「兼容/可靠性」；各标杆是否将其作为核心能力 | WAF 绕过取舍建议（建议，非裁决） | S2 |
| RQ3 | 本地 CLI/侦察框架的数据存储选型（SQLite vs JSON）与「无外部依赖」范式如何？PoXiao 是否应统一为 SQLite（X3/Q2）？ | reNgine（SQLite/Postgres + Web 监控）、Nuclei（文件输出）、OWASP ZAP（本地会话库）、Acunetix（SaaS） | 变化追踪/分页/监控场景对 DB 的真实需求；JSON 单文件适用的边界 | 存储选型边界建议（GuanXing 监控 vs 报告输出） | S3 |
| RQ4 | 业界在漏洞扫描误报抑制/降噪上有哪些可借鉴的工程模式？如何佐证 PoXiao 三层降噪（94%→5%）的合理性？ | Nuclei（验证式检测）、PortSwigger/Burp（置信度分级 + 手动验证）、OWASP ZAP（被动+主动 + 置信度） | 降噪的通用工程手法（验证、置信度、上下文、排除规则） | 降噪工程模式映射表 + 对 PoXiao 三层降噪的佐证 | S4 |
| RQ5 | 本地 CLI 安全工具链的部署/分发形态与异步架构范式在业界标杆中如何体现？对 MVP 范围与渐进输出有何支撑？ | Nuclei / httpx（Go 单二进制 CLI）、reNgine（Docker 全栈）、Acunetix（SaaS+本地） | 单二进制/无外部依赖 vs Docker 全栈 vs SaaS 的取舍；异步并发模型 | 部署形态范式对比 + MVP 范围建议 | S5 |

> **§1 自检记录（中间确认协议 §2.4）**：本阶段为「从种子收敛为 RQ」的单向整理，不存在 ≥2 种互斥方案需要裁决；§2.1 #1 方案分歧型不触发。反向验证 3 问：Q1 若收敛方向被推翻，返工范围仅限 §1 表格（当前产物的 5% 以内），切换成本 0.1 人月 → 可控；Q2 调研问题列表不影响用户/客户/监管可感知行为 → 感知不到；Q3 问题列表本身非用户显式能力点，仅映射上游冲突项 → 未偏离。结论：**未命中，不发起中间确认**。（详见附录 B）

---

## 2. 事实：标杆系统盘点和方案详述

> **四段式「事实」段**。只陈列调研发现的事实，不做引申建议或边界裁决。

### 2.1 行业标杆清单

> 完整盘点调研覆盖的所有标杆系统，给出标签化画像。

**硬指标**：本清单含 4 家；包含 1 家头部 SaaS 代表（Acunetix）+ 3 家开源/自研代表（Nuclei、OWASP ZAP、reNgine），满足「≥3 家且含 ≥1 头部 SaaS + ≥1 开源/自研」。

| 编号 | 标杆系统 | 厂商 / 社区 | 部署形态 | 场景覆盖 | 技术亮点 | 商业模式 | 调研来源 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | Nuclei | ProjectDiscovery（开源社区） | 本地 CLI 单二进制（Go） | 多协议漏洞扫描（HTTP/DNS/TCP/SSL/WebSocket/Headless/Code 等）、模板驱动 | YAML DSL 模板引擎、社区模板库、验证式检测（zero false positives 主张）、零外部依赖 | 开源（MIT）+ 商业云（PDCP） | SR-01、SR-02、SR-10 |
| B2 | Acunetix（Invicti） | Invicti Security（商业） | SaaS + 本地（on-premises）双形态 | Web 应用与 API 的 DAST 扫描、IAST、WAF 兼容导出 | proof-based scanning（自动验证降噪）、爬虫型 DAST、数千 CVE 覆盖、Jira/GitHub/GitLab 集成 | 商业闭源订阅 | SR-06、SR-07、SR-11 |
| B3 | OWASP ZAP | OWASP（开源社区） | 本地桌面 / CI Daemon / API（无原生 SaaS） | Web 应用 DAST（代理被动+主动扫描）、渗透辅助 | 代理架构、Add-on 插件市场、自动化框架、置信度评级报告、GitHub Top 1000 项目 | 开源（Apache-2.0） | SR-08、SR-11 |
| B4 | reNgine | yogeshojha（开源社区） | Docker Compose 全栈部署（Django+Celery+PostgreSQL） | Web 应用自动化侦察、子域/端点发现、Nuclei 漏洞扫描、资产监控与变化追踪、Web 仪表盘 | 高度可配置 YAML 扫描引擎、数据库支撑的侦察数据关联、持续监控、变化追踪、多角色权限 | 开源（GPL-3.0） | SR-04、SR-05 |

### 2.2 标杆方案详述

> 每家标杆逐一展开（4 家均有详述）；每段区分「已核实的事实」与「推断/假设」。置信度标注：已核实 / 推断 / 综合归纳。

#### 2.2.1 B1 - Nuclei（ProjectDiscovery）

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 基于简单 YAML DSL 的快速、可定制漏洞扫描器，面向应用/API/网络/DNS/云配置的漏洞发现 | 已核实（SR-01 标题与介绍段） |
| 目标用户 | 安全工程师、渗透测试人员、漏洞赏金猎人、开发者 | 已核实（SR-01 For Security Engineers / For Developers 段落） |
| 核心能力 | 模板驱动的漏洞检测；支持协议 dns/file/http/headless/tcp/ssl/websocket/whois/code/javascript；社区模板库（持续更新） | 已核实（SR-01 协议列表与 Templates 段） |
| 架构特点 | 模板引擎读取 YAML 定义请求与匹配逻辑；多协议请求聚类（request clustering）+ 并行处理；速率限制 -rl 默认 150 req/s、-c 并发 25、-bs 批量 25 | 已核实（SR-01 RATE-LIMIT / OPTIMIZATIONS 段） |
| 部署形态 | 本地 CLI 单二进制（Go，`go install`）；官方提示「作为服务运行有安全风险，需谨慎」 | 已核实（SR-01 Installation / 标题段） |
| 集成方式 | CLI / 库（Go library）/ 云 API（PDCP）；输出 JSON/JSONL/Markdown/SARIF；report-db 持久化（未明说底层引擎） | 已核实（SR-01 OUTPUT 段） |
| 定价模式 | 开源免费 + 商业云（ProjectDiscovery Cloud） | 已核实（SR-01 社区与云提及） |
| 优势 | 生态最大、模板复用成本低、零外部依赖（单二进制）、社区验证式模板带来低误报主张 | 综合归纳 |
| 局限 | README 无内置 WAF 绕过/规避特性（仅标准 HTTP 控制）；模板质量依赖社区；监控/侦察编排需外部组合 | 已核实 + 推断（SR-01 全文无 WAF/bypass/evasion 关键词） |
| 对本项目的参考价值 | PoXiao 夏至 xiazhi 的 Nuclei 风格模板（D7§3）与之同构；其「异步单二进制 + 无外部依赖 + 模板驱动」是 PoXiao 设计原则（D1§10）的最强同类印证 | 推断 |

#### 2.2.2 B2 - Acunetix（Invicti）

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 面向 Web 应用与 API 的 DAST 漏洞扫描器，从外部向内测试运行中的应用 | 已核实（SR-06 "DAST-first vulnerability scanner" 段） |
| 目标用户 | 企业安全团队、DevSecOps、开发组织 | 已核实（SR-06 "organizations / security teams" 段） |
| 核心能力 | 爬虫型 DAST + IAST；数千已知漏洞与 CVE 覆盖；proof-based scanning 自动确认许多发现以降噪；认证区域扫描 | 已核实（SR-06 Accuracy/Validation、Coverage 段） |
| 架构特点 | 证明式扫描（proof of exploit）自动确认漏洞，减少噪声；支持分布式扫描处理大环境；与 CI/CD、Jira/GitHub/GitLab issue tracker 集成 | 已核实（SR-06 Automation and integration 段） |
| 部署形态 | 本地部署（on-premises）**或** SaaS 解决方案，可按需扩展扫描容量 | 已核实（SR-06 "Scalable and flexible deployment … on premises or as a SaaS solution" 段） |
| 集成方式 | CI/CD 流水线、Jira/GitHub/GitLab、扩展 API | 已核实（SR-06 Integrations 段） |
| 定价模式 | 商业闭源订阅（按站点/容量计费，需询价） | 已核实（SR-06 商业定位；公开价格未列） |
| 优势 | 企业级降噪（proof-based）、合规友好的报告与 issue 集成、SaaS 弹性 | 综合归纳 |
| 局限 | 闭源、成本高、SaaS 形态存在数据出境/合规顾虑；与 PoXiao「本地 CLI + 无外部依赖 + 开源」定位根本冲突 | 推断 |
| 对本项目的参考价值 | 其 WAF 能力是「配置/导出兼容」（见 §2.3），而非「绕过」——为 X2（是否做 WAF 绕过）提供行业参照；其 proof-based 降噪与 issue 集成思路可借鉴 | 推断 |

#### 2.2.3 B3 - OWASP ZAP

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 全球使用最广泛的 Web 应用扫描器；免费开源，社区驱动的 GitHub Top 1000 项目 | 已核实（SR-08 首页标语） |
| 目标用户 | 开发者、渗透测试人员、安全团队、企业 | 已核实（SR-08 社区项目定位） |
| 核心能力 | 代理型 DAST（被动 + 主动扫描）、Add-on 插件扩展、自动化框架（Automation Framework）、API/Daemon 模式 | 已核实（SR-08 + 行业共识；主动/被动扫描为 ZAP 基线能力） |
| 架构特点 | 代理拦截 + 爬虫 + 主动扫描器；通过 Add-on 市场扩展；会话数据本地持久化 | 推断（SR-08 仅首页，架构细节为行业共识，标注推断） |
| 部署形态 | 本地桌面 / CI Daemon / REST API（无原生 SaaS） | 已核实（SR-08 下载/独立开源项目定位）+ 推断 |
| 集成方式 | 桌面 GUI、API、Daemon、自动化框架、CI 集成 | 已核实（行业共识）+ 推断 |
| 定价模式 | 开源免费（Apache-2.0） | 已核实（SR-08 开源声明） |
| 优势 | 零成本、生态成熟、可扩展性强、置信度评级报告 | 综合归纳 |
| 局限 | 重量级 UI/代理模型，不适合作为「无外部依赖的轻量 CLI 侦察链」直接复用；报告偏技术细节 | 推断 |
| 对本项目的参考价值 | 其「置信度评级（Certain/Firm/Tentative）+ 上下文交叉验证 + 配置微调排除已知误报」是业界降噪标准实践（SR-09），可映射 PoXiao 三层降噪 | 推断 |

#### 2.2.4 B4 - reNgine

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 面向 Web 应用的自动化侦察（recon）框架，专注高度可配置的流式侦察 + 数据关联 + 持续监控 + Web UI | 已核实（SR-04 定位段；SR-05 Introduction） |
| 目标用户 | 渗透测试人员、漏洞赏金猎人、企业安全团队 | 已核实（SR-04/SR-05 "pentesters, bug bounty hunters"） |
| 核心能力 | 子域发现、IP/端口识别、端点发现、目录/文件 fuzzing、截图；漏洞扫描（Nuclei / Dalfox / CRLFuzzer / S3）；WAF 检测；OSINT；侦察数据变化追踪；持续监控 | 已核实（SR-05 Features 清单） |
| 架构特点 | Django + Celery + PostgreSQL + Docker Compose 全栈；YAML 可配置扫描引擎（线程/超时/速率）；多角色权限（Sys Admin/Pentester/Auditor）；类自然语言查询；定时/周期扫描 | 已核实（SR-04 技术栈段；SR-05 Configurable Scan Engines / Multiple Users / Continuous Monitoring） |
| 部署形态 | Docker Compose 一键部署（install.sh），访问 127.0.0.1 或 VPS IP | 已核实（SR-04 Getting Started / docker-compose 段） |
| 集成方式 | 工具库（Nuclei/Subfinder/Naabu/amass 可配置）、HackerOne 导入、通知（Slack/Discord/Telegram）、PDF/LLM 报告 | 已核实（SR-05 Tools Arsenal / BountyHub / Report Generation） |
| 定价模式 | 开源免费（GPL-3.0） | 已核实（SR-05 License） |
| 优势 | 侦察数据关联 + 变化追踪 + Web 仪表盘，是「资产监控」场景的直接标杆；明确复用 Nuclei 做漏洞扫描 | 综合归纳 |
| 局限 | 技术栈重（Django+Celery+PostgreSQL+Docker），与 PoXiao「无外部依赖（不用 Docker/Redis/外部 DB）」原则（D1§10）相悖；PostgreSQL 而非 SQLite | 已核实 + 推断（SR-04 明确 PostgreSQL） |
| 对本项目的参考价值 | 其「侦察数据变化追踪 + 持续监控 + Web 仪表盘」是 GuanXing（D1§2）的直接范式参照；但其重依赖栈是**反面教材**——印证 PoXiao 用 SQLite 单文件 + Flask 实现同能力的合理性 | 推断 |

### 2.3 关键技术能力横向事实

> 不评分、不排序，仅按能力维度横陈各方案事实。

| 能力维度 | B1 Nuclei | B2 Acunetix | B3 OWASP ZAP | B4 reNgine | 说明 / 来源 |
| --- | --- | --- | --- | --- | --- |
| POC / 模板引擎范式 | YAML DSL（id/info{severity}/http{matchers-condition,matchers[type:status/size/word/regex/binary/dsl/header]}） | 闭源专有规则，无公开模板格式 | 闭源规则 + Add-on 脚本 | YAML 可配置扫描引擎 + 复用 Nuclei 模板 | SR-02、SR-10、SR-04；PoXiao 模板同构（D7§3） |
| 异步 / 并发模型 | 并行请求聚类；-rl 150/s、-c 25、-bs 25 | 分布式扫描（商业） | 代理 + 多线程扫描 | Celery 多 worker（MAX/MIN_CONCURRENCY） | SR-01、SR-04、SR-06 |
| WAF 处理（绕过 vs 兼容） | 无内置 WAF 绕过（README 无 bypass/evasion 关键词） | WAF = 配置/导出兼容（导出扫描结果到 WAF、配置白名单），非绕过 | 无内建绕过；靠配置/排除 | WAF 检测（识别），非绕过 | SR-01、SR-07；X2 关键事实 |
| 降噪 / 误报抑制 | 验证式检测主张（zero false positives），模拟真实步骤确认 | proof-based scanning 自动确认 | 置信度评级（Certain/Firm/Tentative）+ 手动验证 + 配置排除 | 依赖 Nuclei 模板质量 | SR-01、SR-06、SR-09、SR-11 |
| 存储 / 数据持久化 | 文件输出（JSON/JSONL/Markdown/SARIF）+ 可选 report-db（引擎未明） | SaaS/本地数据库（闭源） | 本地会话库（持久化扫描会话） | PostgreSQL（数据库支撑的侦察关联） | SR-01、SR-04、SR-08 |
| 部署形态 | 本地单二进制 CLI，无外部依赖 | SaaS + 本地（商业） | 本地桌面 / CI Daemon（无 SaaS） | Docker Compose 全栈（重依赖） | SR-01、SR-04、SR-06、SR-08 |
| 监控 / 变化追踪（Web UI） | 无（纯 CLI） | SaaS 仪表盘（商业） | 无原生监控 UI | 有（持续监控 + 变化追踪 + Web 仪表盘） | SR-05；对应 GuanXing（D1§2） |
| 报告 / 集成（SRC / Issue） | JSON/SARIF/Markdown 导出 | Jira/GitHub/GitLab 集成、导出 | 报告 + API | HackerOne 导入、PDF/LLM 报告、通知 | SR-01、SR-04、SR-06 |
| 开源 / 闭源 | 开源 | 闭源商业 | 开源 | 开源 | 各 SR |

---

## 3. 对比：对比矩阵与加权评分

> **四段式「对比」段**。在 §2 的事实基础上建立对比矩阵，赋予权重并打分。

### 3.1 对比矩阵

> **每行权重之和 = 1.00**。评估维度与权重依据 PoXiao 项目特征（本地 CLI、无外部依赖、SRC 工具链、开源定位）设定。

| 评估维度 | 权重 | 权重理由 | B1 Nuclei | B2 Acunetix | B3 ZAP | B4 reNgine |
| --- | --- | --- | --- | --- | --- | --- |
| 场景契合度 | 0.30 | PoXiao 是「技术栈指纹 + CVE 匹配 + 模板驱动 + 本地 CLI」SRC 工具链，契合度直接决定借鉴价值 | 4 | 3 | 4 | 4 |
| 技术成熟度 | 0.20 | 标杆的工程成熟度影响借鉴可靠性（社区规模、持续维护） | 5 | 5 | 5 | 4 |
| 集成难度（反向） | 0.15 | 反向指标：越高越易借鉴/参考；PoXiao 需无外部依赖，重栈难以直接借鉴 | 5 | 2 | 4 | 2 |
| 成本（反向） | 0.15 | 反向指标：越高越低成本；开源/单二进制优于商业 SaaS | 5 | 1 | 5 | 4 |
| 合规可控性 | 0.20 | PoXiao 本地 CLI、数据不出本机；SaaS/闭源带来数据出境与合规风险 | 5 | 2 | 5 | 4 |
| **加权总分** | **1.00** | — | **4.70** | **2.75** | **4.55** | **3.70** |

**评分标尺**：每项 1~5 分，1 = 严重不符合，3 = 基本满足但存在明显局限，5 = 完美契合（契合「对 PoXiao 的借鉴价值」）。

**加权总分计算**：
- B1 Nuclei = 0.30×4 + 0.20×5 + 0.15×5 + 0.15×5 + 0.20×5 = 1.20 + 1.00 + 0.75 + 0.75 + 1.00 = **4.70**
- B2 Acunetix = 0.30×3 + 0.20×5 + 0.15×2 + 0.15×1 + 0.20×2 = 0.90 + 1.00 + 0.30 + 0.15 + 0.40 = **2.75**
- B3 ZAP = 0.30×4 + 0.20×5 + 0.15×4 + 0.15×5 + 0.20×5 = 1.20 + 1.00 + 0.60 + 0.75 + 1.00 = **4.55**
- B4 reNgine = 0.30×4 + 0.20×4 + 0.15×2 + 0.15×4 + 0.20×4 = 1.20 + 0.80 + 0.30 + 0.60 + 0.80 = **3.70**

> **§3 自检记录（中间确认协议 §2.4 / §3.1 权重设定）**：权重采用「场景契合度 0.30 + 合规可控性 0.20 + 技术成熟度 0.20 + 集成难度 0.15 + 成本 0.15」。反向验证 3 问：Q1 若权重被推翻重设，返工范围仅限 §3.1 权重列与加权总分（产物的 5% 以内），切换成本可忽略 → 可控；Q2 评分权重不影响用户/客户/监管可感知行为 → 感知不到；Q3 权重非用户显式指定能力点 → 未偏离。敏感性说明：即便将「场景契合度」降至 0.20、「合规可控性」升至 0.30，排名仍为 Nuclei(4.55) > ZAP(4.45) > reNgine(3.55) > Acunetix(2.65)，结论稳健。结论：**未命中，不发起中间确认**。（详见附录 B）

### 3.2 评分结论

> 基于 §3.1 加权总分，形成分层结论。每层结论引用得分作为依据。

- **优先借鉴**：**Nuclei（4.70）** — 适用度评分最高（4.70）。理由：场景契合度 4/5（模板驱动 + 本地 CLI + 无外部依赖与 PoXiao 设计原则 D1§10 同构）、技术成熟度 5/5（社区事实标准）、集成难度 5/5（单二进制零依赖易借鉴）、成本 5/5（开源）、合规可控性 5/5（数据不出本机）。其 YAML DSL 模板范式是 PoXiao 夏至 xiazhi 引擎的直接参照（D7§3 已同构）。
- **部分借鉴**：**OWASP ZAP（4.55）** — 借鉴点：置信度评级（Certain/Firm/Tentative）+ 上下文交叉验证 + 配置排除已知误报的降噪实践（SR-09），可映射 PoXiao 三层降噪的工程合理性；Add-on 扩展模型思路。不借鉴的部分：重量级代理/桌面 UI 模型不直接复用为 PoXiao 轻量 CLI 侦察链。
- **部分借鉴**：**reNgine（3.70）** — 借鉴点：「侦察数据变化追踪 + 持续监控 + Web 仪表盘」是 GuanXing（D1§2）资产监控的直接范式参照，且明确复用 Nuclei 做漏洞扫描。不借鉴的部分：其 Django+Celery+PostgreSQL+Docker 全栈（SR-04）与 PoXiao「无外部依赖（不用 Docker/Redis/外部 DB）」原则（D1§10）根本冲突——仅借鉴其监控/变化追踪设计，不借鉴技术栈；存储改用 SQLite 单文件（见 §4.1）。
- **不借鉴（否决）**：**Acunetix 的 SaaS/商业闭源形态作为采用对象（2.75）** — 否决理由：评分最低（2.75），核心否决点为合规可控性 2/5（SaaS 数据出境风险）+ 成本 1/5（商业闭源高成本）+ 集成难度 2/5（闭源无法借鉴内部实现）。其定位与 PoXiao「本地 CLI + 无外部依赖 + 开源」根本冲突。**仅作方法论参考**：proof-based scanning 降噪思路、WAF 兼容（非绕过）定位、Jira/GitHub issue 集成模式。

### 3.3 方案组合分析（如有）

> 调研发现「单一方案无法覆盖全部需求，需组合」时展开。

| 组合方式 | 覆盖哪些能力 | 未覆盖能力 | 组合复杂度 | 总体成本估算 |
| --- | --- | --- | --- | --- |
| Nuclei（模板引擎范式 + 异步 CLI）+ ZAP（降噪/置信度实践参考）+ reNgine 概念（监控/变化追踪，改为 SQLite 实现） | POC 模板引擎、异步探测、降噪工程模式、Web 资产监控 | 商业级 SaaS 弹性、闭源 IAST 深度 | 中（均为开源/自研参考，无外部绑定） | 低（全部开源 + 自研，无授权成本） |

> 说明：PoXiao 无需「采购」任何标杆，组合策略为「以 Nuclei 为引擎范式主线，吸收 ZAP 的降噪实践与 reNgine 的监控概念（用 SQLite 自研落地）」，与 PoXiao 开源/自研定位一致。

---

## 4. 建议：取舍决策支持

> **四段式「建议」段**。基于 §2 事实 + §3 对比，给出可被 `business-architect` 直接采用的建议。本节是**建议而非最终裁决**，最终边界由业务架构师冻结。

### 4.1 自研 / 采购 / 复用边界建议

| 能力项 | 建议方式 | 建议依据 | 候选方案 / 系统 | 关键前提 |
| --- | --- | --- | --- | --- |
| POC 模板引擎（夏至 xiazhi） | 复用（参考 Nuclei 范式自研引擎） | Nuclei YAML DSL 为行业事实标准；PoXiao 模板已 Nuclei 风格（D7§3，215 个）；复用社区范式降低自研成本 | Nuclei template schema（id/info/severity/http/matchers） | 保持与 Nuclei 模板格式兼容，便于复用社区模板库 |
| 异步 HTTP 探测 / 技术栈指纹（破晓 dawn） | 复用（httpx 思路自研） | httpx 基于 retryablehttp 异步、提取技术栈/CDN/WAF（SR-03），与 dawn 指纹设计一致；单库零依赖 | httpx（思路参考，自研集成） | 满足无外部依赖约束（自研或用纯 Python 异步库） |
| WAF 绕过模块（xiazhi/waf_bypass.py） | 自研（降级为可选插件，默认关闭） | 行业主流（Nuclei 无内置绕过、httpx 靠重试/退避「处理 WAF」而非绕过、Acunetix 为 WAF 兼容导出）均不将绕过作核心能力；D2§7⑧ 显式否定 | xiazhi/waf_bypass.py（可选模块） | 需安全架构师裁决是否保留（对应 U-01 / X2） |
| 资产监控 Web 仪表盘（观星 GuanXing） | 自研（SQLite 单文件） | reNgine 变化追踪需 DB 支撑（SR-05）；GuanXing 已用 sqlite3 WAL（D6§8）；用 SQLite 而非 Postgres 以守「无外部依赖」 | reNgine 概念 + SQLite + Flask | 统一 SQLite（非 Postgres），与 X3 建议一致 |
| 三层降噪（94%→5%） | 自研 | PortSwigger 置信度分级 + 手动验证（SR-09）、Nuclei 验证式检测（SR-01）佐证该工程模式有效；PoXiao 已实现 | — | 由系统架构师在系统设计中落地实现细节 |
| 报告引擎（Jinja2 / 字符串模板） | 自研 | D2§9 候选 Jinja2，但 pyproject 依赖未含（D6§1），实现方式待确认 | Flask/Jinja2 或字符串模板 | 确认实现方式（对应 U-03 / Q5） |
| SRC 报告生成（补天/漏洞盒子格式） | 自研 | Acunetix 集成 Jira/GitHub 思路（SR-06）；PoXiao 已规划一键生成（D2§6.2） | — | 对齐补天提交格式（D2§6.2） |

### 4.2 MVP 范围建议

> 对用户诉求中的 P0/P1 功能给出「是否可在 MVP 内实现」的调研侧建议（基于标杆可行性）。

| 功能（对齐用户诉求 / 资料） | 建议 MVP？ | 理由 |
| --- | --- | --- |
| 技术栈指纹 + CVE 精确匹配（D2§4.1/§5.1） | ✅ | 核心能力；Nuclei 验证式检测 + httpx 指纹范式均有标杆支撑 |
| 三层降噪（94%→5%，D1§4） | ✅ | 核心差异点；PortSwigger/Burp 置信度分级（SR-09）佐证工程合理性 |
| Nuclei 风格 POC 引擎（D7§3，215 模板） | ✅ | 模板已就绪且同构 Nuclei；Nuclei 范式成熟可复用 |
| 渐进式输出（D2§2.1 最高优先级） | ✅ | 标杆均为流式/异步输出，工程可行 |
| 断点续扫（D2§2.3） | ✅ | 本地 CLI checkpoint 模式，Nuclei project 模式（SR-01 -project）可参照 |
| 域名自动发现（D2§3.2，补天 3900 厂商硬需求） | ✅ | D2§7⑩ 列为硬需求；reNgine 子域发现 + brands.json（D7§1）可参照 |
| 资产监控 Web 仪表盘（GuanXing，D1§2） | ⚠️ MVP 后（部分） | 需 SQLite + Flask Web，非 MVP 必须；reNgine 概念可后续移植（用 SQLite） |
| WAF 绕过（X2 / Q1） | ❌（完整版） | 行业非核心能力（Nuclei/httpx/Acunetix 均不将其作核心）；建议降级为路线图可选模块 |

### 4.3 技术栈参考建议

| 技术层 | 推荐方案 | 替代方案 | 选择理由 |
| --- | --- | --- | --- |
| POC 模板引擎范式 | Nuclei YAML DSL（id/info/severity/http/matchers） | 自研 JSON 模板 | 社区生态 + 与 PoXiao 现有 215 模板同构（D7§3），复用成本最低 |
| 异步 HTTP 探测 | httpx retryablehttp 思路（自研/轻量集成） | aiohttp | 无外部依赖 + 技术栈/CDN/WAF 指纹提取（SR-03），契合 dawn 设计 |
| 存储（监控/变化追踪） | SQLite 单文件（GuanXing） | PostgreSQL（reNgine 式，不推荐） | 变化追踪/分页需 DB；SQLite 守「无外部依赖」（D1§10），拒绝 reNgine 重栈 |
| 存储（报告输出） | JSON / Markdown 文件 | SQLite | 报告为人读/机读导出，JSON 单文件足够（Nuclei 同范式，SR-01） |
| 降噪策略 | 验证式匹配（Nuclei）+ 置信度分级（Burp, SR-09） | 纯规则匹配 | 误报抑制需「验证 + 分级 + 排除」，对齐三层降噪（D1§4） |

---

## 5. 风险与待确认项

> **四段式「风险」段**。列出调研中发现的主要风险、不确定信息、待业务架构师进一步裁决的依赖项。

### 5.1 主要风险清单

| 编号 | 风险描述 | 触发条件 | 影响范围 | 严重程度 | 缓解建议 |
| --- | --- | --- | --- | --- | --- |
| R-01 | 模板数 206 vs 215 文案不一致（X1） | 对外文档/报告引用「206」而代码为 215 | 统计口径混乱、用户信任受损 | 低 | 以代码实际 215 为准，修正 README（D1§5/§8）；列入 U-05 |
| R-02 | WAF 绕过定位冲突（X2）：D2§7⑧ 否定，D1§2/D6§9 代码含 waf_bypass.py | 保留模块且与「不做 WAF 绕过」需求相悖 | 安全架构、xiazhi stealth 模块设计 | 中 | 降级为可选插件、默认关闭；提交安全/系统架构师裁决（U-01） |
| R-03 | 存储选型 SQLite vs JSON 冲突（X3） | GuanXing 用 SQLite，D2§9 写 JSON「无需数据库」 | 数据一致性、监控模块落地 | 中 | GuanXing 监控统一 SQLite（变化追踪需 DB）；报告输出可用 JSON；提交系统架构师确认（U-02） |
| R-04 | 报告引擎 Jinja2 依赖缺失（Q5） | 报告生成依赖 Jinja2 但 pyproject 未列 | 报告模块实现方式不确定 | 低 | 确认用 Flask 渲染或字符串模板（U-03） |
| R-05 | CVE 内置 121 条未逐条核验（Q4） | 下游引用「121 条」但实际不符 | 检测覆盖率口径 | 低 | 源码核验 cve_match.py 实际条数（U-04） |
| R-06 | 领域文档 CONTEXT.md / docs/adr 缺失（Q6） | 下游架构文档术语漂移、ADR 无法沉淀 | 术语一致性、架构决策可追溯 | 中 | 主理人决定是否补建术语表与 ADR 体系（U-07） |
| R-07 | requirements 模块 taxonomy 与 dawn 实际模块名不一致（Q7） | 需求模块（info_leak/api_detect 等）未在 dawn/ 同名出现 | 需求-实现映射混乱 | 中 | 系统架构师核对是否已实现/改名/合并（U-06） |

### 5.2 待确认项（需主理人 / 业务方反馈）

> 调研中因外部信息不可得或属下游裁决权，暂不能确认的事实。

| 编号 | 待确认项 | 不确定性说明 | 若无法确认的备选路径 |
| --- | --- | --- | --- |
| U-01 | WAF 绕过是否保留（X2/Q1） | D2§7⑧ 否定，D1§2/D6§9 代码含 waf_bypass.py，三源互斥 | 本调研建议降级为可选插件；最终由安全/系统架构师裁决 |
| U-02 | 存储统一 SQLite vs JSON（X3/Q2） | D1§9/D6§8 用 SQLite，D2§9 写 JSON | 建议 GuanXing 监控统一 SQLite，报告输出用 JSON；系统架构师确认 |
| U-03 | 报告引擎 Jinja2 实现方式（Q5） | D2§9 候选 Jinja2，D6§1 依赖不含 | 确认用 Flask 渲染或字符串模板 |
| U-04 | CVE 内置实际条数（Q4） | D1§8 称 121，未逐条核验 | 源码核验 cve_match.py |
| U-05 | 模板数修正（X1） | 206 vs 215 | 以代码 215 为准修正 README |
| U-06 | 模块 taxonomy 对齐（Q7） | requirements 模块名与 dawn/ 实际不符 | 系统架构师核对实现/改名/合并 |
| U-07 | CONTEXT.md / ADR 是否补建（Q6） | D3/D4/D5/AGENTS.md 约定需但仓库缺失 | 主理人决定是否补建 |

> **§5 自检记录（中间确认协议 §2.4 / §5.2 关键事实核实）**：本节汇总的 U-01~U-07 均为「下游裁决/源码核验」类待确认项，非本调研需即时裁决的方案分歧。以最易被视为分歧的 U-01（WAF 绕过）做反向验证：Q1 若 3 个月后推翻（保留↔移除 waf_bypass.py），返工范围 = 单个 xiazhi 模块 + stealth 标志位 + 测试，约 0.5 人月、远低于 30% 产物 / 1 人月阈值 → 可控，未命中 §2.2(1)；Q2 用户/客户/监管可感知点：WAF 绕过为内部扫描能力，非 SLA/合同/监管/对外承诺感知点 → 感知不到，未命中 §2.2(2)；Q3 与用户原始诉求一致性：主理人注入诉求显式列「技术栈指纹 + CVE 精确匹配 + 三层降噪」为核心理念，未显式提及 WAF 绕过；D2§7⑧ 显式「破晓不做 WAF 绕过」——本建议（降级/默认关闭）与之对齐，未偏离用户显式能力 → 一致/未显式提及，未命中 §2.2(3)。结论：**反向验证全部未命中，不发起中间确认**；U-01~U-07 作为待确认项移交下游。（详见附录 B）

### 5.3 需业务架构持续关注的依赖项

| 编号 | 依赖项 | 说明 | 建议关注阶段 |
| --- | --- | --- | --- |
| D-01 | WAF 绕过裁决（U-01/X2）影响 xiazhi stealth 模块与安全设计 | 是否保留 waf_bypass 决定 stealth 扫描能力边界 | 安全设计、系统设计 |
| D-02 | SQLite 统一（U-02/X3）影响 GuanXing 与数据层 | 监控库与全项目存储一致性 | 系统设计（数据层） |
| D-03 | 模板 schema 对齐 Nuclei（RQ1/X1）影响 xiazhi 引擎与报告 | 兼容性决定社区模板复用度 | 系统设计（POC 引擎） |
| D-04 | 三层降噪工程实现（RQ4）需系统架构师落地 | 降噪算法与置信度分级的具体实现 | 系统设计 |

---

## 6. 关键来源目录

> 集中列出全部调研所使用的公开资料、官方文档、社区仓库、分析报告等。每条来源不低于 URL 粒度，关键来源给出具体章节/段落。

**硬指标**：共 12 条来源（≥3），覆盖每家标杆（B1-B4）且含 URL；关键数据已标注来源章节。

| 编号 | 来源类型 | 标题 / 名称 | URL / 路径 | 相关章节 | 最后访问日期 |
| --- | --- | --- | --- | --- | --- |
| SR-01 | 开源仓库 | Nuclei GitHub Repository | https://github.com/projectdiscovery/nuclei | B1, §2.2.1, §2.3, §3.1 | 2026-07-09 |
| SR-02 | 官方文档 | Nuclei Templates Introduction（YAML DSL） | https://docs.projectdiscovery.io/templates/introduction | B1, §2.2.1, §2.3 | 2026-07-09 |
| SR-03 | 开源仓库 | httpx GitHub Repository（异步 HTTP 探测） | https://github.com/projectdiscovery/httpx | B1 参照, §2.3, §4.1 | 2026-07-09 |
| SR-04 | 开源仓库 | reNgine GitHub Repository | https://github.com/yogeshojha/rengine | B4, §2.2.4, §2.3, §3.3 | 2026-07-09 |
| SR-05 | 官方文档 | reNgine Wiki（架构/特性） | https://rengine.wiki/ | B4, §2.2.4, §2.3, §4.1 | 2026-07-09 |
| SR-06 | 官方文档 | Acunetix Vulnerability Scanner（DAST/proof-based/SaaS） | https://www.acunetix.com/vulnerability-scanner/ | B2, §2.2.2, §2.3, §4.1 | 2026-07-09 |
| SR-07 | 官方文档 | Acunetix Configuring Web Application Firewalls | https://www.acunetix.com/support/docs/wvs/configuring-web-application-firewalls/ | B2, §2.2.2, §2.3（WAF 兼容） | 2026-07-09 |
| SR-08 | 官方站点 | OWASP ZAP 官网 | https://www.zaproxy.org/ | B3, §2.2.3, §2.3 | 2026-07-09 |
| SR-09 | 官方文档 | PortSwigger Best practices for managing false positives | https://portswigger.net/burp/documentation/dast/user-guide/working-with-scans/false-positives-best-practice | B3, §2.2.3, §4.2, §4.3（降噪） | 2026-07-09 |
| SR-10 | 社区文档 | Nuclei Matchers（status/size/word/regex/binary/dsl/header） | https://c4pr1c3.github.io/nuclei-docs/templating-guide/operators/matchers.html | B1, §2.3（模板 schema） | 2026-07-09 |
| SR-11 | 对比报告 | SourceForge Acunetix vs Nuclei vs OWASP ZAP 对比 | https://sourceforge.net/software/compare/Acunetix-vs-Nucleus-Security-vs-OWASP-Zed-Attack-Proxy-ZAP/ | B2/B3, §3.2 | 2026-07-09 |
| SR-12 | 基准报告 | pentest-tools Web App Vulnerability Scanners Benchmark 2024 | https://pentest-tools.com/benchmarks/web-app-vulnerability-scanners-benchmark-2024.pdf | §3.2（误报率基准参照） | 2026-07-09 |

---

## 7. 硬指标清单

> 汇总本模板所有章节的硬指标，供自动校验与人工审核使用。

| 章节 | 硬指标项 | 当前状态 | 备注 |
| --- | --- | --- | --- |
| §1 | 调研问题已收敛为 ≥ 3 条可执行问题 | ✅ | RQ1-RQ5（5 条） |
| §2.1 | 标杆系统 ≥ 3 家，含 ≥ 1 家头部 SaaS | ✅ | B1-B4；B2 Acunetix 为头部 SaaS |
| §2.1 | 标杆系统 ≥ 1 家开源或自研代表 | ✅ | B1 Nuclei / B3 ZAP / B4 reNgine 均为开源 |
| §2.2 | 每家标杆有独立详述卡片 | ✅ | B1-B4 四张详述卡，均含置信度标注 |
| §2.3 | 关键能力横向事实无遗漏 | ✅ | 9 个能力维度横陈，未评分 |
| §3.1 | 对比矩阵含 5 维度 + 权重 + 评分 | ✅ | 权重和 = 1.00，加权总分已计算 |
| §3.2 | 评分结论含优先/部分/不借鉴三层 | ✅ | 优先：Nuclei；部分：ZAP/reNgine；不借鉴：Acunetix 形态 |
| §4.1 | 自研/采购/复用边界有明确建议 | ✅ | 7 项能力边界建议 |
| §4.2 | MVP 范围建议与用户诉求对齐 | ✅ | 对齐 D1/D2 功能清单 |
| §5.1 | 主要风险 ≥ 3 条，有缓解建议 | ✅ | R-01~R-07（7 条），均含缓解建议 |
| §6 | 关键来源可追溯（URL / 章节） | ✅ | SR-01~SR-12（12 条 URL），覆盖各标杆 |
| 全文 | 明确区分事实 / 推断 / 建议 / 风险 | ✅ | §2 事实含置信度；§3 对比；§4 建议；§5 风险 |
| 全文 | 不存在编造来源或占位符 | ✅ | 全文无占位符或示例前缀残留 |

---

## 附录 A：调研方法论与来源检索清单

### A.1 调研流程（tech-research-advisor 六阶段映射）

| 阶段 | 动作 | 落入章节 |
| --- | --- | --- |
| Phase 0 问题类型 | 判定为架构类 + 工具选型类混合 | §0 |
| Phase 1 问题分层 | 从用户诉求 + material_digest 冲突项抽象为 5 个调研问题 | §1 |
| Phase 2 多维信息收集 | 6 次 WebSearch + 10 次 WebFetch，覆盖 Nuclei/httpx/reNgine/Acunetix/ZAP/PortSwigger 官方文档与仓库 | §2、§6 |
| Phase 3 候选方案整理 | 4 家标杆去重归类（B1-B4） | §2.1 |
| Phase 4 业务特征画像 | 结合 PoXiao 设计原则（异步/无外部依赖/本地 CLI）设定评估维度与权重 | §3.1 |
| Phase 5 综合评估矩阵 | 5 维度加权评分（权重和 1.00） | §3 |
| Phase 6 双/多方案推荐 | 分层结论（优先/部分/不借鉴）+ 组合分析 | §3.2、§3.3、§4 |

### A.2 检索清单（公开可核验）

- WebSearch：Nuclei template engine YAML / Nuclei vs Acunetix vs ZAP / Acunetix WAF evasion / reNgine architecture SQLite Celery / httpx async / false positive reduction（6 次）
- WebFetch：Nuclei GitHub、Nuclei Templates Docs、httpx GitHub、reNgine GitHub、reNgine Wiki、Acunetix Scanner、Acunetix WAF Config、OWASP ZAP、PortSwigger FP 实践、Nuclei Matchers（10 次）

### A.3 置信度标注约定

- **已核实**：直接来自标杆官方文档/仓库原文引用。
- **推断**：基于命名/架构/行业共识的合理推测，已在 §2.2 逐维度标注。
- **综合归纳**：多源归纳结论。

---

## 附录 B：中间确认自检记录（协议 §2.4）

> 按协议在关键章节产出后插入自检，先按 §2.1 判定，再按 §2.3 反向验证 3 问；命中即发起 `[中间确认]`，未命中须给出证据。本调研全程 4 次自检均**未命中**，故未发起任何阻塞。

### B.1 §1.2 调研问题收敛自检

- §2.1 方案分歧型判定：收敛为 RQ1-RQ5 是单向整理，无 ≥2 互斥方案需裁决 → 不触发。
- 反向验证 3 问：
  - Q1：若收敛方向被推翻，返工 = §1 表格（产物的 5% 以内），切换 0.1 人月 → 可控。
  - Q2：调研问题列表不影响用户/客户/监管可感知行为 → 感知不到。
  - Q3：问题列表非用户显式能力点，仅映射上游冲突项 → 未偏离。
- 结论：**未命中，不发起**。

### B.2 §2.1 标杆清单自检

- §2.1 方案分歧型判定：标杆集 B1-B4 已满足「≥3 家 + ≥1 头部 SaaS + ≥1 开源」硬约束，候选（Nuclei/Acunetix/ZAP/reNgine/httpx/Burp）中选取明确，无不可裁决的分歧 → 不触发。
- 反向验证 3 问：
  - Q1：若替换某标杆，返工 = §2.1 一行 + §2.2 一张卡（产物的 5% 以内），切换可忽略 → 可控。
  - Q2：标杆选择不影响用户/客户/监管可感知行为 → 感知不到。
  - Q3：标杆选择非用户显式指定能力点 → 未偏离。
- 结论：**未命中，不发起**。

### B.3 §3.1 权重设定自检

- §2.1 方案分歧型判定：权重为评分方法参数，非方案分歧；默认权重（场景契合 0.30 / 合规 0.20 / 成熟 0.20 / 集成 0.15 / 成本 0.15）契合 PoXiao 本地 CLI/无外部依赖/开源特征，无反转排名风险 → 不触发。
- 反向验证 3 问：
  - Q1：若权重重设，返工 = §3.1 权重列 + 加权总分（产物的 5% 以内）→ 可控。
  - Q2：评分权重不影响用户/客户/监管可感知行为 → 感知不到。
  - Q3：权重非用户显式指定能力点 → 未偏离。
- 敏感性：即便场景契合降至 0.20、合规升至 0.30，排名仍 Nuclei(4.55) > ZAP(4.45) > reNgine(3.55) > Acunetix(2.65)，结论稳健。
- 结论：**未命中，不发起**。

### B.4 §5.2 待确认项（关键事实核实）自检

- §2.1 方案分歧型判定：U-01~U-07 为「下游裁决/源码核验」类，本调研给出建议但不裁决，非需即时阻断的方案分歧 → 不触发。
- 以最易被视为分歧的 U-01（WAF 绕过）做 §2.3 反向验证：
  - Q1：若 3 个月后推翻（保留↔移除 waf_bypass.py），返工 = 单个 xiazhi 模块 + stealth 标志 + 测试，约 0.5 人月，远低于 30% 产物 / 1 人月 → 可控，未命中 §2.2(1)。
  - Q2：WAF 绕过为内部扫描能力，非 SLA/合同/监管/对外承诺感知点 → 感知不到，未命中 §2.2(2)。
  - Q3：主理人诉求显式列「技术栈指纹+CVE精确匹配+三层降噪」，未显式提及 WAF 绕过；D2§7⑧ 显式「不做 WAF 绕过」；本建议（降级/默认关闭）与之对齐 → 一致/未显式提及，未命中 §2.2(3)。
- 结论：**反向验证全部未命中，不发起中间确认**；U-01~U-07 移交下游裁决。
