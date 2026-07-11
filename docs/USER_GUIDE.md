# 破晓 用户手册（USER GUIDE）

> 面向安全工程师 / 红队。安装、快速上手、常用模块说明。
> 架构决策基线见 `CONTEXT.md`；开发者向见 `docs/DEVELOPER.md`。

## 1. 安装

### 方式 A：源码运行（推荐，模板最齐）
```bash
git clone <repo> && cd poxiao
python -m pip install -e .        # 注册 poxiao 命令
python -m pytest                  # 可选：自检
```

### 方式 B：wheel 安装（Phase 4 起）
```bash
python -m pip install build wheel
python -m build --wheel           # 产物在 dist/
python -m pip install dist/*.whl
poxiao --help
```
> 注意：wheel **不打包 `templates/`**。运行时模板需从源码目录提供，或用 `--templates-dir <path>` 指定（观星/惊蛰等模板驱动模块依赖它）。

### 运行要求
- Python >= 3.10
- 外部运行时依赖最小化（httpx / beautifulsoup4 / lxml / pyyaml / flask / dnspython / python-whois），守 MVP 边界。

## 2. 快速上手

```bash
# 主入口（唯一注册命令）
poxiao --help

# 被动侦察（FOFA 等），密钥隔离在环境变量，不入库
export FOFA_EMAIL=you@example.com
export FOFA_KEY=xxxxxxxx
poxiao recon --target example.com

# 漏洞扫描（惊蛰）
poxiao scan --target example.com --templates-dir templates

# WAF 绕过（显式开关，默认关 —— 修正 X2）
poxiao poc scan --waf-bypass

# HTML 报告（纯 stdlib 生成，动态文本转义守 Q5）
poxiao report --format html --out report.html
```

## 3. 模块速览
| 模块 | 作用 | 关键开关 |
| --- | --- | --- |
| Dawn（dawn） | CVE 指纹匹配 | 内置 `BUILTIN_VULNS`（唯一性门禁） |
| FrostMoon | 指纹/暴露面 | — |
| VernalEquinox | 被动侦察源（FOFA 等） | `FOFA_EMAIL`/`FOFA_KEY` 密钥隔离、限流、单源降级 |
| JingZhe（惊蛰） | 漏洞验证/POC | 默认凭据/Git/Swagger/Actuator 模板；平台格式 butian/vulbox/cnvd |
| GuanXing（观星） | 告警/导出 | 本地 webhook + JSONL 日志 + CSV/JSON 导出（**无邮件/服务端**） |
| XiaZhi（夏至） | 补充能力 | — |

## 4. 观星告警与导出
- 告警**仅本地**：webhook 接收 + 落 `scan_results/` JSONL 日志。
- 导出：`python -m guanxing.export --format csv|json`，产出批量报告文件。
- 设计约束（D9 / R4）：不引入 SMTP 配置面与邮件依赖，避免供应链与配置风险。

## 5. 数据治理与红线
- CVE / 模板 **唯一性、撞号、字段完整性** 是硬约束（`tools/ci_audit.py`）。
- 红线（`src/utils/redline.py`）：公网目标、敏感操作有确认/告警；`verify_ssl` 默认 false，但公网目标启动告警。
- 数量（如 257 CVE / 224 模板）**仅作指标**，不硬编码为通过条件（守 X1）。

## 6. 故障排查
- `poxiao --help` 看子命令；各子命令 `--help` 看参数。
- 模板校验：`python tools/template_sync.py validate templates`。
- 数据治理：`python tools/ci_audit.py`。
