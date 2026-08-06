# 破晓 开发者指南（DEVELOPER GUIDE）

> 面向贡献者。仓库结构、CI 三件套、模板贡献、类型化策略。
> ADR 基线见 `docs/DEVELOPER.md`；用户向见 `docs/USER_GUIDE.md`。

## 1. 仓库结构
```
poxiao/
├── src/                 # 主包（cli / dawn / frostmoon / vernalequinox / jingzhe / guanxing / xiazhi / utils / commands / monitor / target）
│   ├── cli.py           # 唯一 main() 入口（poxiao 命令）
│   └── __main__.py      # 支持 python -m src
├── templates/           # Nuclei 模板（exposures/misconfig/vulnerabilities/cves/default-logins）
├── tools/               # 工程工具（非运行时）
│   ├── ci_audit.py      # 数据治理硬门禁（CVE 唯一性 / 模板治理）
│   ├── type_check.py    # 渐进 mypy 门禁（单一事实来源）
│   ├── gen_sbom.py      # CycloneDX SBOM 生成
│   ├── template_sync.py # 模板 validate + diff（计数作指标）
│   └── bench.py         # asyncio 性能压测基准
├── tests/               # pytest（conftest 把仓库根加入 sys.path）
├── docs/                # USER_GUIDE / DEVELOPER / agents/
├── .github/
│   ├── workflows/ci.yml # 主 CI（ci_audit + pytest + type_check + build）
│   ├── workflows/pr_check.yml  # PR 模板贡献校验
│   └── PULL_REQUEST_TEMPLATE.md
└── pyproject.toml       # 打包元数据（build-system + scripts 仅 poxiao）
```

## 2. CI 三件套（提交前本地跑一遍）
```bash
python tools/ci_audit.py     # 硬门禁：撞号/字段缺失/YAML 损坏才失败
python -m pytest             # 测试（--no-cov 可跳过覆盖率报告）
python tools/type_check.py   # 渐进 mypy 门禁（9 模块零错误）
python -m build --wheel      # 可复现构建（P4-1）
```

## 3. 类型化渐进策略（R2）
- 全仓 `mypy --strict` 零错误成本高，**不承诺**。
- `tools/type_check.py` 维护**受控模块白名单**（单一事实来源），CI 与本地共用。
- 新增标注模块需先自身零错误，再列入白名单；禁止引入 `--strict` 全仓。
- `pyproject.toml` 的 `[tool.mypy]`：`ignore_missing_imports=true`，非 strict。

## 4. 新增 / 修改模板（对接 D1 / X1）
1. 在 `templates/<类别>/` 下新增 `.yaml`。
2. 必填：`id` / `info` / `info.name` / `info.severity` / `http` 或 `requests`。
3. `id` 全局唯一（撞号 CI 驳回）。
4. 本地校验：`python tools/template_sync.py validate templates/<file>`。
5. **不**在代码/PR 硬编码模板数量（215/224）为通过条件，计数仅指标。
6. 提交遵循 `.github/PULL_REQUEST_TEMPLATE.md`。

## 5. 供应链与 SBOM（D12 / A08）
- `python tools/gen_sbom.py --out sbom.json` 生成 CycloneDX 1.5 SBOM（含 purl，可选 SHA-256）。
- 依赖锁定用 `pyproject.toml` dependencies；内网镜像按需配置 pip。

## 6. 性能压测（D11）
- `python tools/bench.py --targets 100 --concurrency 20 --task-ms 20` 合成 asyncio 基准（不触网）。
- 指标：吞吐 / 时延 P50~P99 / 错误率；错误率超阈值判"超时雪崩"（exit 2，仅提示不阻断）。

## 7. 红线与数据治理
- `src/utils/redline.py`：公网目标/敏感操作告警与确认；`verify_ssl` 默认 false + 公网告警。
- `tools/ci_audit.py`：CVE/模板唯一性、撞号、字段完整性硬失败。
- 改动 `src/dawn/cve_match.py` 的 `BUILTIN_VULNS` 须保证 id 唯一。

## 8. i18n 方向（D13，可选 /  deferred）
- 当前全中文；后续可抽取文案层（`src/i18n/messages.py` + gettext），优先验证英文报告与社区英文 Nuclei 模板兼容。
- HTML 报告已用 `html.escape`（守 Q5），天然兼容 UTF-8，i18n 风险低。

## 9. 提交约定
- 运行产物 `.coverage`、根目录临时文件 `_*.txt` 已被 `.gitignore` 忽略。
- 提交信息聚焦"做了什么 + 守什么约束"，关联 Phase 任务（P4-x）。
