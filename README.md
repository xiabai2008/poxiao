# 破晓 (PoXiao)

**二十四节气安全工具链** — SRC 挖洞全流程自动化

> 信息收集 → 漏洞验证 → 资产监控，一条命令贯穿到底

---

## 核心理念

市面扫描器的三个痛点：
1. **假阳性爆炸** — CDN/WAF 把 404 都返回 200，不做降噪白扫
2. **工具割裂** — 子域名、扫描、验证、报告要切四五个工具
3. **结果不可操作** — "发现 XSS" 但不告诉你具体 payload

破晓解法：**一套工具链 + 三层降噪 + 即扫即用**

---

## 工具链

```
poxiao discover   🏢 公司名 → 域名
poxiao subdomain  🥇霜月 子域名收集（crt.sh + DNS爆破 + 泛解析检测）
poxiao scan       🔍 主机扫描（技术栈 + 敏感路径 + CVE匹配）
poxiao verify     🥈惊蛰 漏洞自动验证（10模块 + 评分 + 降噪）
poxiao monitor    🥉观星 Web 资产监控面板（扫描自动入库）
poxiao report     📋 SRC 补天格式报告
```

---

## 三层降噪（惊蛰核心）

```
层1: 内容特征 — 配置文件返回了 HTML → 假阳性
层2: 尺寸聚类 — 3+ 路径同尺寸（±8%容差）→ CDN catch-all
层3: 校准匹配 — 随机探测路径匹配 → 统一错误页

效果: renrenche.com 20假阳性 → 0（假阳率从94% → ~5%）
```

---

## 实测数据

```
110+ 厂商扫描
7.6 秒 / 30 目标
58.com → 89 子域名（54 存活）
补天已提交 1 份报告
数据库: 86 目标持续监控
```

---

## 快速开始

```bash
# 安装
pip install httpx dnspython flask

# 子域名收集
python -m src.cli subdomain example.com

# 批量扫描
python -m src.cli scan data/targets.txt -c 10

# 漏洞验证
python -m src.cli verify https://target.com

# 启动监控面板
python -m src.cli monitor import scan_results/summary_*.json
python -m src.cli monitor serve
# → http://localhost:5099
```

---

## 项目结构

```
src/
├── cli.py              # 统一命令行入口
├── scanner/            # 扫描引擎
│   ├── engine.py       # HTTP 扫描 + 技术栈识别
│   └── sensitive.py    # 敏感路径发现 + CDN 降噪
├── collector/          # 🥇 霜月
│   └── shuangyue.py    # 子域名收集器
├── verifier/           # 🥈 惊蛰
│   └── jingzhe.py      # 漏洞验证引擎
├── monitor/            # 🥉 观星
│   ├── db.py           # SQLite 数据库
│   └── web.py          # Flask Web 面板
├── target/             # 目标管理
├── reporter/           # 报告生成
└── cve/                # CVE 漏洞库
```

---

## 技术栈

| 组件 | 技术 |
|------|------|
| HTTP | httpx（异步） |
| DNS | dnspython |
| 证书透明 | crt.sh / certspotter / AlienVault OTX |
| 数据库 | SQLite |
| Web | Flask + Bootstrap 5（内联模板，零文件部署） |
| 语言 | Python 3.10+ |

---

## 设计原则

- **异步优先** — 所有网络 I/O 用 asyncio，30 目标 7 秒
- **无外部依赖** — 不用 Docker、不用 Redis、SQLite 单文件
- **渐进输出** — 扫完一个出结果，不等全部
- **即可用** — CLI 单命令，Web 单文件启动

---

*"破晓是凌晨的第一道光，"*  
*"霜月是十一月的清冷，"*  
*"惊蛰是万物复苏，"*  
*"观星是仰望天空。"*
