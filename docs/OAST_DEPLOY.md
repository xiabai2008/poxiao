# OAST 公网部署指南（带外回调）

破晓的 OAST（Out-of-Band Application Security Testing）用于验证**盲注、XXE、SSRF、RCE 回连**
等无法从响应直接判断的漏洞：POC 模板经 `{{oast-url}}`/`{{oast-domain}}` 生成随机子域，
目标若访问该域名，回调被记录，`--oast-check` 确认命中即证明漏洞存在。

**关键点**：回调服务器必须**公网可达**（目标服务器需能访问它）。以下为常见部署方案。

---

## 架构

```
┌─────────────┐    {{oast-url}} 生成随机子域    ┌──────────────────┐
│  扫描机      │ ──────────────────────────────▶ │  OAST 服务器（公网）│
│  poxiao poc │     目标回连（HTTP/DNS）         │  poxiao oast serve │
└─────────────┘ ◀────────────────────────────── └──────────────────┘
       │ 查询命中（poxiao oast query / --oast-check）
```

配置：扫描机与 OAST 服务器均设 `POXIAO_OAST_BASE=http://<公网域名>`。

---

## 方案一：云服务器直连（推荐，10 分钟）

1. **准备公网域名**（如 `oast.example.com`），解析到云服务器 IP
2. **云服务器启动回调服务器**（默认监听 0.0.0.0:8899）：

   ```bash
   # 源码安装后
   POXIAO_OAST_BASE=http://oast.example.com poxiao oast serve --port 8899
   # 或单文件二进制
   ./poxiao oast serve --port 8899
   ```

3. **安全组放行 8899 端口**（仅对扫描目标可达即可，建议限定来源 IP）
4. **扫描机设置同一域名并扫描**：

   ```bash
   export POXIAO_OAST_BASE=http://oast.example.com
   poxiao poc scan https://target -t templates/ --oast --oast-check
   ```

5. 命中判定：`poxiao oast query --domain <子域>`（服务器上）或扫描机 `--oast-check` 自动确认

> 回调日志在服务器 `scan_results/oast_calls.log`（JSONL），可配置 `POXIAO_OAST_LOG`。

---

## 方案二：内网穿透（frp，家庭/办公网络）

无公网 IP 时用 frp 把本机 8899 端口暴露到公网 VPS：

```ini
# frps.toml（VPS 端）
bindPort = 7000
```

```ini
# frpc.toml（本机端）
serverAddr = "vps.example.com"
serverPort = 7000

[[proxies]]
name = "oast"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8899
remotePort = 8899
```

启动：
```bash
# VPS
./frps -c frps.toml
# 本机
./frpc -c frpc.toml
POXIAO_OAST_BASE=http://oast.example.com poxiao oast serve --port 8899
```

域名 `oast.example.com` 解析到 VPS IP 即可。ngrok / cloudflared 同理（临时场景推荐 ngrok）。

---

## 方案三：内网测试（无外网目标）

仅测试内网目标时，回调服务器可直接跑在扫描机或内网任意主机：

```bash
POXIAO_OAST_BASE=http://192.168.1.50:8899 poxiao oast serve --port 8899
# 同一台或同网段机器扫描
poxiao poc scan http://10.0.0.8 -t templates/ --oast --oast-check
```

> 内网场景注意：目标与回调服务器必须互通；`POXIAO_OAST_BASE` 用目标可达的地址。

---

## 验证部署

```bash
# 1. 服务器：启动并确认监听
poxiao oast serve --port 8899

# 2. 任意机器模拟回连（确认公网可达）
curl "http://oast.example.com/<随机串>/probe"

# 3. 服务器查询命中
poxiao oast query --domain "<随机串>"
# 应显示: OAST 回调记录 (1)  GET /<随机串>/probe
```

---

## 安全注意事项

| 事项 | 说明 |
|------|------|
| 端口暴露 | 回调服务器无鉴权（有意的：任何能访问该域名的请求都会被记录），**公网部署务必用不常用端口 + 安全组限定来源** |
| 数据留存 | 回调记录含来源 IP/请求体（前 4KB），按需配置 `POXIAO_OAST_LOG` 保留策略 |
| 域名防护 | 子域随机化（8 位随机标签）防扫描器探测污染；勿用真实业务域名做 OAST 基址 |
| 隐私 | 生产环境定期 `poxiao oast flush` 清理记录 |
