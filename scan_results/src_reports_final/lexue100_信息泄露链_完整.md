# 信息泄露链：.gitignore + robots.txt 双重泄露 → 完整站点架构暴露

## 基本信息

- **漏洞等级**: 中危
- **厂商**: 乐学一百 (lexue100.com)
- **漏洞类型**: 敏感信息泄露（Git 信息泄露 + robots.txt 泄露 + 内部路径暴露链）
- **技术栈**: PHP/7.4.32 + Tengine + Discuz!/UCenter 框架

## 漏洞描述

目标站点存在 **两处信息泄露**，分别暴露了不同层面的内部结构信息，且互相交叉印证，形成了一条完整的站点架构泄露链。

**泄露源 ① — .gitignore 文件**

`https://www.lexue100.com/.gitignore` 可被外部直接访问，返回完整的项目忽略规则，暴露了以下内部路径：

| 路径 | 说明 |
|------|------|
| `/.idea/` | JetBrains IDE 项目配置目录 |
| `/.vscode` | VS Code 项目配置目录 |
| `/.git/` | Git 版本控制目录 |
| `/.svn/` | SVN 版本控制目录 |
| `/data/` | 数据存储目录 |
| `/engine/` | 引擎/核心代码目录 |
| `/data_local/` | 本地数据目录 |
| `/down_files/` | 文件下载目录 |
| `/uploads/` | 文件上传目录 |
| `/workfile/` | 工作文件目录 |
| `/config.php` | **配置文件**（关键） |
| `/test_*.php` | **测试文件**（关键） |

**泄露源 ② — robots.txt 文件**

`https://www.lexue100.com/robots.txt` 进一步暴露了更多隐藏路径：

```
Disallow: /data/
Disallow: /source/       ← Discuz! 源码目录
Disallow: /template/     ← Discuz! 模板目录
Disallow: /uploads/
Disallow: /workfile/
Disallow: /language/
Disallow: /down_files/
Disallow: /uc_client/    ← 🔥 Discuz! UCenter 客户端（确认框架）
Disallow: /api/          ← API 接口
Disallow: /camera/       ← 拍照功能目录
```

## 复现步骤

**Step 1 — 获取 .gitignore**

访问：`https://www.lexue100.com/.gitignore`

返回内容：
```
/.idea/
.DS_Store
/.git/
/.svn/
/data/
/engine/
/data_local/
/down_files/
/uploads/
/workfile/
/config.php
/test_*.php
/phpinfo.php
/.vscode
```

截图 1：浏览器访问 .gitignore 完整页面

**Step 2 — 获取 robots.txt**

访问：`https://www.lexue100.com/robots.txt`

返回内容：
```
user-agent: *
Disallow: /data/
Disallow: /source/
Disallow: /template/
Disallow: /uploads/
Disallow: /workfile/
Disallow: /language/
Disallow: /down_files/
Disallow: /uc_client/
Disallow: /api/
Disallow: /camera/
```

截图 2：浏览器访问 robots.txt 完整页面

**Step 3 — 交叉验证路径真实性**

根据两处泄露，逐一探测内部路径：

| 路径 | HTTP状态 | 来源 | 说明 |
|------|----------|------|------|
| `/config.php` | **200** | .gitignore | ✅ 配置文件存在且可访问 |
| `/test.php` | **200** | .gitignore | ✅ 测试文件存在且可访问 |
| `/admin.php` | **200** | — | ✅ 管理后台入口存在 |
| `/camera/` | **200** | robots.txt | ✅ 拍照目录存在 |
| `/data/` | 403 | 两者 | ⚠️ 数据目录存在，被访问控制 |
| `/engine/` | 403 | .gitignore | ⚠️ 引擎目录存在 |
| `/source/` | 403 | robots.txt | ⚠️ Discuz! 源码目录存在 |
| `/template/` | 403 | robots.txt | ⚠️ Discuz! 模板目录存在 |
| `/uc_client/` | 403 | robots.txt | 🔥 Discuz! UCenter 客户端确认 |
| `/api/uc.php` | 502 | — | 🔥 UCenter API 接口存在 |
| `/uploads/` | 403 | 两者 | ⚠️ 上传目录存在 |

截图 3：各路径 HTTP 状态码截图

**Step 4 — 框架识别**

通过以下证据链确认使用 **Discuz!** 框架：

1. robots.txt 中的 `/uc_client/` 路径（Discuz! UCenter 标准路径）
2. `/api/uc.php` 接口存在（UCenter API 标准接口）
3. `/source/` 和 `/template/` 目录（Discuz! 标准目录结构）
4. `X-Powered-By: PHP/7.4.32`（PHP 版本可被外部获取）

**Step 5 — 漏洞链总结**

通过 .gitignore 和 robots.txt 的交叉分析，攻击者可以获知：

- ✅ 站点技术栈：PHP 7.4.32 + Tengine + Discuz!/UCenter
- ✅ 全部内部目录结构（15+ 个路径）
- ✅ 配置文件位置（/config.php）
- ✅ 管理后台入口（/admin.php）
- ✅ UCenter API 位置（/api/uc.php）
- ✅ 上传目录位置（/uploads/）
- ✅ 开发工具链（JetBrains IDE / VS Code / Git / SVN）
- ✅ 存在测试文件（/test.php 可访问）

以上信息为后续攻击提供了完整的站点架构图，大大降低了攻击者的侦查成本。

## 修复建议

1. **立即禁止 .gitignore 访问**：在 Tengine/Nginx 配置中添加规则拦截所有 `.git` 相关文件
2. **修改 robots.txt**：移除 /uc_client/、/api/ 等敏感路径，仅保留必要的 SEO 规则
3. **删除测试文件**：移除服务器上的 test.php、test_*.php
4. **配置文件保护**：将 config.php 移至 Web 根目录之外，返回 404 而非空响应
5. **部署流程改进**：使用 `git archive` 部署代替 `git clone`，避免 `.git` 目录泄露风险
6. **版本号隐藏**：在 PHP 配置中设置 `expose_php = Off`

### Nginx/Tengine 配置

```nginx
# 禁止版本控制文件
location ~ /\.(git|svn|idea|vscode) {
    deny all;
    return 404;
}

# 隐藏 PHP 版本
fastcgi_hide_header X-Powered-By;
```

### PHP 配置

```ini
expose_php = Off
```
