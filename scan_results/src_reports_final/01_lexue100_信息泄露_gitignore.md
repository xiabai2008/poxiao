# 信息泄露：.gitignore 泄露敏感路径 → 验证多个内部文件可访问

## 基本信息

- **漏洞等级**: 中危
- **厂商**: 乐学一百 (lexue100.com)
- **漏洞URL**: https://www.lexue100.com/.gitignore
- **漏洞类型**: 敏感信息泄露（Git 信息泄露 + 内部路径暴露）

## 漏洞描述

目标站点 **乐学一百** 的 `.gitignore` 文件可被外部直接访问，泄露了以下内部路径和文件信息：

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

经进一步验证，其中 **多个路径确实存在并可被外部探测**，形成了一条完整的信息泄露链。

## 复现步骤

**Step 1 — 获取 .gitignore 文件**

访问 `https://www.lexue100.com/.gitignore`，返回完整的 .gitignore 内容：

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

截图：浏览器访问 .gitignore 的完整页面

**Step 2 — 验证泄露路径是否真实存在**

根据 .gitignore 中泄露的路径，逐一验证：

| 路径 | HTTP状态 | 说明 |
|------|----------|------|
| `/config.php` | 200 | ✅ 配置文件存在，可被访问 |
| `/test.php` | 200 | ✅ 测试文件存在，可被访问 |
| `/data/` | 403 | ⚠️ 数据目录存在，被保护 |
| `/engine/` | 403 | ⚠️ 引擎目录存在，被保护 |
| `/uploads/` | 403 | ⚠️ 上传目录存在，被保护 |

截图：每个路径的 HTTP 响应状态

**Step 3 — 总结**

通过 .gitignore 文件，攻击者可以：
1. 获知站点使用的技术栈（基于目录结构推测为自定义 PHP CMS）
2. 锁定配置文件位置（/config.php）
3. 发现上传目录（/uploads/）
4. 了解开发工具链（.idea/、.vscode）

## 修复建议

1. 在 Web 服务器（Tengine）配置中禁止访问 `.gitignore` 及所有 `.git` 目录下的文件
2. 将所有配置文件（config.php）移至 Web 根目录之外
3. 删除服务器上的测试文件（test.php）
4. 部署时使用 `git archive` 或 `rsync --exclude=.git` 而非 `git clone`
5. 将 `.gitignore` 中的敏感路径做混淆或移除

### Nginx/Tengine 配置示例

```nginx
location ~ /\.git {
    deny all;
    return 404;
}
location ~ /\.gitignore {
    deny all;
    return 404;
}
```
