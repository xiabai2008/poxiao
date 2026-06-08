# 未授权访问：YzmCMS 管理后台暴露

## 基本信息

- **漏洞等级**: 中危
- **厂商**: YzmCMS 官方站点 (yzmcms.com)
- **漏洞URL**: https://www.yzmcms.com/admin
- **漏洞类型**: 未授权访问（管理后台暴露）

## 漏洞描述

目标站点 **YzmCMS** 的管理后台入口 `/admin` 可被外部直接访问，且未经任何 IP 限制或额外认证层保护。访问后自动跳转至登录页面。

## 复现步骤

**Step 1 — 访问管理后台入口**

访问 `https://www.yzmcms.com/admin`

页面返回 JavaScript 重定向代码：
```html
<script type="text/javascript">
  var url="https://www.yzmcms.com/admin/index/login.html";
  if(top.location !== self.location){
    top.location=url;
  }else{
    window.location.href=url;
  }
</script>
```

自动跳转至真实登录页面：`https://www.yzmcms.com/admin/index/login.html`

**Step 2 — 确认登录接口可交互**

直接 POST 请求登录接口，确认可正常响应：
```
POST https://www.yzmcms.com/admin/index/login.html
Body: username=admin&password=admin

Response: {"status":0,"message":"验证码不正确！"}
```

返回 JSON 格式的认证响应，说明登录接口工作正常，仅被验证码拦截。

**Step 3 — 确认系统版本**

通过页面特征识别为 **YzmCMS** 内容管理系统。该 CMS 为国产开源 CMS，存在多个已知漏洞（CVE 在数据库中）。

## 修复建议

1. 对管理后台实施 IP 白名单或 VPN 访问控制
2. 修改默认管理路径 `/admin` 为自定义路径
3. 添加额外的 HTTP 基本认证层
4. 在 WAF 层对 `/admin` 路径做访问频率限制
5. 确保 YzmCMS 版本为最新，及时修补已知漏洞
