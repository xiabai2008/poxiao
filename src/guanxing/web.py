"""观星 — 资产监控 Web 界面"""

import functools
import os
from flask import Flask, request, Response, redirect, url_for, make_response
import werkzeug
from markupsafe import escape
from pathlib import Path

from .db import (
    get_targets, get_target_by_id, get_scans, get_changes,
    get_stats, import_from_summary, export_data,
)
from . import auth
from src.utils.audit import audit

app = Flask(__name__)


# ── 认证与访问控制（安全设计 §2.1 / §4.1）──────────────

# 两套认证路径，向后兼容：
#   A) 表单 session 认证：启用时（设置了 auth 凭据）走 /login + session token
#   B) 遗留 Basic Auth：保留 POXIAO_MONITOR_USER/PASS 环境变量行为
# 优先级 A > B；均未配置则不启用认证（默认，兼容现状，仅限本机回环 §5.2）。

_SESSION_COOKIE = auth._SESSION_COOKIE
_USER_COOKIE = auth._USER_COOKIE


def _form_auth_enabled() -> bool:
    """表单认证是否启用：环境变量允许时且 user/pass 均已设置。"""
    user, pw = auth.get_credentials()
    return bool(user and pw)


def _current_user() -> str | None:
    """基于会话 cookie 取当前登录用户。"""
    token = request.cookies.get(_SESSION_COOKIE)
    return auth.verify_session_token(token)


def _check_auth(username: str | None, password: str | None) -> bool:
    """校验用户名密码（Basic Auth 遗留路径 + 表单路径共用）"""
    user, stored = auth.get_credentials()
    if not user:
        return False
    if username != user:
        return False
    # 支持 bcrypt 哈希与明文（明文兼容旧环境变量）
    if stored and auth.verify_password(password or "", stored):
        return True
    return hmac_compare(password or "", stored or "")


def hmac_compare(a: str, b: str) -> bool:
    """恒定时间比较（防时序攻击），兼容明文凭据对比。"""
    import hmac as _hmac
    if a is None or b is None:
        return False
    return _hmac.compare_digest(a, b)


def _require_auth() -> "werkzeug.Response | None":
    """认证中间件：返回 401/重定向响应 或 None（通过）。

    顺序：
      1. 若表单认证启用 -> 校验会话；未登录则重定向 /login。
      2. 否则若 Legacy Basic Auth 启用 -> 校验 Authorization 头。
    """
    if _form_auth_enabled():
        if _current_user():
            return None
        # API 请求返回 401，页面请求重定向登录页
        if request.path.startswith("/api/"):
            return Response("Unauthorized", 401)
        return redirect(url_for("login"))
    # 兼容 Basic Auth
    if not (os.environ.get("POXIAO_MONITOR_USER") and os.environ.get("POXIAO_MONITOR_PASS")):
        return None
    authz = request.authorization
    if not authz or not _check_auth(authz.username, authz.password):
        return Response(
            "Unauthorized — set POXIAO_MONITOR_USER / POXIAO_MONITOR_PASS",
            401,
            {"WWW-Authenticate": 'Basic realm="GuanXing"'},
        )
    return None


def requires_auth(f):
    """认证装饰器（表单 session 优先，回退 Basic Auth）"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        """权限装饰器包装函数"""
        resp = _require_auth()
        if resp is not None:
            return resp
        return f(*args, **kwargs)
    return decorated


def csrf_protect(f):
    """CSRF 保护装饰器：仅对启用表单认证时的写请求生效（§4.1 CSRF）。"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        """CSRF 校验包装：表单认证启用时对写请求校验令牌"""
        if request.method in ("POST",) and _form_auth_enabled():
            user = _current_user()
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not user or not auth.verify_csrf_token(token, user):
                return Response("CSRF verification failed", 400)
        return f(*args, **kwargs)
    return decorated


def _esc(val, max_len=0):
    """安全转义 HTML (防 XSS)"""
    s = escape(str(val) if val is not None else "")
    if max_len > 0 and len(s) > max_len:
        return s[:max_len] + "..."
    return s

# ── 内联模板（单文件部署，无需额外模板目录）──

_LAYOUT_HEAD = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.bootcdn.net/ajax/libs/bootstrap-icons/1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body {{ background: #f5f7fa; font-size: 14px; }}
        .card {{ border: none; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 16px; }}
        .stat-card {{ text-align: center; padding: 20px; }}
        .stat-value {{ font-size: 2rem; font-weight: 700; }}
        .stat-label {{ color: #6c757d; font-size: 13px; }}
        .navbar {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); }}
        .navbar-brand {{ font-weight: 700; letter-spacing: 1px; }}
        .badge-critical {{ background: #dc3545; }}
        .badge-high {{ background: #fd7e14; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #0dcaf0; }}
        .tech-tag {{ display: inline-block; padding: 2px 8px; margin: 2px;
                    background: #e9ecef; border-radius: 12px; font-size: 12px; }}
        .change-new {{ background: #d1e7dd; }}
        .change-old {{ background: #f8d7da; text-decoration: line-through; }}
        pre.log {{ background: #1a1a2e; color: #00ff88; padding: 12px; border-radius: 8px;
                  font-size: 13px; max-height: 300px; overflow-y: auto; }}
    </style>
</head>
<body>
<nav class="navbar navbar-dark">
    <div class="container">
        <a class="navbar-brand" href="/">🔭 观星 · 资产监控</a>
        <div class="d-flex">
            <a href="/" class="btn btn-outline-light btn-sm me-2">仪表盘</a>
            <a href="/targets" class="btn btn-outline-light btn-sm me-2">目标</a>
            <a href="/changes" class="btn btn-outline-light btn-sm me-2">变更</a>
            <a href="/import" class="btn btn-outline-warning btn-sm">导入</a>
            {logout_btn}
        </div>
    </div>
</nav>
<div class="container mt-3">
"""

_LAYOUT_FOOT = """</div>
<script src="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""


def _layout(title: str, content_html: str) -> str:
    """组装标准页面布局 (head + nav + content + footer)"""
    # 表单认证启用时导航栏追加登出入口（§2.1）
    logout_btn = (' <a href="/logout" class="btn btn-outline-danger btn-sm">登出</a>'
                  if _form_auth_enabled() else "")
    return _LAYOUT_HEAD.format(title=title, logout_btn=logout_btn) + content_html + _LAYOUT_FOOT


# ── 路由 ───────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """表单登录（§2.1 表单认证 + session token）。未启用认证时直接跳仪表盘。"""
    if not _form_auth_enabled():
        return redirect("/")
    user = _current_user()
    if user:
        return redirect("/")
    error = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if user_value := auth.get_credentials()[0]:
            if (username == user_value) and (_validate_login(user_value, password)):
                auth.reset_failed(user_value)
                audit("web", "login_success", msg=f"用户登录成功 {username}",
                      user_id=username, level="info")
                resp = make_response(redirect("/"))
                # 会话 + CSRF cookie（HttpOnly / SameSite=Lax，§4.1）
                resp.set_cookie(_SESSION_COOKIE, auth.issue_session_token(username),
                                httponly=True, samesite="Lax",
                                max_age=auth._SESSION_MAX_AGE)
                resp.set_cookie(_USER_COOKIE, username, httponly=True, samesite="Lax")
                resp.set_cookie(auth._CSRF_COOKIE, auth.issue_csrf_token(username),
                                httponly=False, samesite="Lax",
                                max_age=auth._SESSION_MAX_AGE)
                return resp
            else:
                auth.record_failed(user_value)
                audit("web", "login_failed", msg=f"用户登录失败 {username}",
                      user_id=username, level="warn")
                error = "用户名或密码错误"
        else:
            error = "用户名或密码错误"

    content = f"""
    <div class="row justify-content-center mt-5">
      <div class="col-md-4"><div class="card p-4">
        <h4 class="mb-3">🔭 观星 · 登录</h4>
        {f'<div class="alert alert-danger">{escape(error)}</div>' if error else ''}
        <form method="POST">
          <div class="mb-3">
            <label class="form-label">用户名</label>
            <input type="text" name="username" class="form-control" required>
          </div>
          <div class="mb-3">
            <label class="form-label">密码</label>
            <input type="password" name="password" class="form-control" required>
          </div>
          <button type="submit" class="btn btn-primary w-100">登录</button>
        </form>
      </div></div>
    </div>
    """
    return _layout("观星 · 登录", content)


def _validate_login(username: str, password: str) -> bool:
    """表单登录校验：优先 bcrypt 哈希，兼容明文（§2.1 / §3.3.2）。"""
    _, stored = auth.get_credentials()
    if not stored:
        return False
    return auth.verify_password(password, stored) or hmac_compare(password, stored)


@app.route("/logout", methods=["GET", "POST"])
@requires_auth
def logout():
    """登出：清空会话 cookie 并记审计。"""
    user = _current_user() or "local-user"
    audit("web", "logout", msg=f"用户登出 {user}", user_id=user, level="info")
    resp = make_response(redirect("/login"))
    resp.set_cookie(_SESSION_COOKIE, "", expires=0)
    resp.set_cookie(_USER_COOKIE, "", expires=0)
    resp.set_cookie(auth._CSRF_COOKIE, "", expires=0)
    return resp


def _csrf_hidden_input() -> str:
    """表单认证启用时输出 CSRF 隐藏域。"""
    if not _form_auth_enabled():
        return ""
    user = _current_user()
    token = auth.issue_csrf_token(user) if user else ""
    return f'<input type="hidden" name="csrf_token" value="{escape(token)}">'


@app.route("/")
@requires_auth
def dashboard():
    """仪表盘页面（统计/技术栈分布/最近变更）"""
    stats = get_stats()
    targets, _ = get_targets(limit=10)
    changes = get_changes(limit=10)

    tech_html = " ".join(
        f'<span class="tech-tag">{_esc(t)} &times;{c}</span>'
        for t, c in sorted(stats["tech_distribution"].items(), key=lambda x: -x[1])[:12]
    )

    recent_targets = "".join(
        f"""<tr>
            <td><a href="/target/{t['id']}">{_esc(t['host'], 35)}</a></td>
            <td><span class="badge {'bg-success' if t['status']=='alive' else 'bg-secondary'}">{_esc(t['status'])}</span></td>
            <td>{' '.join(f'<span class="tech-tag">{_esc(x)}</span>' for x in (t.get('tech_stack',[]) or [])[:3])}</td>
            <td><span class="badge {'bg-warning text-dark' if t['sensitive_count']>0 else 'bg-light text-muted'}">{t['sensitive_count']}</span></td>
            <td><span class="badge {'bg-danger' if t['cve_count']>0 else 'bg-light text-muted'}">{t['cve_count']}</span></td>
            <td class="text-muted small">{_esc(t['last_seen'][:16])}</td>
        </tr>"""
        for t in targets
    ) or '<tr><td colspan="6" class="text-center text-muted">暂无数据 — 运行 poxiao scan 后自动导入</td></tr>'

    changes_html = "".join(
        f"""<tr>
            <td><a href="/target/{c['target_id']}">目标#{c['target_id']}</a></td>
            <td>{_esc(c['change_type'])}</td>
            <td>{_esc(c['changed_at'][:16])}</td>
        </tr>"""
        for c in changes
    ) or '<tr><td colspan="3" class="text-center text-muted">暂无变更</td></tr>'

    alive_pct = round(stats['alive']/max(stats['total'],1)*100)
    found_pct = round(stats['with_findings']/max(stats['total'],1)*100)
    content = f"""
    <div class="row">
        <div class="col-md-3"><div class="card stat-card">
            <div class="stat-value">{stats['total']}</div><div class="stat-label">监控目标</div>
            <div class="progress mt-2" style="height:4px"><div class="progress-bar bg-primary" style="width:100%"></div></div></div></div>
        <div class="col-md-3"><div class="card stat-card">
            <div class="stat-value text-success">{stats['alive']}<small class="fs-6"> / {alive_pct}%</small></div><div class="stat-label">存活</div>
            <div class="progress mt-2" style="height:4px"><div class="progress-bar bg-success" style="width:{alive_pct}%"></div></div></div></div>
        <div class="col-md-3"><div class="card stat-card">
            <div class="stat-value text-warning">{stats['with_findings']}<small class="fs-6"> / {found_pct}%</small></div><div class="stat-label">有发现</div>
            <div class="progress mt-2" style="height:4px"><div class="progress-bar bg-warning" style="width:{found_pct}%"></div></div></div></div>
        <div class="col-md-3"><div class="card stat-card">
            <div class="stat-value text-info">{stats['recent_changes']}</div><div class="stat-label">7日内变更</div></div></div>
    </div>
    <div class="row">
        <div class="col-md-8">
            <div class="card"><div class="card-body">
                <h5>📋 最近目标</h5>
                <table class="table table-hover table-sm">
                <thead><tr><th>目标</th><th>状态</th><th>技术栈</th><th>发现</th><th>CVE</th><th>最近扫描</th></tr></thead>
                <tbody>{recent_targets}</tbody></table>
            </div></div>
        </div>
        <div class="col-md-4">
            <div class="card"><div class="card-body">
                <h5>🛠 技术栈分布</h5>
                <div>{tech_html}</div>
            </div></div>
            <div class="card"><div class="card-body">
                <h5>📝 最近变更</h5>
                <table class="table table-sm"><tbody>{changes_html}</tbody></table>
            </div></div>
        </div>
    </div>
    """
    return _layout("观星 · 仪表盘", content)


@app.route("/targets")
@requires_auth
def targets_list():
    """目标列表页（搜索/状态筛选/分页）"""
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    try:
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 20)), 1), 200)
    except (TypeError, ValueError):
        # 非数字分页参数回退默认值，避免 500
        page, per_page = 1, 20
    offset = (page - 1) * per_page

    targets, total = get_targets(
        status=status or None,
        limit=per_page,
        offset=offset,
        search=q or None,
    )
    total_pages = max((total + per_page - 1) // per_page, 1)

    rows = "".join(
        f"""<tr>
            <td><a href="/target/{t['id']}">{_esc(t['host'], 35)}</a></td>
            <td><code>{_esc(t['url'], 40)}</code></td>
            <td><span class="badge {'bg-success' if t['status']=='alive' else 'bg-secondary'}">{_esc(t['status'])}</span></td>
            <td>{' '.join(f'<span class="tech-tag">{_esc(x)}</span>' for x in (t.get('tech_stack',[]) or [])[:4])}</td>
            <td><span class="badge {'bg-warning text-dark' if t['sensitive_count']>0 else 'bg-light text-muted'}">{t['sensitive_count']}</span></td>
            <td><span class="badge {'bg-danger' if t['cve_count']>0 else 'bg-light text-muted'}">{t['cve_count']}</span></td>
            <td class="text-muted small">{_esc(t['last_seen'][:16])}</td>
        </tr>"""
        for t in targets
    ) or '<tr><td colspan="7" class="text-center text-muted">无匹配结果</td></tr>'

    # 分页控件
    def _page_url(p: int) -> str:
        """生成分页链接 URL（保留当前筛选条件）"""
        from urllib.parse import urlencode
        return "/targets?" + urlencode({"q": q, "status": status, "page": p, "per_page": per_page})

    pager_parts = []
    if page > 1:
        pager_parts.append(f'<a href="{_page_url(page-1)}" class="btn btn-sm btn-outline-primary">&laquo; 上一页</a>')
    pager_parts.append(f'<span class="mx-2 align-self-center">第 {page} / {total_pages} 页</span>')
    if page < total_pages:
        pager_parts.append(f'<a href="{_page_url(page+1)}" class="btn btn-sm btn-outline-primary">下一页 &raquo;</a>')
    pager_html = f'<div class="d-flex justify-content-center align-items-center mt-3">{"".join(pager_parts)}</div>'

    content = f"""
    <h4>🎯 所有目标 ({total})</h4>
    <div class="card mb-3"><div class="card-body py-2">
    <form method="GET" class="row g-2">
        <div class="col-md-6">
            <input type="text" name="q" class="form-control form-control-sm" placeholder="搜索域名或URL..." value="{_esc(q)}">
        </div>
        <div class="col-md-3">
            <select name="status" class="form-select form-select-sm">
                <option value="">全部状态</option>
                <option value="alive" {'selected' if status=='alive' else ''}>存活</option>
                <option value="dead" {'selected' if status=='dead' else ''}>不可达</option>
            </select>
        </div>
        <div class="col-md-3">
            <button type="submit" class="btn btn-sm btn-primary w-100">筛选</button>
        </div>
    </form>
    </div></div>
    <div class="card"><div class="card-body">
    <table class="table table-hover table-sm">
    <thead><tr><th>域名</th><th>URL</th><th>状态</th><th>技术栈</th><th>发现</th><th>CVE</th><th>最近</th></tr></thead>
    <tbody>{rows}</tbody></table>
    </div></div>
    {pager_html}
    """
    return _layout("观星 · 目标列表", content)


@app.route("/target/<int:target_id>")
@requires_auth
def target_detail(target_id):
    """目标详情页（发现/CVE/扫描历史）"""
    t = get_target_by_id(target_id)
    if not t:
        return "Target not found", 404

    scans = get_scans(target_id, limit=20)
    changes = get_changes(target_id, limit=20)

    scans_html = "".join(
        f"""<tr>
            <td>{_esc(s['scanned_at'][:16])}</td>
            <td><span class="badge {'bg-success' if s['alive'] else 'bg-secondary'}">{'存活' if s['alive'] else '不可达'}</span></td>
            <td>{' '.join(f'<span class="tech-tag">{_esc(x)}</span>' for x in (s.get('tech_stack',[]) or [])[:5])}</td>
            <td>{len(s.get('sensitive_paths',[]) or [])}</td>
            <td>{len(s.get('cve_matches',[]) or [])}</td>
        </tr>"""
        for s in scans
    ) or '<tr><td colspan="5" class="text-center text-muted">暂无扫描记录</td></tr>'

    changes_html = "".join(
        f"""<tr>
            <td>{_esc(c['changed_at'][:16])}</td>
            <td>{_esc(c['change_type'])}</td>
            <td><span class="change-old">{_esc(c['old_value'], 60)}</span></td>
            <td><span class="change-new">{_esc(c['new_value'], 60)}</span></td>
        </tr>"""
        for c in changes
    ) or '<tr><td colspan="4" class="text-center text-muted">暂无变更</td></tr>'

    # 最新扫描的敏感发现
    latest_scan = scans[0] if scans else {}
    sensitive = latest_scan.get("sensitive_paths", []) or []
    cves = latest_scan.get("cve_matches", []) or []

    sensitive_html = "".join(
        f'<li><code>{_esc(s.get("url",""))}</code> [{_esc(s.get("status","?"))}] {_esc(s.get("category",""))}</li>'
        for s in sensitive[:15]
    ) or '<li class="text-muted">无</li>'

    tech_tags = ' '.join(f'<span class="tech-tag">{_esc(x)}</span>' for x in (t.get('tech_stack',[]) or []))

    content = f"""
    <h4>🔍 {_esc(t['host'])}</h4>
    <div class="row">
        <div class="col-md-8">
            <div class="card"><div class="card-body">
                <h5>基本信息</h5>
                <table class="table table-sm">
                    <tr><td width="100">URL</td><td><code>{_esc(t['url'])}</code></td></tr>
                    <tr><td>状态</td><td><span class="badge {'bg-success' if t['status']=='alive' else 'bg-secondary'}">{_esc(t['status'])}</span></td></tr>
                    <tr><td>技术栈</td><td>{tech_tags or '未知'}</td></tr>
                    <tr><td>首次发现</td><td>{_esc(t['first_seen'][:16])}</td></tr>
                    <tr><td>最近扫描</td><td>{_esc(t['last_seen'][:16])}</td></tr>
                </table>
            </div></div>

            <div class="card"><div class="card-body">
                <h5>最新发现的敏感路径</h5>
                <ul>{sensitive_html}</ul>
            </div></div>
        </div>

        <div class="col-md-4">
            <div class="card"><div class="card-body">
                <h5>CVE 匹配 ({len(cves)})</h5>
                {"".join(f'<div class="mb-2"><span class="badge badge-{"critical" if c.get("severity") in ("CRITICAL","HIGH") else "medium"}">{_esc(c.get("severity","?"))}</span> {_esc(c.get("cve","?"), 30)}</div>' for c in cves[:10]) or '<p class="text-muted">无</p>'}
            </div></div>
        </div>
    </div>

    <h5 class="mt-3">📊 扫描历史</h5>
    <div class="card"><div class="card-body">
    <table class="table table-hover table-sm">
    <thead><tr><th>时间</th><th>存活</th><th>技术栈</th><th>发现</th><th>CVE</th></tr></thead>
    <tbody>{scans_html}</tbody></table>
    </div></div>

    <h5 class="mt-3">🔄 变更记录</h5>
    <div class="card"><div class="card-body">
    <table class="table table-hover table-sm">
    <thead><tr><th>时间</th><th>类型</th><th>旧值</th><th>新值</th></tr></thead>
    <tbody>{changes_html}</tbody></table>
    </div></div>
    """
    return _layout(f"观星 · {_esc(t['host'])}", content)


@app.route("/changes")
@requires_auth
def changes_list():
    """变更记录列表页"""
    changes = get_changes(limit=100)
    rows = "".join(
        f"""<tr>
            <td><a href="/target/{c['target_id']}">#{c['target_id']}</a></td>
            <td>{_esc(c['changed_at'][:16])}</td>
            <td>{_esc(c['change_type'])}</td>
            <td><span class="change-old">{_esc(c['old_value'], 80)}</span></td>
            <td><span class="change-new">{_esc(c['new_value'], 80)}</span></td>
        </tr>"""
        for c in changes
    ) or '<tr><td colspan="5" class="text-center text-muted">暂无变更</td></tr>'

    content = f"""
    <h4>🔄 变更记录</h4>
    <div class="card"><div class="card-body">
    <table class="table table-hover table-sm">
    <thead><tr><th>目标</th><th>时间</th><th>类型</th><th>旧值</th><th>新值</th></tr></thead>
    <tbody>{rows}</tbody></table>
    </div></div>
    """
    return _layout("观星 · 变更记录", content)


@app.route("/import", methods=["GET", "POST"])
@requires_auth
@csrf_protect
def import_page():
    """扫描结果导入页面（JSON 上传）"""
    msg = ""
    if request.method == "POST":
        path = request.form.get("path", "")
        if path and Path(path).exists():
            try:
                import_from_summary(path)
                user = _current_user() or "local-user"
                audit("web", "import_summary", msg=f"面板导入扫描汇总 {path}",
                      user_id=user, level="info", **{"path": path})
                msg = f'<div class="alert alert-success">✅ 导入成功: {_esc(path)}</div>'
            except Exception as e:
                msg = f'<div class="alert alert-danger">❌ 导入失败: {_esc(e)}</div>'
        else:
            msg = f'<div class="alert alert-warning">文件不存在: {_esc(path)}</div>'

    # 列出可导入的汇总文件
    import glob
    summaries = sorted(glob.glob("scan_results/summary_*.json"), reverse=True)[:10]
    files_html = "".join(
        f'<option value="{_esc(s)}">{_esc(Path(s).name)}</option>' for s in summaries
    )

    content = f"""
    {msg}
    <h4>📥 导入扫描结果</h4>
    <div class="card"><div class="card-body">
    <form method="POST">
        {_csrf_hidden_input()}
        <div class="mb-3">
            <label class="form-label">扫描汇总 JSON 文件</label>
            <select name="path" class="form-select">
                <option value="">-- 选择文件 --</option>
                {files_html}
            </select>
            <div class="form-text mt-1">或输入路径: scan_results/summary_*.json</div>
            <input type="text" name="path" class="form-control mt-1" placeholder="手动输入路径">
        </div>
        <button type="submit" class="btn btn-primary">导入</button>
    </form>
    </div></div>

    <h5 class="mt-3">💡 使用方法</h5>
    <pre class="log">
# 1. 先运行扫描
python -m src.cli scan data/targets.txt

# 2. 导入扫描结果到观星
python -m src.cli monitor --import scan_results/summary_*.json

# 3. 启动 Web 监控面板
python -m src.cli monitor --serve

# 4. 浏览器打开 http://localhost:5099</pre>
    """
    return _layout("观星 · 导入", content)


@app.route("/api/export")
@requires_auth
def api_export() -> Response:
    """批量导出资产与变更（CSV / JSON），仅本地文件下载（P2-2 / X3）。"""
    fmt = request.args.get("format", "json") or "json"
    if fmt not in ("csv", "json"):
        fmt = "json"
    content, mimetype, filename = export_data(fmt)
    user = _current_user() or "local-user"
    # §7.1 敏感操作：导出须记录审计
    audit("web", "export_data", msg=f"面板导出资产 {filename}",
          user_id=user, level="info", **{"format": fmt})
    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def start_server(host: str = "127.0.0.1", port: int = 5099, debug: bool = False):
    """启动 Web 服务器"""
    print("GuanXing Asset Monitor")
    print(f"   http://localhost:{port}")
    app.run(host=host, port=port, debug=debug)
