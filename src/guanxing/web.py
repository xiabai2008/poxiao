"""观星 — 资产监控 Web 界面"""

import functools
import os
from flask import Flask, request, Response
from markupsafe import escape
from pathlib import Path

from .db import (
    get_targets, get_target_by_id, get_scans, get_changes,
    get_stats, import_from_summary, export_data,
)

app = Flask(__name__)


# ── 基础认证 ──────────────────────────────────────

def _check_auth(username: str | None, password: str | None) -> bool:
    """校验用户名密码"""
    return (
        username == os.environ.get("POXIAO_MONITOR_USER", "")
        and password == os.environ.get("POXIAO_MONITOR_PASS", "")
    )


def _require_auth() -> Response | None:
    """若设置了认证环境变量则校验，返回 401 Response 或 None"""
    if not (os.environ.get("POXIAO_MONITOR_USER") and os.environ.get("POXIAO_MONITOR_PASS")):
        return None
    auth = request.authorization
    if not auth or not _check_auth(auth.username, auth.password):
        return Response(
            "Unauthorized — set POXIAO_MONITOR_USER / POXIAO_MONITOR_PASS",
            401,
            {"WWW-Authenticate": 'Basic realm="GuanXing"'},
        )
    return None


def requires_auth(f):
    """认证装饰器 (仅在环境变量存在时生效)"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        resp = _require_auth()
        if resp is not None:
            return resp
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
    return _LAYOUT_HEAD.format(title=title) + content_html + _LAYOUT_FOOT


# ── 路由 ───────────────────────────────────────

@app.route("/")
@requires_auth
def dashboard():
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
def import_page():
    msg = ""
    if request.method == "POST":
        path = request.form.get("path", "")
        if path and Path(path).exists():
            try:
                import_from_summary(path)
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
