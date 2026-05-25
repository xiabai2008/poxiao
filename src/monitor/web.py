"""观星 — 资产监控 Web 界面"""

from flask import Flask, render_template_string, jsonify, request, redirect, url_for
from pathlib import Path
import json as _json

from .db import (
    get_targets, get_target_by_id, get_scans, get_changes,
    get_stats, import_from_summary, upsert_target, add_scan,
)

app = Flask(__name__)

# ── 内联模板（单文件部署，无需额外模板目录）──

BASE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>观星 · 资产监控</title>
    <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.bootcdn.net/ajax/libs/bootstrap-icons/1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body { background: #f5f7fa; font-size: 14px; }
        .card { border: none; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 16px; }
        .stat-card { text-align: center; padding: 20px; }
        .stat-value { font-size: 2rem; font-weight: 700; }
        .stat-label { color: #6c757d; font-size: 13px; }
        .navbar { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); }
        .navbar-brand { font-weight: 700; letter-spacing: 1px; }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #fd7e14; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #0dcaf0; }
        .tech-tag { display: inline-block; padding: 2px 8px; margin: 2px;
                    background: #e9ecef; border-radius: 12px; font-size: 12px; }
        .change-new { background: #d1e7dd; }
        .change-old { background: #f8d7da; text-decoration: line-through; }
        pre.log { background: #1a1a2e; color: #00ff88; padding: 12px; border-radius: 8px;
                  font-size: 13px; max-height: 300px; overflow-y: auto; }
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
{{ content|safe }}
</div>
<script src="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""


# ── 路由 ───────────────────────────────────────

@app.route("/")
def dashboard():
    stats = get_stats()
    targets = get_targets(limit=10)
    changes = get_changes(limit=10)

    tech_html = " ".join(
        f'<span class="tech-tag">{t} ×{c}</span>'
        for t, c in sorted(stats["tech_distribution"].items(), key=lambda x: -x[1])[:12]
    )

    recent_targets = "".join(
        f"""<tr>
            <td><a href="/target/{t['id']}">{t['host'][:35]}</a></td>
            <td><span class="badge {'bg-success' if t['status']=='alive' else 'bg-secondary'}">{t['status']}</span></td>
            <td>{' '.join(f'<span class="tech-tag">{x}</span>' for x in (t.get('tech_stack',[]) or [])[:3])}</td>
            <td><span class="badge {'bg-warning text-dark' if t['sensitive_count']>0 else 'bg-light text-muted'}">{t['sensitive_count']}</span></td>
            <td><span class="badge {'bg-danger' if t['cve_count']>0 else 'bg-light text-muted'}">{t['cve_count']}</span></td>
            <td class="text-muted small">{t['last_seen'][:16]}</td>
        </tr>"""
        for t in targets
    ) or '<tr><td colspan="6" class="text-center text-muted">暂无数据 — 运行 poxiao scan 后自动导入</td></tr>'

    changes_html = "".join(
        f"""<tr>
            <td><a href="/target/{c['target_id']}">目标#{c['target_id']}</a></td>
            <td>{c['change_type']}</td>
            <td>{c['changed_at'][:16]}</td>
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
    return render_template_string(BASE_HTML, content=content)


@app.route("/targets")
def targets_list():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    targets = get_targets(limit=200)

    # 过滤
    if q:
        targets = [t for t in targets if q.lower() in t.get("host","").lower()
                   or q.lower() in t.get("url","").lower()]
    if status:
        targets = [t for t in targets if t.get("status") == status]

    rows = "".join(
        f"""<tr>
            <td><a href="/target/{t['id']}">{t['host'][:35]}</a></td>
            <td><code>{t['url'][:40]}</code></td>
            <td><span class="badge {'bg-success' if t['status']=='alive' else 'bg-secondary'}">{t['status']}</span></td>
            <td>{' '.join(f'<span class="tech-tag">{x}</span>' for x in (t.get('tech_stack',[]) or [])[:4])}</td>
            <td><span class="badge {'bg-warning text-dark' if t['sensitive_count']>0 else 'bg-light text-muted'}">{t['sensitive_count']}</span></td>
            <td><span class="badge {'bg-danger' if t['cve_count']>0 else 'bg-light text-muted'}">{t['cve_count']}</span></td>
            <td class="text-muted small">{t['last_seen'][:16]}</td>
        </tr>"""
        for t in targets
    ) or '<tr><td colspan="7" class="text-center text-muted">无匹配结果</td></tr>'

    content = f"""
    <h4>🎯 所有目标 ({len(targets)})</h4>
    <div class="card mb-3"><div class="card-body py-2">
    <form method="GET" class="row g-2">
        <div class="col-md-6">
            <input type="text" name="q" class="form-control form-control-sm" placeholder="搜索域名或URL..." value="{q}">
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
    """
    return render_template_string(BASE_HTML, content=content)


@app.route("/target/<int:target_id>")
def target_detail(target_id):
    t = get_target_by_id(target_id)
    if not t:
        return "Target not found", 404

    scans = get_scans(target_id, limit=20)
    changes = get_changes(target_id, limit=20)

    scans_html = "".join(
        f"""<tr>
            <td>{s['scanned_at'][:16]}</td>
            <td><span class="badge {'bg-success' if s['alive'] else 'bg-secondary'}">{'存活' if s['alive'] else '不可达'}</span></td>
            <td>{' '.join(f'<span class="tech-tag">{x}</span>' for x in (s.get('tech_stack',[]) or [])[:5])}</td>
            <td>{len(s.get('sensitive_paths',[]) or [])}</td>
            <td>{len(s.get('cve_matches',[]) or [])}</td>
        </tr>"""
        for s in scans
    ) or '<tr><td colspan="5" class="text-center text-muted">暂无扫描记录</td></tr>'

    changes_html = "".join(
        f"""<tr>
            <td>{c['changed_at'][:16]}</td>
            <td>{c['change_type']}</td>
            <td><span class="change-old">{c['old_value'][:60]}</span></td>
            <td><span class="change-new">{c['new_value'][:60]}</span></td>
        </tr>"""
        for c in changes
    ) or '<tr><td colspan="4" class="text-center text-muted">暂无变更</td></tr>'

    # 最新扫描的敏感发现
    latest_scan = scans[0] if scans else {}
    sensitive = latest_scan.get("sensitive_paths", []) or []
    cves = latest_scan.get("cve_matches", []) or []

    sensitive_html = "".join(
        f'<li><code>{s.get("url","")}</code> [{s.get("status","?")}] {s.get("category","")}</li>'
        for s in s[:15]
    ) or '<li class="text-muted">无</li>'

    tech_tags = ' '.join(f'<span class="tech-tag">{x}</span>' for x in (t.get('tech_stack',[]) or []))

    content = f"""
    <h4>🔍 {t['host']}</h4>
    <div class="row">
        <div class="col-md-8">
            <div class="card"><div class="card-body">
                <h5>基本信息</h5>
                <table class="table table-sm">
                    <tr><td width="100">URL</td><td><code>{t['url']}</code></td></tr>
                    <tr><td>状态</td><td><span class="badge {'bg-success' if t['status']=='alive' else 'bg-secondary'}">{t['status']}</span></td></tr>
                    <tr><td>技术栈</td><td>{tech_tags or '未知'}</td></tr>
                    <tr><td>首次发现</td><td>{t['first_seen'][:16]}</td></tr>
                    <tr><td>最近扫描</td><td>{t['last_seen'][:16]}</td></tr>
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
                {"".join(f'<div class="mb-2"><span class="badge badge-{"critical" if c.get("severity") in ("CRITICAL","HIGH") else "medium"}">{c.get("severity","?")}</span> {c.get("cve","?")[:30]}</div>' for c in cves[:10]) or '<p class="text-muted">无</p>'}
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
    return render_template_string(BASE_HTML, content=content)


@app.route("/changes")
def changes_list():
    changes = get_changes(limit=100)
    rows = "".join(
        f"""<tr>
            <td><a href="/target/{c['target_id']}">#{c['target_id']}</a></td>
            <td>{c['changed_at'][:16]}</td>
            <td>{c['change_type']}</td>
            <td><span class="change-old">{c['old_value'][:80]}</span></td>
            <td><span class="change-new">{c['new_value'][:80]}</span></td>
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
    return render_template_string(BASE_HTML, content=content)


@app.route("/import", methods=["GET", "POST"])
def import_page():
    msg = ""
    if request.method == "POST":
        path = request.form.get("path", "")
        if path and Path(path).exists():
            try:
                import_from_summary(path)
                msg = f'<div class="alert alert-success">✅ 导入成功: {path}</div>'
            except Exception as e:
                msg = f'<div class="alert alert-danger">❌ 导入失败: {e}</div>'
        else:
            msg = f'<div class="alert alert-warning">文件不存在: {path}</div>'

    # 列出可导入的汇总文件
    import glob
    summaries = sorted(glob.glob("scan_results/summary_*.json"), reverse=True)[:10]
    files_html = "".join(
        f'<option value="{s}">{Path(s).name}</option>' for s in summaries
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
    return render_template_string(BASE_HTML, content=content)


def start_server(host: str = "0.0.0.0", port: int = 5099, debug: bool = False):
    """启动 Web 服务器"""
    print(f"GuanXing Asset Monitor")
    print(f"   http://localhost:{port}")
    app.run(host=host, port=port, debug=debug)
