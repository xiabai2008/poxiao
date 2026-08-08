"""AI 模板生成（A1：对齐 nuclei -ai，LLM 生成 Nuclei 模板）

流程：
  1. 系统提示（Nuclei 模板格式规范 + 破晓引擎支持面）
  2. 调用 OpenAI 兼容 Chat Completions API（httpx，无额外依赖）
  3. 提取 ```yaml 代码块 → 字段校验（复用 validate 逻辑）→ loader 实测加载
  4. 输出到目标目录，提示签名入库

配置（环境变量，按源隔离）:
  POXIAO_LLM_API_KEY   必填
  POXIAO_LLM_BASE_URL  默认 https://api.openai.com/v1（兼容 DeepSeek/通义/Kimi 等）
  POXIAO_LLM_MODEL     默认 gpt-4o-mini
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import httpx

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

SYSTEM_PROMPT = """你是安全研究专家，负责生成 Nuclei 风格的 YAML 漏洞检测模板。
要求：
1. 输出单个 YAML 模板，必须包含 id、info(name/author/severity/description/tags)、http 块
2. 使用标准请求格式（method/path/headers/body），不要使用 raw 格式
3. matchers 支持类型：word/status/regex/size/dsl；DSL 表达式只能使用这些函数：
   to_lower/to_upper/trim/len/contains/icontains/starts_with/ends_with/replace/concat/substr/
   base64/base64_decode/url_encode/url_decode/hex_encode/hex_decode/md5/sha1/sha256/
   rand_int/rand_base/rand_char/regex/printable
4. 变量只能用：{{BaseURL}} {{Hostname}} {{Host}} {{Scheme}} {{Port}} {{randstr}} {{randbase64}} {{timestamp}} {{oast-url}} {{oast-domain}}
5. 只输出 YAML 代码块（```yaml 包裹），不要解释
6. 模板必须能真正检测漏洞：请求要命中特征，matcher 要精确，避免误报
7. 若需求不明确或无法生成安全模板，输出 ```yaml 空块```

生成模板："""


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _extract_yaml(text: str) -> str:
    """从 LLM 输出中提取 YAML 代码块"""
    m = re.search(r"```yaml\s*\n(.*?)```", text, re.S)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\s*\n(.*?)```", text, re.S)
    if m:
        return m.group(1).strip()
    # 无代码块：整个输出当作 YAML（去掉可能的解释前缀）
    lines = [ln for ln in text.splitlines() if ln.strip()]
    start = next((i for i, ln in enumerate(lines) if ln.strip().startswith("id:")), 0)
    return "\n".join(lines[start:]).strip()


def validate_generated(raw: Dict[str, Any], template_text: str) -> Dict[str, Any]:
    """校验生成的模板：字段 + 引擎可加载；返回 (是否通过, 原因列表)"""
    issues: List[str] = []

    if not raw.get("id"):
        issues.append("缺 id")
    if not isinstance(raw.get("info"), dict):
        issues.append("缺 info 块")
    sev = str((raw.get("info") or {}).get("severity", "")).lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        issues.append(f"未知 severity: {sev or '(空)'}")

    http = raw.get("http", raw.get("requests"))
    if http is None:
        issues.append("缺 http/requests 块")
    else:
        # 检查 matcher 类型支持面
        reqs = http if isinstance(http, list) else [http]
        for req in reqs:
            if not isinstance(req, dict):
                continue
            for m in req.get("matchers", []) or []:
                if not isinstance(m, dict):
                    continue
                mtype = m.get("type", "word")
                if mtype not in ("word", "status", "regex", "size", "dsl", "binary", "header"):
                    issues.append(f"不支持的 matcher 类型: {mtype}")

    # 引擎加载实测
    try:
        from src.xiazhi.loader import TemplateLoader
        loader = TemplateLoader()
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False,
                                         encoding="utf-8") as tf:
            tf.write(template_text)
            tmp_path = tf.name
        try:
            tmpl = loader.load_file(Path(tmp_path))
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        if tmpl is None:
            issues.append("破晓引擎无法加载该模板")
        elif not tmpl.requests:
            issues.append("无可用请求")
    except Exception as e:
        issues.append(f"加载异常: {str(e)[:100]}")

    return {"ok": not issues, "issues": issues}


async def generate_template(description: str, api_key: str = "", base_url: str = "",
                            model: str = "", timeout: float = 60.0) -> Dict[str, Any]:
    """生成模板；返回 {ok, template, text, issues}"""
    api_key = api_key or _env("POXIAO_LLM_API_KEY")
    base_url = (base_url or _env("POXIAO_LLM_BASE_URL",
                                 "https://api.openai.com/v1")).rstrip("/")
    model = model or _env("POXIAO_LLM_MODEL", "gpt-4o-mini")

    if not api_key:
        return {"ok": False, "template": "", "text": "",
                "issues": ["未配置 POXIAO_LLM_API_KEY（或 --api-key）"]}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": description},
                    ],
                    "temperature": 0.2,
                },
            )
            data = resp.json()
    except Exception as e:
        return {"ok": False, "template": "", "text": "",
                "issues": [f"API 调用失败: {str(e)[:150]}"]}

    if resp.status_code != 200:
        err = (data.get("error") or {}).get("message", f"HTTP {resp.status_code}")
        return {"ok": False, "template": "", "text": "",
                "issues": [f"API 错误: {str(err)[:200]}"]}

    text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
    template_text = _extract_yaml(text)

    if not template_text or template_text.strip().startswith("```"):
        return {"ok": False, "template": "", "text": text,
                "issues": ["未提取到 YAML（LLM 可能拒绝了请求）"]}

    try:
        raw = yaml.safe_load(template_text) if yaml else None
    except Exception as e:
        return {"ok": False, "template": template_text, "text": text,
                "issues": [f"YAML 解析失败: {str(e)[:100]}"]}

    if not isinstance(raw, dict):
        return {"ok": False, "template": template_text, "text": text,
                "issues": ["生成的 YAML 不是有效模板"]}

    check = validate_generated(raw, template_text)
    return {
        "ok": check["ok"],
        "template": template_text,
        "text": text,
        "issues": check["issues"],
        "id": raw.get("id", ""),
    }


def save_template(template_text: str, output_dir: str = "templates/ai",
                  template_id: str = "") -> str:
    """保存生成的模板，返回路径"""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    name = template_id or "ai-generated"
    safe = re.sub(r"[^A-Za-z0-9_-]", "-", name).strip("-") or "ai-generated"
    path = out / f"{safe}.yaml"
    path.write_text(template_text, encoding="utf-8")
    return str(path)


def main(argv: List[str] | None = None) -> int:
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(description="破晓 AI 模板生成（A1）")
    parser.add_argument("description", help="要检测的漏洞描述，如：Apache Tomcat 反序列化 RCE")
    parser.add_argument("--api-key", default="", help="LLM API Key（或 POXIAO_LLM_API_KEY）")
    parser.add_argument("--base-url", default="", help="OpenAI 兼容 API Base URL")
    parser.add_argument("--model", default="", help="模型名")
    parser.add_argument("--out", default="templates/ai", help="输出目录")
    parser.add_argument("--save", action="store_true", help="校验通过后保存模板")
    args = parser.parse_args(argv)

    print(f"[ai] 生成模板: {args.description}")
    result = asyncio.run(generate_template(
        args.description, api_key=args.api_key,
        base_url=args.base_url, model=args.model,
    ))

    if not result["ok"]:
        print(f"[ai] 失败: {result['issues']}")
        return 1

    print(f"[ai] 生成成功 (id={result.get('id', '')})")
    print(result["template"])
    if args.save:
        path = save_template(result["template"], args.out, result.get("id", ""))
        print(f"[ai] 已保存: {path}")
        print("[ai] 下一步: python tools/template_sync.py validate <file>")
        print("[ai]          python tools/template_sync.py sign templates --key <私钥>")
    print("RESULT: OK (exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
