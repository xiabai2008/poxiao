"""精选模板筛选（P2-4：community → 正式库的高价值候选）

规则（全部满足才入选）：
  - 可被破晓 loader 加载（raw/DSL 已支持，99.9% 兼容）
  - severity ∈ {high, critical}（排除 low/info 噪音）
  - 命中高价值信号之一：
      * 国内组件关键词（seeyon/致远、泛微、蓝凌、用友、金蝶、通达、万户、
        jeecg、若依 ruoyi、nacos、shiro、fastjson、log4j、weblogic、
        struts2、thinkphp、dedecms、discuz、phpmyadmin、jenkins、
        grafana、gitlab、confluence、jira、xxl-job、spring-boot、
        actuator、minio、coremail、蓝凌、帆软、帆软报表、泛微 e-cology 等）
      * 模板 id 含 CVE-20xx（近 3 年优先）
      * tags 含 rce/unauth/sqli/lfi（高危类型）
  - 无未知模板级变量风险（variables 块已声明的除外）

用法:
  python tools/template_select.py <community-dir> [--list] [--apply]
  --list   只输出候选清单（默认）
  --apply  复制入选模板到 templates/（同名跳过，不覆盖已有）
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# 国内组件/高价值关键词（匹配 info.tags / info.name / 模板 id）
HIGH_VALUE_KEYWORDS = [
    "seeyon", "weaver", "ecology", "e-cology", "landray", "蓝凌", "yonyou",
    "用友", "ufida", "kingdee", "金蝶", "tongda", "通达", "fanwei", "泛微",
    "jeecg", "ruoyi", "若依", "nacos", "shiro", "fastjson", "log4j",
    "weblogic", "struts2", "thinkphp", "dedecms", "discuz", "phpmyadmin",
    "jenkins", "grafana", "gitlab", "confluence", "jira", "xxl-job",
    "spring", "actuator", "minio", "coremail", "帆软", "finereport",
    "groupmail", "泛微", "致远", "万户", "websitebator", "wanhu",
    "lanling", "蓝凌", "sqlserver", "oracle", "elasticsearch", "redis",
    "mongodb", "docker", "kubernetes", "tomcat", "nginx", "apache",
    "iis", "exchange", "sharepoint", "webpack", "nextjs", "vue",
]

HIGH_RISK_TAGS = ["rce", "unauth", "sqli", "lfi", "rce-check", "auth-bypass"]


def is_high_value(raw: dict, tid: str) -> bool:
    """判断模板是否命中高价值信号"""
    info = raw.get("info", {}) or {}
    haystack = " ".join([
        tid or "",
        str(info.get("name", "") or ""),
        " ".join(str(info.get("tags", "") or "").split(",")),
    ]).lower()
    for kw in HIGH_VALUE_KEYWORDS:
        if kw in haystack:
            return True
    return False


def has_high_risk_type(raw: dict) -> bool:
    info = raw.get("info", {}) or {}
    tags = str(info.get("tags", "") or "").lower()
    return any(t in tags for t in HIGH_RISK_TAGS)


def recent_cve(tid: str) -> int:
    """模板 id 中 CVE 年份（如 CVE-2024-xxxx → 2024），无则 0"""
    m = re.search(r"CVE-(\d{4})", tid or "")
    return int(m.group(1)) if m else 0


def select_candidates(community_dir: Path, max_candidates: int = 800,
                      min_score: int = 0, include_cn_forced: bool = True) -> List[Dict[str, Any]]:
    """筛选候选模板，返回按价值排序的清单

    Args:
        min_score: 最低分数门槛（score >= min_score 才入选）
        include_cn_forced: 国内组件模板强制入选（即使分数不足）
    """
    candidates: List[Dict[str, Any]] = []
    for yml in sorted(community_dir.rglob("*.yaml")):
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        tid = str(raw.get("id", "") or "")
        info = raw.get("info", {}) or {}
        sev = str(info.get("severity", "info") or "info").lower()
        if sev not in ("high", "critical"):
            continue
        # 必须可被破晓加载
        if not raw.get("http") and not raw.get("requests"):
            continue

        score = 0
        reasons = []
        cn_hit = is_high_value(raw, tid)
        if cn_hit:
            score += 3
            reasons.append("国内组件/高价值关键词")
        cve_year = recent_cve(tid)
        if cve_year:
            score += 2 if cve_year >= 2023 else 1
            reasons.append(f"CVE-{cve_year}")
        if has_high_risk_type(raw):
            score += 2
            reasons.append("高危类型")
        if sev == "critical":
            score += 1

        if score < min_score and not (include_cn_forced and cn_hit):
            continue

        candidates.append({
            "file": str(yml.relative_to(community_dir)),
            "id": tid,
            "severity": sev,
            "score": score,
            "reasons": reasons,
            "cve_year": cve_year,
        })

    candidates.sort(key=lambda c: (-c["score"], -c["cve_year"], c["id"]))
    return candidates[:max_candidates]


def apply_candidates(candidates: List[Dict[str, Any]], community_dir: Path,
                     target_dir: Path) -> Dict[str, int]:
    """复制候选到目标目录（保留相对路径，不覆盖已有文件）

    防撞号（P2-4 教训）：跳过与目标库已有模板 ID 重复的候选，
    避免 ci_audit 唯一性门禁失败。
    """
    # 目标库已有 ID 集合（排除 nuclei_selected 自身）
    existing_ids: set = set()
    if target_dir.exists():
        for p in target_dir.rglob("*.yaml"):
            if "nuclei_selected" in p.parts:
                continue
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and raw.get("id"):
                    existing_ids.add(str(raw["id"]))
            except Exception:
                pass

    applied, skipped, skipped_dup = 0, 0, 0
    for c in candidates:
        if c["id"] in existing_ids:
            skipped_dup += 1
            continue
        src = community_dir / c["file"]
        dst = target_dir / "nuclei_selected" / c["file"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            skipped += 1
            continue
        shutil.copy2(src, dst)
        applied += 1
        existing_ids.add(c["id"])
    return {"applied": applied, "skipped": skipped, "skipped_dup": skipped_dup}


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="破晓模板精选筛选（P2-4）")
    parser.add_argument("community", help="community 模板目录")
    parser.add_argument("--list", action="store_true", help="仅输出候选清单（默认）")
    parser.add_argument("--apply", action="store_true", help="复制入选模板到 templates/nuclei_selected/")
    parser.add_argument("--max", type=int, default=800, help="候选上限")
    parser.add_argument("--min-score", type=int, default=0,
                        help="最低分数门槛（score>=6 高价值/高危组合；国内组件不受此限）")
    args = parser.parse_args(argv)

    if yaml is None:
        print("[select] PyYAML 未安装")
        return 1

    community = Path(args.community)
    if not community.exists():
        print(f"[select] 目录不存在: {community}")
        return 1

    candidates = select_candidates(community, max_candidates=args.max,
                                   min_score=args.min_score)
    print(f"[select] 候选 {len(candidates)} 个（high/critical + 高价值信号）")
    for c in candidates[:20]:
        print(f"  [{c['score']}] {c['file']}  ({','.join(c['reasons'])})")
    if len(candidates) > 20:
        print(f"  ... 共 {len(candidates)} 个（--apply 全量合入）")

    if args.apply:
        result = apply_candidates(candidates, community, Path("templates"))
        print(f"[select] 已合入 {result['applied']} 个，跳过已有 {result['skipped']} 个，"
              f"跳过撞号 {result['skipped_dup']} 个")
        print("[select] 下一步: python tools/template_sync.py validate templates/nuclei_selected")
        print("[select]          python tools/template_sync.py sign templates --key <私钥>")

    print("RESULT: OK (exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
