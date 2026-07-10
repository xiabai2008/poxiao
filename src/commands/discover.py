"""域名发现命令"""

from pathlib import Path

from src.target.discovery import DomainDiscovery
from src.utils.output import Out


def cmd_discover(args):
    """域名发现命令"""
    dd = DomainDiscovery(timeout=5.0, enable_search=args.search)

    try:
        # 加载公司列表
        if args.file:
            filepath = Path(args.file)
            if not filepath.exists():
                Out.error(f"文件不存在: {args.file}")
                return
            names = [l.strip() for l in filepath.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.strip().startswith("#")]
        elif args.name:
            if Path(args.name).exists():
                names = [l.strip() for l in Path(args.name).read_text(encoding="utf-8").splitlines()
                        if l.strip() and not l.strip().startswith("#")]
            else:
                names = [args.name]
        else:
            Out.error("请指定公司名或 --file")
            return

        Out.info(f"发现 {len(names)} 家公司的域名...")
        Out.blank()

        found = []
        for i, name in enumerate(names):
            best = dd.discover_best(name)
            if best:
                found.append(best)
                Out.success(f"{name} -> {best}")
            else:
                Out.dim(f"{name} -> 未找到")

        # 保存
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(found), encoding="utf-8")
        Out.blank()
        Out.success(f"找到 {len(found)}/{len(names)} 个域名")
        Out.info(f"已保存: {output}")

    finally:
        dd.close()
