#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破晓 · 性能压测基准 (Phase 3 / P3-4 / D11)
============================================

合成 asyncio 并发基准（**不触网**），用于评估破晓并发调度模型在
大批量（≤100 目标）下的吞吐与稳定性，并检测"超时雪崩"
（错误率突增即判为雪崩，仅提示不阻断）。

模型：每个"目标"是一个 `asyncio.sleep` 模拟任务；
  * 正常任务耗时 ~ task-ms（带抖动）；
  * 按 --error-rate 比例注入"超时/失败"任务（耗时更长且计入错误）。
  * --concurrency 控制并发上限（Semaphore）。

指标：总耗时、吞吐(目标/秒)、P50/P95/P99 时延、错误数、错误率。

退出码：
  0 = 完成且错误率 ≤ 阈值
  2 = 检测到"超时雪崩"（错误率 > 阈值），仅提示
  1 = 运行异常

用法：
  python tools/bench.py --targets 100 --concurrency 20 --task-ms 50
  python tools/bench.py --targets 8 --concurrency 4 --task-ms 1 --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


async def _sim_target(
    idx: int,
    task_ms: float,
    error_rate: float,
    timeout_ms: float,
    sem: asyncio.Semaphore,
    latencies: List[float],
    errors: List[int],
    rng: random.Random,
) -> None:
    """模拟单个目标的扫描任务。"""
    async with sem:
        t0 = time.monotonic()
        # 注入"超时/失败"：耗时显著更长并计为错误（模拟超时雪崩源）
        if rng.random() < error_rate:
            await asyncio.sleep(timeout_ms / 1000.0)
            errors[0] += 1
        else:
            jitter = rng.uniform(0.5, 1.5)
            await asyncio.sleep(task_ms / 1000.0 * jitter)
        latencies.append((time.monotonic() - t0) * 1000.0)


async def run_bench(
    targets: int = 100,
    concurrency: int = 20,
    task_ms: float = 50.0,
    error_rate: float = 0.1,
    timeout_ms: float = 500.0,
    rounds: int = 1,
    seed: int = 1337,
) -> Dict[str, Any]:
    """运行合成基准，返回指标 dict。"""
    rng = random.Random(seed)
    latencies: List[float] = []
    errors = [0]

    for _ in range(rounds):
        latencies.clear()
        errors[0] = 0
        sem = asyncio.Semaphore(max(1, concurrency))
        t_start = time.monotonic()
        await asyncio.gather(
            *(
                _sim_target(i, task_ms, error_rate, timeout_ms, sem, latencies, errors, rng)
                for i in range(targets)
            )
        )
        # 单轮即可，多轮仅复跑（指标以末轮为准）

    elapsed = time.monotonic() - t_start
    sorted_lat = sorted(latencies)
    total = targets * rounds
    err = errors[0]
    err_rate = (err / total) if total else 0.0

    return {
        "targets": targets,
        "rounds": rounds,
        "concurrency": concurrency,
        "task_ms": task_ms,
        "error_rate_injected": error_rate,
        "total_tasks": total,
        "elapsed_sec": round(elapsed, 4),
        "throughput_per_sec": round(total / elapsed, 2) if elapsed > 0 else 0.0,
        "latency_ms": {
            "p50": round(_percentile(sorted_lat, 50), 2),
            "p95": round(_percentile(sorted_lat, 95), 2),
            "p99": round(_percentile(sorted_lat, 99), 2),
            "max": round(sorted_lat[-1], 2) if sorted_lat else 0.0,
        },
        "errors": err,
        "error_rate": round(err_rate, 4),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="破晓性能压测基准（合成）")
    parser.add_argument("--targets", type=int, default=100, help="目标数（默认 100）")
    parser.add_argument("--concurrency", type=int, default=20, help="并发上限")
    parser.add_argument("--task-ms", type=float, default=50.0, help="单目标模拟耗时(ms)")
    parser.add_argument("--error-rate", type=float, default=0.1, help="注入失败比例")
    parser.add_argument("--timeout-ms", type=float, default=500.0, help="失败任务模拟超时(ms)")
    parser.add_argument("--rounds", type=int, default=1, help="重复轮数")
    parser.add_argument("--avalanche-threshold", type=float, default=0.2,
                        help="错误率超过此值判为超时雪崩")
    parser.add_argument("--json", default=None, help="指标写入 JSON")
    args = parser.parse_args(argv)

    try:
        metrics = asyncio.run(run_bench(
            targets=args.targets,
            concurrency=args.concurrency,
            task_ms=args.task_ms,
            error_rate=args.error_rate,
            timeout_ms=args.timeout_ms,
            rounds=args.rounds,
        ))
    except Exception as e:
        print(f"[bench] 运行异常: {e}")
        return 1

    print("=" * 56)
    print("POXIAO BENCHMARK / 破晓性能压测基准（合成）")
    print("=" * 56)
    print(f"目标数={metrics['targets']}  并发={metrics['concurrency']}  "
          f"单任务~{metrics['task_ms']}ms")
    print(f"总耗时: {metrics['elapsed_sec']}s  吞吐: {metrics['throughput_per_sec']} 目标/秒")
    print(f"时延(ms): P50={metrics['latency_ms']['p50']}  "
          f"P95={metrics['latency_ms']['p95']}  P99={metrics['latency_ms']['p99']}  "
          f"max={metrics['latency_ms']['max']}")
    print(f"错误: {metrics['errors']}/{metrics['total_tasks']}  "
          f"错误率={metrics['error_rate']}")

    if args.json:
        Path(args.json).write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"指标 -> {args.json}")

    if metrics["error_rate"] > args.avalanche_threshold:
        print(f"[bench] 检测到超时雪崩（错误率 {metrics['error_rate']} > "
              f"阈值 {args.avalanche_threshold}）")
        print("RESULT: AVALANCHE (exit 2)")
        return 2

    print("RESULT: OK (exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
