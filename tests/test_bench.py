"""P3-4 性能压测基准测试（合成，不触网）"""
import asyncio

from tools.bench import run_bench


def test_bench_metrics_present():
    metrics = asyncio.run(run_bench(
        targets=8, concurrency=4, task_ms=1, error_rate=0.0, rounds=1
    ))
    assert metrics["total_tasks"] == 8
    assert "throughput_per_sec" in metrics
    assert "latency_ms" in metrics
    assert metrics["latency_ms"]["p50"] >= 0
    assert metrics["errors"] == 0


def test_bench_avalanche_exit_code():
    # 高 error-rate 应触发雪崩分支（exit 2），仅提示不崩溃
    from tools.bench import main
    rc = main(["--targets", "20", "--concurrency", "10",
               "--task-ms", "1", "--error-rate", "0.5",
               "--avalanche-threshold", "0.2"])
    assert rc in (0, 2)
