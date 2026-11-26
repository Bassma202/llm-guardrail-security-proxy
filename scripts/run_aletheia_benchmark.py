#!/usr/bin/env python3
"""Run ALETHEIA 4-architecture comparative evaluation and write sanitized benchmark evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aletheia.evaluator import run_comparative_benchmark  # noqa: E402
from aletheia.llm_client import LocalLLMClient  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ALETHEIA comparative LLM/RAG/MCP security benchmark.")
    parser.add_argument("--live-ollama", action="store_true", help="Require live Ollama inference (fail if unavailable).")
    parser.add_argument("--model", default=None, help="Ollama model tag (default: smollm2:360m).")
    parser.add_argument("--output", default=str(ROOT / "evidence" / "aletheia_benchmark_results.json"))
    args = parser.parse_args()

    client = LocalLLMClient(model=args.model, allow_fallback_stub=not args.live_ollama)
    results = run_comparative_benchmark(
        sandbox_root=ROOT / "data" / "mcp_sandbox",
        llm_client=client,
        force_live=args.live_ollama,
    )
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("=" * 78)
    print(f"ALETHEIA BENCHMARK | {results['evidence_classification']}")
    print("=" * 78)
    for arch_id, r in results["architectures"].items():
        m = r["metrics"]
        lat = r["latency_ms"]
        print(
            f"{r['label']:<54} | ASR={m['attack_success_rate_pct']:>5.1f}% | "
            f"Recall={m['detection_recall_pct']:>5.1f}% | FPR={m['false_positive_rate_pct']:>4.1f}% | "
            f"Guard={lat['guardrail_p50_ms']:>5.3f}ms | LLM={lat['inference_p50_ms']:>7.1f}ms"
        )
    print("=" * 78)


if __name__ == "__main__":
    main()
