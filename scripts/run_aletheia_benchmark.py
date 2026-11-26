#!/usr/bin/env python3
"""Run ALETHEIA 4-architecture evaluation into an immutable non-overwriting run directory (ALETHEIA-05)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aletheia.datasets import materialize_datasets  # noqa: E402
from aletheia.evaluator import run_comparative_benchmark  # noqa: E402
from aletheia.llm_client import LocalLLMClient  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ALETHEIA comparative LLM/RAG/MCP security benchmark.")
    parser.add_argument("--live-ollama", action="store_true", help="Require live Ollama inference (fail if unavailable).")
    parser.add_argument("--model", default=None, help="Ollama model tag (default: smollm2:360m).")
    parser.add_argument("--split", default="frozen_held_out", choices=["dev", "validation", "frozen_held_out"])
    args = parser.parse_args()

    materialize_datasets(ROOT / "datasets")
    client = LocalLLMClient(model=args.model, allow_fallback_stub=not args.live_ollama)
    summary = run_comparative_benchmark(
        sandbox_root=ROOT / "data" / "mcp_sandbox",
        datasets_dir=ROOT / "datasets",
        split=args.split,
        llm_client=client,
        force_live=args.live_ollama,
        runs_base_dir=ROOT / "evidence" / "runs",
    )

    print("=" * 94)
    print(f"ALETHEIA RUN {summary['run_id']} | class={summary['run_classification']} | split={args.split} (n={summary['dataset']['case_count']})")
    print("=" * 94)
    for _, r in summary["architectures"].items():
        m = r["metrics"]
        lat = r["latency_ms"]
        print(
            f"{r['label']:<55} | PolicyViol={m['actual_policy_violation_rate_pct']:>5.1f}% | "
            f"Bypass={m['guardrail_bypass_rate_pct']:>5.1f}% | FalseRef={m['false_refusal_rate_pct']:>4.1f}% | "
            f"Guard={lat['guardrail_p50_ms']:>5.3f}ms | LLM={lat['inference_p50_ms']:>7.1f}ms"
        )
    print("=" * 94)


if __name__ == "__main__":
    main()
