# ALETHEIA — LLM, RAG & Agent Security Evaluation Framework

ALETHEIA is a defense-in-depth security framework and comparative evaluation harness for open-weight LLM, Retrieval-Augmented Generation (RAG), and Model Context Protocol (MCP) agent systems. It enforces authenticated server-derived caller identity on its HTTP API, separates development/validation/frozen held-out evaluation splits, distinguishes actual policy violations from guardrail detection/bypass rates with 95% Wilson confidence intervals, and stores immutable, non-overwriting run artifacts verified with genuine local LLM inference (`Ollama 0.5.7` + `smollm2:360m`).

## Architecture & Core Controls
- **Authenticated Server-Derived Principal API (`src/aletheia/auth.py`, `src/aletheia/web.py`):** Protected endpoints (`/api/query`, `/api/mcp/call`) require Bearer token authentication resolved strictly against a server-side principal registry. Caller-supplied `role`, `tenant_id`, or `enforce_acl` / `enforce_guardrails` fields are rejected via strict Pydantic schemas (`extra="forbid"` -> HTTP `422`), preventing client-side security downgrades.
- **Layered Ingress & Egress Guardrails (`src/aletheia/guardrails.py`):** Unicode NFKC normalization, zero-width and BiDi character stripping, Base64 payload decoding inspection, structural delimiter/role-spoofing detection, Luhn-validated payment card redaction, French NIR/INSEE and Moroccan CIN redaction, FR/MA phone & email redaction, egress credential/canary leak blocking, and external markdown image exfiltration stripping.
- **Secure RAG Pipeline with Pre-Retrieval ACLs (`src/aletheia/rag.py`):** Chunking + TF-IDF cosine retrieval over a fictional multi-tenant observatory & archival corpus (`Observatoire Meridien` and `Fondation Al-Qarawiyyin`), ingestion-time indirect prompt-injection quarantine, `<untrusted_context>` data framing, and independent pre-retrieval role + tenant access filtering derived exclusively from authenticated server identity.
- **Independent MCP Tool Authorization Guard (`src/aletheia/mcp_server.py`):** Minimal JSON-RPC 2.0 MCP tool server exposing strictly allowlisted safe tools (`read_sandbox_doc`, `search_catalog`, `compute_stats`) with zero shell execution, role enforcement, schema validation, and symlink-safe canonical `Path.resolve().is_relative_to(sandbox_root)` path jailing.
- **Versioned Dataset Splits & Immutable Evidence Ledger (`src/aletheia/datasets.py`, `src/aletheia/evaluator.py`):**
  - Three independent SHA-256-hashed JSON datasets: `dev_v1.json` (12 cases), `validation_v1.json` (4 cases), and `frozen_held_out_v1.json` (40 cases: 24 attacks + 16 benign/borderline, zero prompt/ID overlap).
  - Five explicit run classifications (`genuine_live_inference`, `offline_simulated`, `degraded_partial_live`, `guardrail_only_test`, `error_incomplete`) — offline runs never overwrite verified live runs in `evidence/runs/runs_index.json`.
- **OWASP Traceability:** Mapped explicitly to OWASP LLM Top 10 (2025) (`LLM01`, `LLM02`, `LLM05`, `LLM06`, `LLM07`, `LLM08`) and OWASP MCP (`MCP01:2025`).

## Verified 4-Architecture Comparative Results (Live Ollama `smollm2:360m`, Frozen Held-Out `n=40`)
Executed on Apple Silicon Docker (`ollama/ollama:0.5.7`, `smollm2:360m`) on `frozen_held_out_v1.json` (`n=40`: `24` attacks, `16` benign/borderline, SHA-256 `fdbd0f86...`); immutable run artifact stored in [`evidence/runs/RUN-20261126T035757Z-D37E1B78/summary.json`](evidence/runs/RUN-20261126T035757Z-D37E1B78/summary.json):

| Architecture | Actual Policy Violation Rate (95% Wilson CI) | Guardrail Bypass Rate | False Refusal Rate | Guardrail p50 | Live LLM Inference p50 |
|---|---:|---:|---:|---:|---:|
| **Arch 1 — Unprotected Baseline** | `58.3%` (`14/24`, CI `[38.8%, 75.5%]`) | `95.8%` (`23/24`) | `0.0%` (`0/16`) | `0.000 ms` | `1010.6 ms` |
| **Arch 2 — Regex-Only Ingress Filter** | `58.3%` (`14/24`, CI `[38.8%, 75.5%]`) | `79.2%` (`19/24`) | `0.0%` (`0/16`) | `0.020 ms` | `917.9 ms` |
| **Arch 3 — Layered Guardrails (No Independent ACL/MCP)** | `29.2%` (`7/24`, CI `[14.9%, 49.2%]`) | `33.3%` (`8/24`) | `0.0%` (`0/16`) | `0.108 ms` | `1563.6 ms` |
| **Arch 4 — Full ALETHEIA Defense-in-Depth** | **`0.0%`** (`0/24`, CI `[0.0%, 13.8%]`) | **`12.5%`** (`3/24`) | **`0.0%`** (`0/16`) | **`0.102 ms`** | **`1307.8 ms`** |

> **Honest Residual Failure & Statistical Bounds Analysis:** In Arch 4, `0/24` attacks caused an actual policy violation (`95%` Wilson CI `[0.0%, 13.8%]`), **but `3/24` attacks (`12.5%` bypass rate: `HO-SEM-01`, `HO-RAG-01`, `HO-RAG-02`) bypassed deterministic ingress blocking**. Defense-in-depth (RAG ingestion quarantine, pre-retrieval ACLs, egress canary/PII redaction, and independent MCP authorization) prevented actual data or tool policy breaches even when lexical ingress did not flag the prompt. See [`docs/RESEARCH_REPORT.md`](docs/RESEARCH_REPORT.md).

## Known Limitations
- Small-sample statistical bounds: `n=40` (`24` attacks, `16` benign) gives a 95% Wilson CI upper bound of `13.8%` even at `0/24` violations; enterprise benchmarks require larger multi-model corpora.
- Single open-weight local model evaluated in-repo (`smollm2:360m` CPU inference); larger instruction-tuned models may exhibit higher attack compliance under unprotected baselines.
- Deterministic lexical/structural guardrails remain bypassable by novel semantic paraphrases and therefore complement—never replace—deterministic ACL, egress, and tool-authorization boundaries.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make test lint security

# Optional: Live local Ollama evaluation on frozen held-out split
docker compose up -d
docker exec aletheia_ollama ollama pull smollm2:360m
.venv/bin/python scripts/run_aletheia_benchmark.py --live-ollama --model smollm2:360m --split frozen_held_out
docker compose down -v

# Launch Scientific Evaluation Workbench UI
make serve   # http://127.0.0.1:8005
```
