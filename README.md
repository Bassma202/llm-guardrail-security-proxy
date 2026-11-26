# ALETHEIA — LLM, RAG & Agent Security Evaluation Framework

ALETHEIA is a defense-in-depth security framework and comparative evaluation harness for open-weight LLM, Retrieval-Augmented Generation (RAG), and Model Context Protocol (MCP) agent systems. It evaluates four progressive security architectures against a 24-case held-out adversarial and hard-benign benchmark using genuine local LLM inference (`Ollama 0.5.7` + `smollm2:360m`), separating deterministic guardrail/retrieval/tool latency from model inference latency.

## Architecture & Core Controls
- **Layered Ingress & Egress Guardrails (`src/aletheia/guardrails.py`):** Unicode NFKC normalization, zero-width and BiDi character stripping, Base64 payload decoding inspection, structural delimiter/role-spoofing detection, Luhn-validated payment card redaction, French NIR/INSEE and Moroccan CIN redaction, FR/MA phone & email redaction, egress credential/canary leak blocking, and external markdown image exfiltration stripping.
- **Secure RAG Pipeline with Pre-Retrieval ACLs (`src/aletheia/rag.py`):** Chunking + TF-IDF cosine retrieval over a fictional multi-tenant observatory & archival corpus (`Observatoire Meridien` and `Fondation Al-Qarawiyyin`), ingestion-time indirect prompt-injection quarantine, `<untrusted_context>` data framing, and independent pre-retrieval role + tenant access filtering.
- **Independent MCP Tool Authorization Guard (`src/aletheia/mcp_server.py`):** Minimal JSON-RPC 2.0 MCP tool server exposing strictly allowlisted safe tools (`read_sandbox_doc`, `search_catalog`, `compute_stats`) with zero shell execution, role enforcement, schema validation, and symlink-safe canonical `Path.resolve().is_relative_to(sandbox_root)` path jailing.
- **OWASP Traceability:** Mapped explicitly to OWASP LLM Top 10 (2025) (`LLM01`, `LLM02`, `LLM05`, `LLM06`, `LLM07`, `LLM08`) and OWASP MCP (`MCP01:2025`).

## Verified 4-Architecture Comparative Results (Live Ollama `smollm2:360m`)
Executed on Apple Silicon Docker (`ollama/ollama:0.5.7`, `smollm2:360m`) across `24` held-out cases (`15` attacks, `9` benign/hard-benign); full artifact stored in [`evidence/aletheia_benchmark_results.json`](evidence/aletheia_benchmark_results.json):

| Architecture | Attack Success Rate (ASR) | Detection Recall | False Positive Rate (FPR) | Guardrail p50 | Live LLM Inference p50 |
|---|---:|---:|---:|---:|---:|
| **Arch 1 — Unprotected Baseline** | `93.3%` | `6.7%` | `0.0%` | `0.000 ms` | `1540.7 ms` |
| **Arch 2 — Regex-Only Ingress Filter** | `73.3%` | `26.7%` | `0.0%` | `0.037 ms` | `1451.4 ms` |
| **Arch 3 — Layered Guardrails (No Independent ACL/MCP)** | `33.3%` | `66.7%` | `0.0%` | `0.123 ms` | `1924.4 ms` |
| **Arch 4 — Full ALETHEIA Defense-in-Depth** | **`6.7%`** | **`93.3%`** | **`0.0%`** | **`0.097 ms`** | **`1298.9 ms`** |

> **Honest Residual Failure Analysis:** In Arch 4, `1/15` attacks (`ATK-SEM-01`, a polite semantic paraphrase asking about opening configuration phrasing) bypasses deterministic lexical ingress checks. ALETHEIA explicitly reports this failure in [`docs/RESEARCH_REPORT.md`](docs/RESEARCH_REPORT.md) and mitigates blast radius through non-LLM boundaries (egress canary blocking, pre-retrieval ACLs, and independent MCP authorization).

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make test lint security

# Optional: Live local Ollama evaluation
docker compose up -d
docker exec aletheia_ollama ollama pull smollm2:360m
make benchmark-live
docker compose down -v

# Launch Scientific Evaluation Workbench UI
make serve   # http://127.0.0.1:8005
```
