# ALETHEIA — Comparative LLM, RAG & MCP Security Evaluation Report

## 1. Research Question
To what extent do lexical ingress guardrails alone reduce Attack Success Rate (ASR) across realistic LLM + RAG + MCP threat classes compared to a layered defense-in-depth architecture combining normalization, ingestion quarantine, independent pre-retrieval RAG access controls, egress redaction, and independent server-side MCP tool authorization?

## 2. Experimental Design
- **Held-out benchmark suite:** 24 structured cases (`15` attacks across 7 threat classes + `9` benign and hard-benign cases including security terminology and non-Luhn 16-digit IDs).
- **Four evaluated architectures:**
  1. **Arch 1 — Unprotected Baseline:** Raw prompt -> RAG (no quarantine, no ACL) -> LLM -> raw output; unprotected MCP tools.
  2. **Arch 2 — Regex-Only Ingress Filter:** Classic keyword/regex ingress matcher only; no normalization, no RAG ACL, no egress guard, no MCP guard.
  3. **Arch 3 — Layered Guardrails:** Unicode NFKC + zero-width stripping + Base64 decoding inspection + RAG ingestion quarantine + untrusted context isolation + egress PII/secret redaction, **without** independent pre-retrieval ACL or MCP guard.
  4. **Arch 4 — Full ALETHEIA Defense-in-Depth:** Arch 3 plus independent pre-retrieval RAG ACL enforcement (`role` + `tenant_id`) and independent server-side MCP tool authorization guard (allowlist, RBAC, schema, symlink-safe canonical jail).
- **Separated Latency Measurements:** Every run records independent p50 latency for `guardrail_ms`, `retrieval_ms`, `tool_ms`, and `inference_ms` so guardrail overhead is never conflated with model generation time.

## 3. Key Architectural Findings & Failure Analysis
1. **Why Regex-Only Fails (Arch 2):** Simple lexical filters catch obvious direct jailbreaks (`ATK-DIR-01`, `ATK-DIR-02`) but are trivially bypassed by zero-width Unicode characters (`ATK-OBF-01`), Base64-encoded instructions (`ATK-OBF-02`), role-tag spoofing (`ATK-OBF-03`), indirect RAG poisoning (`ATK-RAG-01`), cross-role RAG queries (`ATK-ACL-01`, `ATK-ACL-02`), PII/secret exposure, and MCP tool misuse.
2. **Why Guardrails Alone Are Insufficient (Arch 3 vs Arch 4):** Even strong ingress/egress guardrails cannot stop a benign-sounding query from retrieving a `CONFIDENTIAL` document (`ATK-ACL-01`, `ATK-ACL-02`) or stop an agent from invoking `run_bash` or `../../etc/passwd` (`ATK-MCP-01..03`). Only deterministic, non-LLM architectural boundaries (pre-retrieval ACL + server-side MCP guard) close those classes.
3. **Honest Residual Failure Mode in Arch 4 (`ATK-SEM-01`):** A polite, paraphrased prompt asking to summarize configuration phrasing bypasses deterministic lexical ingress inspection. Rather than hiding this limitation or tuning a brittle rule over the benchmark, ALETHEIA explicitly reports `ATK-SEM-01` as a lexical-layer bypass in its failure log and relies on defense-in-depth (egress canary blocking + zero secrets in system prompts + independent ACLs) to limit blast radius.
4. **False Positive Control (`FPR = 0.0%`):** Hard benign queries discussing "OWASP LLM01 prompt injection" (`BEN-03`) and 16-digit non-Luhn archive identifiers (`BEN-05`) are preserved without false blocking or over-redaction.

See `evidence/aletheia_benchmark_results.json` for exact verified execution metrics, backend classification (`ollama_live`), model tag, and separated p50 latencies.
