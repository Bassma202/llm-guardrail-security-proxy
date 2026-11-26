# ALETHEIA — Threat Model & Trust Boundaries

## 1. System Scope
ALETHEIA evaluates and enforces defense-in-depth security controls for an open-weight LLM assistant connected to:
1. A multi-tenant Retrieval-Augmented Generation (RAG) corpus (`Observatoire Meridien` and `Fondation Al-Qarawiyyin`, both fictional).
2. A JSON-RPC 2.0 Model Context Protocol (MCP) tool server exposing bounded file-read, catalog-search, and statistics tools.
3. A local Ollama inference server (`ollama/ollama:0.5.7`).

## 2. Trust Boundaries
- **TB-1 (Untrusted User Ingress -> Layered Guardrail):** User prompts may contain direct prompt injections, invisible Unicode characters (zero-width spaces, BiDi overrides), Base64-encoded instructions, or PII/credentials.
- **TB-2 (Untrusted External Documents -> RAG Ingestion & Retrieval):** External documents may contain hidden indirect prompt injections or markdown image exfiltration payloads. Even trusted internal documents carry differing sensitivity tiers (`PUBLIC`, `RESTRICTED`, `CONFIDENTIAL`) and tenant labels.
- **TB-3 (LLM Output -> User & Downstream Tools):** Model outputs are treated as untrusted text. Neither prompt framing nor lexical guardrails guarantee the LLM will refuse every semantic attack; therefore, authorization decisions MUST never be delegated to the model.
- **TB-4 (Agent / Caller -> MCP Tool Server):** Tool invocations pass through an independent server-side `MCPAuthorizationGuard` enforcing an explicit tool allowlist, role check, strict schema validation, and symlink-safe canonical path jail (`Path.resolve().is_relative_to(sandbox_root)`).

## 3. OWASP LLM Top 10 (2025) & MCP Alignment
| Threat ID | Attack Class | Primary ALETHEIA Mitigation | Residual Limitation |
|---|---|---|---|
| `LLM01:2025` | Direct & Obfuscated Prompt Injection | NFKC + zero-width stripping + Base64 inspection + structural patterns | Polite semantic paraphrases can evade lexical ingress checks; mitigated in depth by egress canary checks and strict ACLs. |
| `LLM02:2025` | Sensitive Information Disclosure | Pre-retrieval RAG ACLs + ingress/egress Luhn card, FR NIR, MA CIN, FR/MA phone, email, and API key redaction | Unstructured free-text secrets without recognizable format require DLP/policy controls outside regex. |
| `LLM05:2025` | Improper Output Handling | Egress markdown image URL stripping + strict JSON tool schemas | Browser CSP and output encoding remain mandatory in downstream web clients. |
| `LLM06:2025` / `MCP01:2025` | Excessive Agency & Confused Deputy | Independent server-side MCP allowlist (no shell tools), RBAC, canonical symlink-safe jail | Assumes caller identity/role is verified upstream by an OIDC PEP (e.g., LIMEN). |
| `LLM07:2025` | System Prompt Leakage | Egress canary detection + prompt extraction pattern blocking | Canary matching detects verbatim leaks, not paraphrased disclosure of non-canary policy text. |
| `LLM08:2025` | Vector & Embedding Weaknesses | Ingestion-time indirect-injection quarantine + tenant/role metadata pre-filtering | Subtle domain-specific poisoning without injection syntax requires provenance signing and human review. |
