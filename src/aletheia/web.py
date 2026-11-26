"""ALETHEIA Scientific Evaluation Web Interface (Midnight Navy / Ivory / Brass palette)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from aletheia.evaluator import run_comparative_benchmark
from aletheia.guardrails import OWASP_LLM_2025_CONTROLS, LayeredGuardrail
from aletheia.llm_client import LocalLLMClient
from aletheia.mcp_server import MCPAuthorizationGuard
from aletheia.rag import SecureRAGPipeline


class PromptEvalRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
    caller_role: str = Field(default="GUEST")
    tenant_id: str | None = Field(default="observatoire-meridien")
    use_rag: bool = Field(default=True)
    enforce_pre_retrieval_acl: bool = Field(default=True)


class MCPCallRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    caller_role: str = Field(default="RESEARCHER")


def create_app(sandbox_root: Path | None = None, evidence_path: Path | None = None) -> FastAPI:
    app = FastAPI(title="ALETHEIA — LLM, RAG & Agent Security Evaluation Framework", version="2.0.0")
    root = Path(__file__).resolve().parents[2]
    sb = sandbox_root or (root / "data" / "mcp_sandbox")
    ev_path = evidence_path or (root / "evidence" / "aletheia_benchmark_results.json")

    guard = LayeredGuardrail()
    rag = SecureRAGPipeline(quarantine_poisoned=True)
    mcp = MCPAuthorizationGuard(sb)
    llm = LocalLLMClient(allow_fallback_stub=True)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "aletheia",
            "ollama_live_available": llm.is_ollama_available(),
            "model": llm.model,
        }

    @app.get("/api/owasp")
    def get_owasp() -> dict[str, Any]:
        return {"mappings": OWASP_LLM_2025_CONTROLS}

    @app.get("/api/benchmark")
    def get_benchmark() -> dict[str, Any]:
        if ev_path.exists():
            return json.loads(ev_path.read_text(encoding="utf-8"))
        return run_comparative_benchmark(sb, llm_client=llm, force_live=False)

    @app.post("/api/evaluate-prompt")
    def evaluate_prompt(req: PromptEvalRequest) -> dict[str, Any]:
        ingress = guard.inspect_ingress(req.prompt)
        if not ingress.allowed:
            return {
                "allowed": False,
                "stage": "INGRESS_GUARDRAIL",
                "reason": ingress.reason,
                "signals": ingress.signals,
                "risk_score": ingress.risk_score,
            }
        chunks = (
            rag.retrieve(
                ingress.sanitized_text,
                caller_role=req.caller_role,
                tenant_id=req.tenant_id,
                enforce_pre_retrieval_acl=req.enforce_pre_retrieval_acl,
            )
            if req.use_rag
            else []
        )
        ctx = rag.format_isolated_context(chunks) if req.use_rag else ""
        resp = llm.generate(ingress.sanitized_text, context_block=ctx)
        egress = guard.inspect_egress(resp.text)
        return {
            "allowed": egress.allowed,
            "stage": "COMPLETE",
            "backend_mode": resp.backend_mode,
            "model": resp.model,
            "inference_ms": resp.inference_ms,
            "sanitized_prompt": ingress.sanitized_text,
            "ingress_redactions": ingress.redactions,
            "retrieved_docs": [{"doc_id": c["doc_id"], "access_level": c["access_level"], "score": c["score"]} for c in chunks],
            "output": egress.sanitized_text,
            "egress_reason": egress.reason,
            "egress_signals": egress.signals,
        }

    @app.post("/api/mcp/call")
    def call_mcp(req: MCPCallRequest) -> dict[str, Any]:
        res = mcp.validate_and_execute(req.tool_name, req.arguments, caller_role=req.caller_role, enforce_guard=True)
        return {
            "allowed": res.allowed,
            "tool_name": res.tool_name,
            "reason": res.reason,
            "output": res.output,
            "owasp_ref": res.owasp_ref,
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        bench = json.loads(ev_path.read_text(encoding="utf-8")) if ev_path.exists() else run_comparative_benchmark(sb, llm_client=llm)
        rows = ""
        for _, r in bench["architectures"].items():
            m = r["metrics"]
            lat = r["latency_ms"]
            rows += (
                f"<tr><td><strong>{r['label']}</strong></td>"
                f"<td>{m['attack_success_rate_pct']}%</td>"
                f"<td>{m['detection_recall_pct']}%</td>"
                f"<td>{m['false_positive_rate_pct']}%</td>"
                f"<td>{lat['guardrail_p50_ms']} ms</td>"
                f"<td>{lat['inference_p50_ms']} ms</td>"
                f"<td>{len(r['failures'])}</td></tr>"
            )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ALETHEIA — LLM, RAG &amp; Agent Security Evaluation</title>
<style>
  body {{ margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#FAF9F6; color:#0F172A; }}
  header {{ background:#0F172A; color:#FAF9F6; padding:24px 36px; border-bottom:3px solid #B48A3E; }}
  header h1 {{ margin:0; font-size:22px; letter-spacing:0.06em; }}
  header p {{ margin:6px 0 0; color:#94A3B8; font-size:13px; }}
  main {{ max-width:1120px; margin:28px auto; padding:0 24px; }}
  .card {{ background:#FFFFFF; border:1px solid #E2E8F0; border-radius:6px; padding:20px 24px; margin-bottom:20px; }}
  .badge {{ display:inline-block; font-size:11px; padding:3px 8px; border-radius:4px; background:#0F172A; color:#E2C785; letter-spacing:0.04em; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:14px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #E2E8F0; }}
  th {{ background:#F8FAFC; color:#475569; font-weight:600; font-size:12px; text-transform:uppercase; }}
  .note {{ font-size:13px; color:#475569; border-left:3px solid #B48A3E; padding-left:12px; margin-top:12px; }}
</style>
</head>
<body>
<header>
  <h1>ALETHEIA — LLM, RAG &amp; Agent Security Evaluation Framework</h1>
  <p>Evidence Classification: {bench['evidence_classification']} | Held-Out Suite: {bench['benchmark_cases']} cases ({bench['attack_cases']} attacks, {bench['benign_cases']} benign)</p>
</header>
<main>
  <section class="card">
    <span class="badge">4-ARCHITECTURE COMPARATIVE ABLATION</span>
    <h2>Security Efficacy &amp; Separated Latency Decomposition</h2>
    <table>
      <thead>
        <tr>
          <th>Architecture</th><th>Attack Success Rate (ASR)</th><th>Detection Recall</th>
          <th>False Positive Rate</th><th>Guardrail p50</th><th>Inference p50</th><th>Residual Failures</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <p class="note">
      <strong>Engineering finding:</strong> Regex-only ingress filters fail on zero-width Unicode obfuscation, Base64 payloads,
      indirect RAG poisoning, cross-role RAG queries, and MCP confused-deputy calls. Even full ALETHEIA documents its residual
      limitation on polite semantic extraction paraphrases (ATK-SEM-01), where system integrity relies on egress canary blocking
      and independent pre-retrieval ACLs rather than lexical prompt classification alone.
    </p>
  </section>
</main>
</body>
</html>"""

    return app
