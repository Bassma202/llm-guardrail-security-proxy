"""ALETHEIA Protected Application API & Scientific Evaluation UI (Remediated ALETHEIA-01).

Strict architectural boundary:
- Protected endpoints (`/api/protected/query`, `/api/protected/mcp/call`) require verified Bearer
  authentication and derive caller role and tenant strictly server-side. Caller-supplied security
  flags (role, tenant, ACL toggle) are NOT accepted and cannot weaken policy enforcement.
- Research benchmark readouts (`/api/benchmark`) are read-only against immutable run artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from aletheia.auth import AletheiaAuthError, AletheiaAuthService, AletheiaPrincipal
from aletheia.guardrails import OWASP_LLM_2025_CONTROLS, LayeredGuardrail
from aletheia.llm_client import LocalLLMClient
from aletheia.mcp_server import MCPAuthorizationGuard
from aletheia.rag import SecureRAGPipeline


class ProtectedQueryRequest(BaseModel):
    """Strict protected request schema: forbids extra caller-supplied security overrides (ALETHEIA-01)."""

    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(..., min_length=1, max_length=4000)
    use_rag: bool = Field(default=True)


class ProtectedMCPCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


def _load_latest_benchmark(runs_dir: Path, fallback_legacy: Path) -> dict[str, Any] | None:
    idx_path = runs_dir / "runs_index.json"
    if idx_path.exists():
        idx = json.loads(idx_path.read_text(encoding="utf-8"))
        live_id = idx.get("latest_verified_live_run_id")
        if live_id and (runs_dir / live_id / "summary.json").exists():
            return json.loads((runs_dir / live_id / "summary.json").read_text(encoding="utf-8"))
        if idx.get("runs"):
            last_id = idx["runs"][-1]["run_id"]
            if (runs_dir / last_id / "summary.json").exists():
                return json.loads((runs_dir / last_id / "summary.json").read_text(encoding="utf-8"))
    if fallback_legacy.exists():
        return json.loads(fallback_legacy.read_text(encoding="utf-8"))
    return None


def create_app(
    sandbox_root: Path | None = None,
    runs_dir: Path | None = None,
    auth_service: AletheiaAuthService | None = None,
) -> FastAPI:
    app = FastAPI(title="ALETHEIA — LLM, RAG & Agent Security Evaluation Framework", version="2.1.0")
    root = Path(__file__).resolve().parents[2]
    sb = sandbox_root or (root / "data" / "mcp_sandbox")
    r_dir = runs_dir or (root / "evidence" / "runs")
    legacy_ev = root / "evidence" / "aletheia_benchmark_results.json"

    auth = auth_service or AletheiaAuthService()
    guard = LayeredGuardrail()
    rag = SecureRAGPipeline(quarantine_poisoned=True)
    mcp = MCPAuthorizationGuard(sb)
    llm = LocalLLMClient(allow_fallback_stub=True)

    app.state.auth = auth

    def require_principal(authorization: str | None = Header(default=None)) -> AletheiaPrincipal:
        try:
            return auth.verify_bearer(authorization)
        except AletheiaAuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "aletheia",
            "version": "2.1.0",
            "ollama_live_available": llm.is_ollama_available(),
            "model": llm.model,
        }

    @app.get("/api/owasp")
    def get_owasp() -> dict[str, Any]:
        return {"mappings": OWASP_LLM_2025_CONTROLS}

    @app.get("/api/benchmark")
    def get_benchmark() -> dict[str, Any]:
        data = _load_latest_benchmark(r_dir, legacy_ev)
        if not data:
            raise HTTPException(status_code=404, detail="No benchmark run artifacts available yet.")
        return data

    @app.post("/api/protected/query")
    def protected_query(
        req: ProtectedQueryRequest,
        principal: AletheiaPrincipal = Depends(require_principal),
    ) -> dict[str, Any]:
        """Protected RAG+LLM endpoint deriving role and tenant strictly server-side with mandatory ACL & guardrails."""
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
                caller_role=principal.role,
                tenant_id=principal.tenant_id,
                enforce_pre_retrieval_acl=True,
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
            "subject": principal.subject,
            "role": principal.role,
            "tenant_id": principal.tenant_id,
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

    @app.post("/api/protected/mcp/call")
    def protected_mcp_call(
        req: ProtectedMCPCallRequest,
        principal: AletheiaPrincipal = Depends(require_principal),
    ) -> dict[str, Any]:
        """Protected MCP tool endpoint deriving caller role strictly server-side with mandatory tool authorization guard."""
        res = mcp.validate_and_execute(req.tool_name, req.arguments, caller_role=principal.role, enforce_guard=True)
        if not res.allowed:
            raise HTTPException(status_code=403, detail={"reason": res.reason, "owasp_ref": res.owasp_ref})
        return {
            "allowed": True,
            "subject": principal.subject,
            "role": principal.role,
            "tool_name": res.tool_name,
            "reason": res.reason,
            "output": res.output,
            "owasp_ref": res.owasp_ref,
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        bench = _load_latest_benchmark(r_dir, legacy_ev)
        if not bench or "architectures" not in bench:
            return "<h1>ALETHEIA — Run benchmark to populate scientific dashboard.</h1>"
        rows = ""
        for _, r in bench["architectures"].items():
            m = r["metrics"]
            lat = r["latency_ms"]
            pvr = m.get("actual_policy_violation_rate_pct", m.get("attack_success_rate_pct", 0.0))
            gbr = m.get("guardrail_bypass_rate_pct", 0.0)
            fpr = m.get("false_refusal_rate_pct", m.get("false_positive_rate_pct", 0.0))
            rows += (
                f"<tr><td><strong>{r['label']}</strong></td>"
                f"<td>{pvr}%</td><td>{gbr}%</td><td>{fpr}%</td>"
                f"<td>{lat['guardrail_p50_ms']} ms</td><td>{lat['inference_p50_ms']} ms</td></tr>"
            )
        cls_label = bench.get("run_classification", bench.get("evidence_classification", "unknown"))
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ALETHEIA — LLM, RAG &amp; Agent Security Evaluation</title>
<style>
  body {{ margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#FAF9F6; color:#0F172A; }}
  header {{ background:#0F172A; color:#FAF9F6; padding:24px 36px; border-bottom:3px solid #B48A3E; }}
  header h1 {{ margin:0; font-size:22px; letter-spacing:0.06em; }}
  header p {{ margin:6px 0 0; color:#94A3B8; font-size:13px; }}
  main {{ max-width:1120px; margin:28px auto; padding:0 24px; }}
  .card {{ background:#FFFFFF; border:1px solid #E2E8F0; border-radius:6px; padding:20px 24px; margin-bottom:20px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:14px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #E2E8F0; }}
  th {{ background:#F8FAFC; color:#475569; font-weight:600; font-size:12px; text-transform:uppercase; }}
</style>
</head>
<body>
<header>
  <h1>ALETHEIA — LLM, RAG &amp; Agent Security Evaluation Framework</h1>
  <p>Run ID: {bench.get('run_id', 'legacy')} | Classification: {cls_label} | Protected API requires Bearer auth</p>
</header>
<main>
  <section class="card">
    <h2>4-Architecture Comparative Ablation (Policy Violations vs. Guardrail Bypasses)</h2>
    <table>
      <thead>
        <tr>
          <th>Architecture</th><th>Actual Policy Violation Rate</th><th>Guardrail Bypass Rate</th>
          <th>False Refusal Rate</th><th>Guardrail p50</th><th>Inference p50</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
</main>
</body>
</html>"""

    return app
