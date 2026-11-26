"""Model Context Protocol (MCP) JSON-RPC 2.0 tool server with independent tool authorization guard."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Strictly allowlisted safe research tools (no arbitrary shell execution permitted)
TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "read_sandbox_doc": {
        "required_roles": {"RESEARCHER", "ARCHIVIST", "ADMIN"},
        "required_args": {"filename": str},
        "max_arg_len": 120,
        "description": "Read a permitted research document strictly inside the canonical sandbox directory.",
    },
    "search_catalog": {
        "required_roles": {"GUEST", "RESEARCHER", "ARCHIVIST", "ADMIN"},
        "required_args": {"query": str},
        "max_arg_len": 160,
        "description": "Search the fictional Observatory & Heritage public catalog metadata.",
    },
    "compute_stats": {
        "required_roles": {"RESEARCHER", "ARCHIVIST", "ADMIN"},
        "required_args": {"values": list},
        "max_arg_len": 64,
        "description": "Compute basic summary statistics (count, mean, min, max) on bounded numeric arrays.",
    },
}

_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_./-]+$")


@dataclass
class MCPToolResult:
    allowed: bool
    tool_name: str
    reason: str
    output: dict[str, Any] | None = None
    owasp_ref: str = "MCP01:2025 / LLM06:2025"


class MCPAuthorizationGuard:
    """Independent server-side policy enforcement point for MCP tool calls.

    Enforces:
    1. Strict tool allowlist (blocks arbitrary shell/exec tools unconditionally).
    2. Role-based authorization independent of model intent.
    3. Strict argument type, schema, and size validation.
    4. Symlink-safe canonical Path.resolve().is_relative_to(sandbox_root) jail.
    """

    def __init__(self, sandbox_root: Path) -> None:
        self.sandbox_root = sandbox_root.resolve()
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self._seed_sandbox_files()

    def _seed_sandbox_files(self) -> None:
        catalog = {
            "public_star_chart.txt": "Observatoire Meridien (Fictional): Vega photometric magnitude 0.03, spectral class A0V.",
            "restoration_schedule.txt": "Fondation Al-Qarawiyyin (Fictional): Folio 14B humidity stabilized at 46% RH.",
        }
        for name, content in catalog.items():
            p = self.sandbox_root / name
            if not p.exists():
                p.write_text(content, encoding="utf-8")

    def validate_and_execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        caller_role: str = "RESEARCHER",
        enforce_guard: bool = True,
    ) -> MCPToolResult:
        if not enforce_guard:
            # Architecture 1 baseline simulation: demonstrates vulnerability when no independent guard exists
            if tool_name in {"run_bash", "execute_command", "shell"}:
                return MCPToolResult(
                    allowed=True,
                    tool_name=tool_name,
                    reason="UNPROTECTED_BASELINE_WOULD_EXECUTE_SHELL",
                    output={"simulated_unsafe_execution": True, "command": str(arguments.get("command", ""))[:80]},
                )
            if tool_name == "read_sandbox_doc" and ".." in str(arguments.get("filename", "")):
                return MCPToolResult(
                    allowed=True,
                    tool_name=tool_name,
                    reason="UNPROTECTED_BASELINE_PATH_TRAVERSAL_SUCCEEDED",
                    output={"simulated_traversal_path": str(arguments.get("filename", ""))},
                )

        if tool_name not in TOOL_SCHEMAS:
            return MCPToolResult(
                allowed=False,
                tool_name=tool_name,
                reason=f"TOOL_NOT_ALLOWLISTED:{tool_name}",
            )

        schema = TOOL_SCHEMAS[tool_name]
        if caller_role not in schema["required_roles"]:
            return MCPToolResult(
                allowed=False,
                tool_name=tool_name,
                reason=f"INSUFFICIENT_ROLE:{caller_role}",
            )

        if not isinstance(arguments, dict):
            return MCPToolResult(allowed=False, tool_name=tool_name, reason="INVALID_ARGUMENTS_NOT_OBJECT")

        for arg_name, arg_type in schema["required_args"].items():
            if arg_name not in arguments or not isinstance(arguments[arg_name], arg_type):
                return MCPToolResult(
                    allowed=False,
                    tool_name=tool_name,
                    reason=f"SCHEMA_MISMATCH:{arg_name}",
                )

        if tool_name == "read_sandbox_doc":
            filename = arguments["filename"]
            if len(filename) > schema["max_arg_len"] or not _SAFE_FILENAME_RE.match(filename):
                return MCPToolResult(allowed=False, tool_name=tool_name, reason="INVALID_FILENAME_SYNTAX")
            if ".." in Path(filename).parts or filename.startswith("/") or filename.startswith("\\"):
                return MCPToolResult(allowed=False, tool_name=tool_name, reason="PATH_TRAVERSAL_BLOCKED")
            candidate = (self.sandbox_root / filename).resolve()
            if not candidate.is_relative_to(self.sandbox_root):
                return MCPToolResult(allowed=False, tool_name=tool_name, reason="SANDBOX_ESCAPE_BLOCKED")
            if not candidate.is_file():
                return MCPToolResult(allowed=False, tool_name=tool_name, reason="SANDBOX_FILE_NOT_FOUND")
            return MCPToolResult(
                allowed=True,
                tool_name=tool_name,
                reason="TOOL_EXECUTED",
                output={"filename": filename, "content": candidate.read_text(encoding="utf-8")},
            )

        if tool_name == "search_catalog":
            query = arguments["query"].strip()
            if not query or len(query) > schema["max_arg_len"]:
                return MCPToolResult(allowed=False, tool_name=tool_name, reason="INVALID_QUERY_LENGTH")
            hits = []
            for file_path in sorted(self.sandbox_root.glob("*.txt")):
                txt = file_path.read_text(encoding="utf-8")
                if query.lower() in txt.lower() or query.lower() in file_path.name.lower():
                    hits.append({"file": file_path.name, "snippet": txt[:140]})
            return MCPToolResult(
                allowed=True,
                tool_name=tool_name,
                reason="TOOL_EXECUTED",
                output={"query": query, "matches": hits},
            )

        if tool_name == "compute_stats":
            vals = arguments["values"]
            if not vals or len(vals) > schema["max_arg_len"] or not all(isinstance(v, (int, float)) for v in vals):
                return MCPToolResult(allowed=False, tool_name=tool_name, reason="INVALID_NUMERIC_ARRAY")
            return MCPToolResult(
                allowed=True,
                tool_name=tool_name,
                reason="TOOL_EXECUTED",
                output={
                    "count": len(vals),
                    "mean": round(sum(vals) / len(vals), 4),
                    "min": min(vals),
                    "max": max(vals),
                },
            )

        return MCPToolResult(allowed=False, tool_name=tool_name, reason="UNHANDLED_TOOL")

    def handle_jsonrpc(self, payload: dict[str, Any], caller_role: str = "RESEARCHER") -> dict[str, Any]:
        """Minimal JSON-RPC 2.0 MCP tool endpoint (tools/list and tools/call)."""
        req_id = payload.get("id", 1)
        method = payload.get("method", "")
        if method == "tools/list":
            tools = [
                {"name": name, "description": meta["description"], "roles": sorted(meta["required_roles"])}
                for name, meta in TOOL_SCHEMAS.items()
            ]
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}
        if method == "tools/call":
            params = payload.get("params", {})
            res = self.validate_and_execute(
                tool_name=str(params.get("name", "")),
                arguments=params.get("arguments", {}),
                caller_role=caller_role,
                enforce_guard=True,
            )
            if not res.allowed:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32003, "message": res.reason, "data": {"owasp": res.owasp_ref}},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(res.output)}]},
            }
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}
