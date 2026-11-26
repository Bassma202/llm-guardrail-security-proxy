"""Multi-layered LLM ingress/egress guardrails, obfuscation normalization, and Luhn-verified PII/secret redaction."""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width and bidirectional override characters frequently used to evade lexical filters
_INVISIBLE_CHARS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")

OWASP_LLM_2025_CONTROLS = {
    "LLM01:2025": {
        "title": "Prompt Injection",
        "controls": [
            "Unicode NFKC & zero-width normalization + Base64 payload decoding inspection",
            "Role-spoofing & structural delimiter detection",
            "Untrusted RAG context isolation markers (<untrusted_document>)",
        ],
    },
    "LLM02:2025": {
        "title": "Sensitive Information Disclosure",
        "controls": [
            "Ingress & egress multi-jurisdiction PII redaction (Email, FR/MA phone, FR NIR, MA CIN, Luhn payment cards)",
            "Egress secret/credential leak blocker (API keys, PEM keys, bearer tokens)",
            "Pre-retrieval RAG ACL filtering by caller role and tenant",
        ],
    },
    "LLM05:2025": {
        "title": "Improper Output Handling",
        "controls": [
            "Markdown image exfiltration URL stripping on egress",
            "Structured JSON output bounds for tool invocations",
        ],
    },
    "LLM06:2025": {
        "title": "Excessive Agency",
        "controls": [
            "Independent MCP tool authorization guard (strict allowlist, no arbitrary shell)",
            "Canonical path jail and schema validation prior to tool execution",
        ],
    },
    "LLM07:2025": {
        "title": "System Prompt Leakage",
        "controls": [
            "System prompt extraction heuristics and canary marker detection on egress",
        ],
    },
    "LLM08:2025": {
        "title": "Vector and Embedding Weaknesses",
        "controls": [
            "Ingestion-time indirect prompt injection scanner with document quarantine",
            "Pre-retrieval role/tenant metadata ACL enforcement",
        ],
    },
    "MCP01:2025": {
        "title": "Tool Poisoning & Confused Deputy Execution",
        "controls": [
            "Server-side capability allowlist + role verification independent of model output",
            "Symlink-safe Path.resolve() sandbox verification and execution timeout",
        ],
    },
}

_BASELINE_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|guidelines|rules)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(rules|guidelines|instructions)",
    r"you\s+are\s+now\s+in\s+dan\s+mode",
    r"do\s+anything\s+now",
    r"reveal\s+(your\s+)?system\s+prompt",
    r"print\s+(your\s+)?initial\s+instructions",
    r"bypass\s+all\s+safety\s+guidelines",
]

_LAYERED_STRUCTURAL_PATTERNS = _BASELINE_INJECTION_PATTERNS + [
    r"(?:override|reset|forget)\s+(?:your\s+)?(?:system|safety|security)\s+(?:policy|prompt|rules|constraints)",
    r"<\s*/?\s*(?:system|assistant|developer|instruction)\s*>",
    r"\[(?:system\s+note|hidden\s+instruction|developer\s+override)\s*:",
    r"important\s+instruction\s+for\s+ai\s+assistant",
    r"exfiltrate\s+(?:secrets|credentials|tokens|records|data)",
    r"!\[[^\]]*\]\(https?://[^\s)]+(?:\?[^)]*)?\)",
    r"output\s+the\s+(?:exact\s+)?(?:system\s+prompt|hidden\s+rules|canary\s+token)",
]

_SECRET_PATTERNS = {
    "OPENAI_STYLE_KEY": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "PEM_PRIVATE_KEY": re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
    "SYSTEM_CANARY": re.compile(r"\bALETHEIA_INTERNAL_CANARY_[A-Z0-9]+\b"),
}

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_FR_MA_RE = re.compile(r"(?<!\d)(?:\+(?:212|33)[\s.-]?|0)[567](?:[\s.-]?\d{2}){4}(?!\d)")
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_FR_NIR_RE = re.compile(r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}(?:\s?\d{2})?\b")
_MA_CIN_RE = re.compile(r"\b(?:CIN[:\s#-]*)([A-Z]{1,2}\d{5,6})\b")
_MD_EXFIL_RE = re.compile(r"!\[[^\]]*\]\(https?://[^\s)]+\)")


def luhn_valid(number_str: str) -> bool:
    """Validate candidate payment card numbers using the Luhn checksum algorithm."""
    digits = [int(ch) for ch in number_str if ch.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        val = digit
        if idx % 2 == parity:
            val *= 2
            if val > 9:
                val -= 9
        checksum += val
    return checksum % 10 == 0


def normalize_text(text: str) -> tuple[str, list[str]]:
    """Apply Unicode NFKC normalization, invisible character stripping, and safe Base64 inspection."""
    signals: list[str] = []
    if _INVISIBLE_CHARS_RE.search(text):
        signals.append("INVISIBLE_UNICODE_STRIPPED")
    cleaned = _INVISIBLE_CHARS_RE.sub("", text)
    normalized = unicodedata.normalize("NFKC", cleaned)
    if normalized != cleaned:
        signals.append("UNICODE_NFKC_NORMALIZED")

    # Decode suspicious Base64 blocks for inspection (without executing)
    decoded_fragments: list[str] = []
    for match in _BASE64_TOKEN_RE.findall(normalized):
        try:
            raw = base64.b64decode(match, validate=True)
            decoded = raw.decode("utf-8")
            if sum(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded) / max(1, len(decoded)) > 0.85:
                decoded_fragments.append(decoded)
                signals.append("BASE64_TEXT_DECODED_FOR_INSPECTION")
        except Exception:
            continue

    combined = normalized if not decoded_fragments else f"{normalized}\n[DECODED_B64]: " + " ".join(decoded_fragments)
    return combined, signals


def redact_pii_and_secrets(text: str) -> tuple[str, list[str]]:
    """Redact multi-jurisdiction PII (Luhn-validated cards, FR NIR, MA CIN, FR/MA phone, email) and secrets."""
    redactions: list[str] = []
    out = text

    for label, pattern in _SECRET_PATTERNS.items():
        if pattern.search(out):
            out = pattern.sub(f"[REDACTED_{label}]", out)
            redactions.append(label)

    if _EMAIL_RE.search(out):
        out = _EMAIL_RE.sub("[REDACTED_EMAIL]", out)
        redactions.append("EMAIL")

    if _PHONE_FR_MA_RE.search(out):
        out = _PHONE_FR_MA_RE.sub("[REDACTED_PHONE_FR_MA]", out)
        redactions.append("PHONE_FR_MA")

    if _FR_NIR_RE.search(out):
        out = _FR_NIR_RE.sub("[REDACTED_FR_NIR]", out)
        redactions.append("FR_NIR")

    if _MA_CIN_RE.search(out):
        out = _MA_CIN_RE.sub("CIN:[REDACTED_MA_CIN]", out)
        redactions.append("MA_CIN")

    def _replace_card(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if luhn_valid(candidate):
            if "PAYMENT_CARD_LUHN" not in redactions:
                redactions.append("PAYMENT_CARD_LUHN")
            return "[REDACTED_PAYMENT_CARD]"
        return candidate

    out = _CARD_CANDIDATE_RE.sub(_replace_card, out)
    return out, redactions


@dataclass
class GuardrailDecision:
    allowed: bool
    sanitized_text: str
    reason: str
    risk_score: float = 0.0
    signals: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)


class RegexOnlyGuardrail:
    """Architecture 2 baseline: naive regex-only ingress filter (no normalization, no egress or RAG ACL)."""

    def inspect_ingress(self, prompt: str) -> GuardrailDecision:
        for pat in _BASELINE_INJECTION_PATTERNS:
            if re.search(pat, prompt, re.IGNORECASE):
                return GuardrailDecision(
                    allowed=False,
                    sanitized_text="",
                    reason="REGEX_INJECTION_MATCH",
                    risk_score=0.9,
                    signals=[pat],
                )
        return GuardrailDecision(allowed=True, sanitized_text=prompt, reason="ALLOWED", risk_score=0.0)

    def inspect_egress(self, response: str) -> GuardrailDecision:
        return GuardrailDecision(allowed=True, sanitized_text=response, reason="NO_EGRESS_FILTER")


class LayeredGuardrail:
    """Architecture 3/4 defense: Unicode/Base64 normalization, structural injection detection, PII/secret redaction."""

    def inspect_ingress(self, prompt: str) -> GuardrailDecision:
        normalized, signals = normalize_text(prompt)
        matched_rules: list[str] = []
        for pat in _LAYERED_STRUCTURAL_PATTERNS:
            if re.search(pat, normalized, re.IGNORECASE):
                matched_rules.append(pat)

        if matched_rules:
            return GuardrailDecision(
                allowed=False,
                sanitized_text="",
                reason="LAYERED_PROMPT_INJECTION_BLOCKED",
                risk_score=min(1.0, 0.75 + 0.1 * len(matched_rules)),
                signals=signals + [f"RULE_MATCH:{len(matched_rules)}"],
            )

        sanitized, redactions = redact_pii_and_secrets(prompt)
        return GuardrailDecision(
            allowed=True,
            sanitized_text=sanitized,
            reason="INGRESS_SAFE",
            risk_score=0.1 if redactions else 0.0,
            signals=signals,
            redactions=redactions,
        )

    def inspect_egress(self, response: str) -> GuardrailDecision:
        signals: list[str] = []
        out = response

        for label, pattern in _SECRET_PATTERNS.items():
            if pattern.search(out):
                return GuardrailDecision(
                    allowed=False,
                    sanitized_text="[BLOCKED BY ALETHEIA EGRESS GUARD: CREDENTIAL OR CANARY EXPOSURE]",
                    reason=f"EGRESS_SECRET_BLOCKED:{label}",
                    risk_score=1.0,
                    signals=[label],
                )

        if _MD_EXFIL_RE.search(out):
            out = _MD_EXFIL_RE.sub("[STRIPPED_EXTERNAL_IMAGE_TAG]", out)
            signals.append("MARKDOWN_EXFIL_STRIPPED")

        out, redactions = redact_pii_and_secrets(out)
        if redactions:
            signals.append("EGRESS_PII_REDACTED")

        return GuardrailDecision(
            allowed=True,
            sanitized_text=out,
            reason="EGRESS_SAFE",
            risk_score=0.2 if signals else 0.0,
            signals=signals,
            redactions=redactions,
        )
