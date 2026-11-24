"""
AI Security Guardrail & Ingress/Egress Proxy
Author: Bassma Alaoui Sossey
Protects LLM applications against OWASP LLM Top 10 vulnerabilities:
- LLM01: Prompt Injection (Direct & Jailbreak heuristics)
- LLM02: Insecure Output Handling
- LLM06: Sensitive Information Disclosure (PII Redaction)
"""

import re
from typing import Dict, Any, Tuple, List

class LLMGuardrailProxy:
    def __init__(self):
        # Known prompt injection heuristics and jailbreak patterns
        self.jailbreak_patterns = [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|guidelines|rules)",
            r"disregard\s+(all\s+)?(previous|prior|above)\s+(rules|guidelines|instructions)",
            r"you\s+are\s+now\s+in\s+DAN\s+mode",
            r"do\s+anything\s+now",
            r"reveal\s+(your\s+)?system\s+prompt",
            r"print\s+(your\s+)?initial\s+instructions",
            r"roleplay\s+as\s+an\s+unfiltered\s+AI",
            r"bypass\s+all\s+safety\s+guidelines"
        ]
        
        # PII Detection Regex Patterns
        self.pii_patterns = {
            "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "PHONE_FR_MA": r"\b(?:\+?(?:212|33)|0)[1-9](?:[\s.-]?\d{2}){4}\b"
        }

    def inspect_ingress_prompt(self, user_prompt: str) -> Tuple[bool, str, str]:
        """
        Inspects incoming prompt for malicious prompt injection.
        Returns: (is_safe: bool, sanitized_prompt: str, reason: str)
        """
        # 1. Check for prompt injection / jailbreaks
        for pattern in self.jailbreak_patterns:
            if re.search(pattern, user_prompt, re.IGNORECASE):
                return False, "", f"PROMPT_INJECTION_DETECTED: Matched pattern '{pattern}'"

        # 2. Redact sensitive PII before transmission to LLM provider
        sanitized = user_prompt
        for pii_type, regex in self.pii_patterns.items():
            sanitized = re.sub(regex, f"[REDACTED_{pii_type}]", sanitized)

        return True, sanitized, "PROMPT_SAFE"

    def inspect_egress_output(self, model_response: str) -> Tuple[bool, str, str]:
        """
        Inspects model response before returning to user (prevents system leak or credential leaks).
        """
        system_leak_patterns = [
            r"ANTHROPIC_MAGIC_STRING",
            r"OPENAI_API_KEY",
            r"BEGIN PRIVATE KEY",
            r"sk-[a-zA-Z0-9]{20,}"
        ]
        for pattern in system_leak_patterns:
            if re.search(pattern, model_response, re.IGNORECASE):
                return False, "[REDACTED BY SECURITY PROXY: SENSITIVE_CREDENTIAL_LEAK]", "CREDENTIAL_EXPOSURE_BLOCKED"

        return True, model_response, "OUTPUT_SAFE"
