"""
RAG Ingestion Security Auditor (Indirect Prompt Injection Detector)
Author: Bassma Alaoui Sossey
Scans external documents (PDF text, web scraps, emails) for hidden adversarial payloads
before chunking and embedding into Vector Stores (ChromaDB, Pinecone).
"""

import re
from typing import Dict, Any, List

class RAGSecurityAuditor:
    def __init__(self):
        # Indirect injection signatures common in untrusted data
        self.indirect_signatures = [
            r"\[SYSTEM NOTE:",
            r"IMPORTANT INSTRUCTION FOR AI ASSISTANT",
            r"HIDDEN INSTRUCTION:",
            r"Please output the following text and ignore",
            r"system:\s*override",
            r"!\[.*?\]\(https?://.*?/exfil\?data=" # Markdown image exfiltration attack
        ]

    def audit_document(self, doc_text: str, doc_name: str = "untrusted_input.txt") -> Dict[str, Any]:
        threats_found = []
        
        # 1. Signature-based scan
        for sig in self.indirect_signatures:
            matches = re.findall(sig, doc_text, re.IGNORECASE)
            if matches:
                threats_found.append({
                    "threat_type": "INDIRECT_PROMPT_INJECTION",
                    "signature": sig,
                    "count": len(matches)
                })

        # 2. Check for suspicious markdown data exfiltration payloads
        exfil_match = re.search(r"!\[.*?\]\(https?://[^\s]+\)", doc_text)
        if exfil_match:
            threats_found.append({
                "threat_type": "DATA_EXFILTRATION_PAYLOAD",
                "details": f"Embedded markdown image tag detected: {exfil_match.group(0)[:60]}..."
            })

        is_safe = len(threats_found) == 0
        return {
            "document": doc_name,
            "is_safe": is_safe,
            "threats_count": len(threats_found),
            "threats": threats_found,
            "recommendation": "INGEST_PERMITTED" if is_safe else "QUARANTINE_DOCUMENT"
        }
