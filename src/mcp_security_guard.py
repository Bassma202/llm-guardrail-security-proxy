"""
Model Context Protocol (MCP) Tool Security & Sandbox Policy Enforcer
Author: Bassma Alaoui Sossey
Secures agentic AI workflows and MCP tool calls against Confused Deputy attacks,
directory traversal, dangerous shell commands, and privilege escalation.
"""

import os
import re
from typing import Dict, Any, Tuple

class MCPSecurityGuard:
    def __init__(self, sandbox_root: str = "/var/sandbox/data"):
        self.sandbox_root = os.path.abspath(sandbox_root)
        
        # Blocklist of high-risk shell commands
        self.dangerous_commands = [
            r"\brm\s+-rf\b", r"\bmkfs\b", r"\bdd\b", r":\(\)\{\s*:\|:&\s*\};:",
            r"\bcurl\b.*\|\s*(ba)?sh\b", r"\bwget\b.*\|\s*(ba)?sh\b",
            r"\bchmod\s+777\b", r"\bchown\b", r"\bcat\s+/etc/shadow\b"
        ]

    def validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates MCP agent tool call.
        Returns: (is_allowed: bool, reason: str)
        """
        # 1. Inspect Shell Execution Tools
        if tool_name in ["run_bash", "execute_command", "terminal"]:
            cmd = arguments.get("command", "")
            for pattern in self.dangerous_commands:
                if re.search(pattern, cmd, re.IGNORECASE):
                    return False, f"POLICY_VIOLATION: Command matched dangerous destruction signature '{pattern}'"

        # 2. Inspect File System Tools (Directory Traversal Protection)
        elif tool_name in ["read_file", "write_file", "delete_file"]:
            target_path = arguments.get("path", "")
            if not target_path:
                return False, "INVALID_ARGUMENT: Path argument cannot be empty"

            # Check for path traversal attempts
            if "../" in target_path or "..\\" in target_path:
                return False, "PATH_TRAVERSAL_BLOCKED: Detected directory traversal sequence '../'"

            # Enforce sandbox boundary
            resolved = os.path.abspath(os.path.join(self.sandbox_root, target_path.lstrip("/")))
            if not resolved.startswith(self.sandbox_root):
                return False, f"SANDBOX_ESCAPE_BLOCKED: Path '{target_path}' attempts to escape sandbox boundary"

        return True, "TOOL_EXECUTION_PERMITTED"

if __name__ == "__main__":
    guard = MCPSecurityGuard()
    print("Safe read:", guard.validate_tool_call("read_file", {"path": "reports/summary.txt"}))
    print("Traversal attempt:", guard.validate_tool_call("read_file", {"path": "../../etc/shadow"}))
    print("Dangerous command:", guard.validate_tool_call("run_bash", {"command": "rm -rf /"}))
