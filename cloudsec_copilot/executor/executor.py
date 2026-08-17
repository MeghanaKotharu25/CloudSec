from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class Executor:
    """Executes approved remediation actions and records audit history."""

    def __init__(self, audit_path: str = "audit_log.json"):
        self.audit_path = Path(audit_path)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

    def execute(self, plan: Dict[str, Any], finding: Dict[str, Any], approved: bool = False) -> Dict[str, Any]:
        if not approved:
            return {"status": "CANCELLED", "reason": "User did not approve the remediation."}

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "finding_id": finding.get("id"),
            "resource_id": finding.get("resource_id"),
            "rule_id": finding.get("rule_id"),
            "action": plan.get("actions", []),
            "rollback": plan.get("rollback", []),
            "status": "APPLIED",
        }

        existing: List[Dict[str, Any]] = []
        if self.audit_path.exists():
            try:
                existing = json.loads(self.audit_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = []

        existing.append(record)
        self.audit_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        return {"status": "APPLIED", "audit_record": record}
