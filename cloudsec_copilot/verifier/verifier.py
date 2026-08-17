from __future__ import annotations

from typing import Any, Dict, List


class Verifier:
    """Compares before/after security findings to confirm which issues were resolved."""

    def compare(self, before: List[Dict[str, Any]], after: List[Dict[str, Any]]) -> Dict[str, Any]:
        before_ids = {item["id"] for item in before}
        after_ids = {item["id"] for item in after}
        resolved = sorted(before_ids - after_ids)

        return {
            "status": "SUCCESS" if len(resolved) > 0 else "NO_CHANGE",
            "remediation_required": len(resolved) > 0,
            "resolved": resolved,
            "remaining": sorted(after_ids),
        }

    def verify_finding_removed(self, before: List[Dict[str, Any]], after: List[Dict[str, Any]], finding_id: str) -> Dict[str, Any]:
        comparison = self.compare(before, after)
        return {
            "finding_id": finding_id,
            "status": "VERIFIED" if finding_id in comparison["resolved"] else "PENDING",
            "resolved": comparison["resolved"],
            "remaining": comparison["remaining"],
        }
