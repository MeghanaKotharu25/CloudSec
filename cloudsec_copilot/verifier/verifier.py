from __future__ import annotations

from typing import Any, Dict, List


class Verifier:
    """Compares before/after security findings and resource state to confirm resolution or rollback."""

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

    def verify_finding_removed(
        self,
        before: List[Dict[str, Any]],
        after: List[Dict[str, Any]],
        finding_id: str,
    ) -> Dict[str, Any]:
        """Verifies that a specific finding was completely eliminated in the post-remediation rescan."""
        comparison = self.compare(before, after)
        after_ids = {item["id"] for item in after}

        if finding_id not in after_ids:
            return {
                "finding_id": finding_id,
                "status": "VERIFIED",
                "resolved": comparison["resolved"],
                "remaining": comparison["remaining"],
                "message": f"Finding {finding_id} successfully verified resolved in live scan.",
            }

        return {
            "finding_id": finding_id,
            "status": "REMEDIATION_FAILED",
            "resolved": comparison["resolved"],
            "remaining": comparison["remaining"],
            "message": f"Finding {finding_id} remains present after remediation attempt.",
        }

    def verify_rollback(
        self,
        before_rollback: List[Dict[str, Any]],
        after_rollback: List[Dict[str, Any]],
        finding_id: str,
    ) -> Dict[str, Any]:
        """Verifies that rolling back restored the original security state (vulnerability reappears)."""
        after_ids = {item["id"] for item in after_rollback}

        if finding_id in after_ids:
            return {
                "finding_id": finding_id,
                "status": "ROLLBACK_VERIFIED",
                "message": f"Finding {finding_id} successfully verified restored to original state.",
                "current_findings": sorted(after_ids),
            }

        return {
            "finding_id": finding_id,
            "status": "ROLLBACK_FAILED",
            "message": f"Finding {finding_id} was not detected after rollback execution.",
            "current_findings": sorted(after_ids),
        }
