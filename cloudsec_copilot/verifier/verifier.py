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
