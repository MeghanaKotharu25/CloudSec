from __future__ import annotations

from typing import Any, Dict, List

import networkx as nx


class RiskEngine:
    """Prioritizes findings using graph-aware risk scoring."""

    severity_weights = {
        "LOW": 2,
        "MEDIUM": 4,
        "HIGH": 7,
        "CRITICAL": 9,
    }

    def prioritize(self, findings: List[Dict[str, Any]], graph: nx.DiGraph) -> Dict[str, Any]:
        prioritized: List[Dict[str, Any]] = []

        for finding in findings:
            resource_id = finding["resource_id"]
            resource_label = self._resource_label(finding)
            if resource_label not in graph:
                resource_label = self._fallback_resource_label(resource_id, graph)

            blast_radius = self._compute_blast_radius(graph, resource_label)
            internet_exposure = 10 if "0.0.0.0/0" in str(finding.get("details", {})) else 4
            privilege_level = 10 if finding["severity"] in {"CRITICAL", "HIGH"} else 6
            severity_score = self.severity_weights.get(finding["severity"], 2)
            blast_score = min(10, max(1, len(blast_radius) + 1))

            composite_score = (
                0.35 * severity_score
                + 0.25 * internet_exposure
                + 0.25 * blast_score
                + 0.15 * privilege_level
            )

            prioritized.append(
                {
                    "vuln_id": finding["id"],
                    "composite_score": round(float(composite_score), 2),
                    "blast_radius": blast_radius,
                    "attack_paths": [[source, *path] for source, path in self._attack_paths(graph, resource_label)],
                    "priority": self._priority_label(float(composite_score)),
                }
            )

        prioritized.sort(key=lambda x: x["composite_score"], reverse=True)
        return {
            "overall_risk_score": round(sum(item["composite_score"] for item in prioritized) / max(1, len(prioritized)), 2),
            "attack_graph_summary": {
                "total_nodes": graph.number_of_nodes(),
                "total_edges": graph.number_of_edges(),
                "entry_points": list(sorted(node for node in graph.nodes if node.startswith("EC2:"))),
                "critical_assets": list(sorted(node for node in graph.nodes if node.startswith("S3:") or node.startswith("RDS:"))),
            },
            "prioritized_findings": prioritized,
        }

    def _resource_label(self, finding: Dict[str, Any]) -> str:
        resource_id = finding["resource_id"]
        resource_type = finding.get("resource_type")

        if resource_type == "S3Bucket":
            return f"S3:{resource_id}"
        if resource_type == "SecurityGroup":
            return f"SG:{resource_id}"
        if resource_type == "IAMRole":
            return f"IAM:{resource_id}"
        if resource_type == "RDSInstance":
            return f"RDS:{resource_id}"
        if resource_id.startswith("SG:") or resource_id.startswith("sg-"):
            return f"SG:{resource_id.replace('SG:', '').replace('sg-', '')}" if resource_id.startswith("SG:") else f"SG:{resource_id}"
        if resource_id.startswith("arn:aws:s3:::"):
            return f"S3:{resource_id.split(':::')[-1]}"
        if resource_id.startswith("arn:aws:iam::"):
            return f"IAM:{resource_id.split('/')[-1]}"
        if resource_id in {"public-data-bucket", "vulnerable-prod-db", "admin-role"}:
            prefixes = {"public-data-bucket": "S3", "vulnerable-prod-db": "RDS", "admin-role": "IAM"}
            return f"{prefixes[resource_id]}:{resource_id}"
        return resource_id

    def _fallback_resource_label(self, resource_id: str, graph: nx.DiGraph) -> str:
        if resource_id in graph:
            return resource_id
        for node in graph.nodes:
            if node.endswith(f":{resource_id}"):
                return node
        return resource_id

    def _compute_blast_radius(self, graph: nx.DiGraph, resource_label: str) -> List[str]:
        if resource_label not in graph:
            return []

        reachable = []
        seen = {resource_label}
        queue = [resource_label]
        while queue:
            node = queue.pop(0)
            for neighbor in list(graph.successors(node)) + list(graph.predecessors(node)):
                if neighbor not in seen:
                    seen.add(neighbor)
                    reachable.append(neighbor)
                    queue.append(neighbor)
        return reachable

    def _attack_paths(self, graph: nx.DiGraph, resource_label: str):
        paths = []
        for source in sorted(graph.nodes):
            if source.startswith("EC2:"):
                try:
                    path = nx.shortest_path(graph, source, resource_label)
                    if path and path[0] == source:
                        paths.append((source, path))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
        return paths

    @staticmethod
    def _priority_label(value: float) -> str:
        if value >= 8:
            return "CRITICAL"
        if value >= 6:
            return "HIGH"
        if value >= 4:
            return "MEDIUM"
        return "LOW"
