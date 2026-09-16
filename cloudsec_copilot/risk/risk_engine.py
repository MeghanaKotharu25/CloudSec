from __future__ import annotations

from typing import Any, Dict, List, Optional

import networkx as nx

from cloudsec_copilot.graph.graph_builder import CloudGraphBuilder


class RiskEngine:
    """Prioritizes security findings using deterministic, explainable, graph-aware risk scoring."""

    SEVERITY_WEIGHTS: Dict[str, float] = {
        "LOW": 2.0,
        "MEDIUM": 4.0,
        "HIGH": 7.0,
        "CRITICAL": 9.0,
    }

    def __init__(self) -> None:
        self.graph_builder = CloudGraphBuilder()

    def prioritize(self, findings: List[Dict[str, Any]], graph: nx.DiGraph) -> Dict[str, Any]:
        """Calculate context-aware composite risk scores for all findings using graph reachability and blast radius."""
        prioritized: List[Dict[str, Any]] = []

        for finding in findings:
            resource_id = finding.get("resource_id", "")
            resource_label = self._resource_label(finding)
            if resource_label not in graph:
                resource_label = self._fallback_resource_label(resource_id, graph)

            # 1. Attack path calculation from INTERNET
            attack_paths_data = self.graph_builder.find_attack_paths(graph, resource_label)
            raw_attack_paths = [p["path"] for p in attack_paths_data]

            # 2. Blast radius calculation along directed privilege/attack edges
            blast_info = self.graph_builder.compute_blast_radius(graph, resource_label)
            blast_radius_nodes = blast_info["reachable_nodes"]

            # 3. Severity term (0 - 10)
            severity_score = self.SEVERITY_WEIGHTS.get(finding.get("severity", "LOW"), 2.0)

            # 4. Internet Exposure term (0 - 10) grounded in graph reachability
            internet_exposure = self._compute_internet_exposure(graph, resource_label, finding, attack_paths_data)

            # 5. Blast Radius term (0 - 10) grounded in reached resources and admin escalation
            blast_score = blast_info["score"]

            # 6. Privilege Level term (0 - 10) grounded in IAM policies / admin access
            privilege_level = self._compute_privilege_level(finding, resource_label, blast_info)

            # 7. Deterministic composite score (0.0 - 10.0)
            composite_score = (
                0.35 * severity_score
                + 0.25 * internet_exposure
                + 0.25 * blast_score
                + 0.15 * privilege_level
            )
            composite_score = round(min(10.0, max(0.0, float(composite_score))), 2)

            explanation = self._build_explanation(
                finding,
                severity_score,
                internet_exposure,
                blast_score,
                privilege_level,
                attack_paths_data,
                blast_info,
            )

            risk_breakdown = {
                "severity": {
                    "score": round(severity_score, 2),
                    "weight": 0.35,
                    "contribution": round(0.35 * severity_score, 2),
                },
                "internet_exposure": {
                    "score": round(internet_exposure, 2),
                    "weight": 0.25,
                    "contribution": round(0.25 * internet_exposure, 2),
                    "is_exposed": bool(attack_paths_data or internet_exposure >= 7.0),
                },
                "blast_radius": {
                    "score": round(blast_score, 2),
                    "weight": 0.25,
                    "contribution": round(0.25 * blast_score, 2),
                    "impacted_count": blast_info["resource_count"],
                    "reaches_admin": blast_info["has_admin_privilege"],
                },
                "privilege": {
                    "score": round(privilege_level, 2),
                    "weight": 0.15,
                    "contribution": round(0.15 * privilege_level, 2),
                },
                "explanation": explanation,
            }

            prioritized.append(
                {
                    "vuln_id": finding["id"],
                    "resource_id": resource_id,
                    "resource_label": resource_label,
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", "LOW"),
                    "composite_score": composite_score,
                    "blast_radius": blast_radius_nodes,
                    "blast_info": blast_info,
                    "attack_paths": raw_attack_paths,
                    "attack_paths_details": attack_paths_data,
                    "priority": self._priority_label(composite_score),
                    "risk_breakdown": risk_breakdown,
                }
            )

        prioritized.sort(key=lambda x: x["composite_score"], reverse=True)

        # Graph summary metrics
        internet_exposed_nodes = []
        if "INTERNET" in graph:
            internet_exposed_nodes = sorted(list(graph.successors("INTERNET")))

        summary = {
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
            "entry_points": list(sorted(node for node in graph.nodes if node.startswith("EC2:"))),
            "internet_exposed": internet_exposed_nodes,
            "critical_assets": list(sorted(node for node in graph.nodes if node.startswith("S3:") or node.startswith("RDS:"))),
            "attack_paths_found": sum(len(item["attack_paths"]) for item in prioritized),
        }

        overall_score = round(
            sum(item["composite_score"] for item in prioritized) / max(1, len(prioritized)), 2
        )

        return {
            "overall_risk_score": overall_score,
            "attack_graph_summary": summary,
            "prioritized_findings": prioritized,
        }

    def _compute_internet_exposure(
        self,
        graph: nx.DiGraph,
        resource_label: str,
        finding: Dict[str, Any],
        attack_paths: List[Dict[str, Any]],
    ) -> float:
        """Evaluate exposure term (0 - 10) based on actual graph paths from INTERNET."""
        # 1. Direct connection from INTERNET
        if graph.has_edge("INTERNET", resource_label):
            edge_data = graph.get_edge_data("INTERNET", resource_label) or {}
            if edge_data.get("is_sensitive", False):
                return 10.0
            return 8.5

        # 2. Indirect attack path from INTERNET
        if attack_paths:
            any_sensitive = False
            for p in attack_paths:
                for step in p.get("steps", []):
                    if step.get("is_sensitive", False) or any(
                        port in {22, 3389, 3306, 5432, 1433, 6379, 9200} for port in step.get("ports", [])
                    ):
                        any_sensitive = True
                        break
            return 8.5 if any_sensitive else 7.0

        # 3. Rule-specific fallbacks
        rule_id = finding.get("rule_id", "")
        if rule_id in {"RULE-SG-OPEN", "RULE-SG-SENSITIVE-PORT", "RULE-S3-PUBLIC", "RULE-EC2-PUBLIC", "RULE-RDS-PUBLIC"}:
            if "0.0.0.0/0" in str(finding.get("details", {})):
                return 8.5
            return 7.0

        # 4. Internal resources (IAM roles, unencrypted storage without public ingress)
        return 2.5

    def _compute_privilege_level(
        self,
        finding: Dict[str, Any],
        resource_label: str,
        blast_info: Dict[str, Any],
    ) -> float:
        """Evaluate privilege term (0 - 10) based on reached administrative roles and policies."""
        rule_id = finding.get("rule_id", "")

        # Direct IAM admin finding
        if rule_id == "RULE-IAM-ADMIN" or "AdministratorAccess" in resource_label:
            return 10.0
        if rule_id == "RULE-IAM-WILDCARD":
            return 9.0

        # If attack flow reaches administrative privileges
        if blast_info.get("has_admin_privilege", False):
            return 9.5
        if blast_info.get("has_iam_reach", False):
            return 7.0

        # Standard non-identity finding privilege levels
        sev = finding.get("severity", "LOW")
        if sev == "CRITICAL":
            return 5.0
        if sev == "HIGH":
            return 4.0
        return 2.0

    def _build_explanation(
        self,
        finding: Dict[str, Any],
        sev: float,
        exp: float,
        blast: float,
        priv: float,
        attack_paths: List[Dict[str, Any]],
        blast_info: Dict[str, Any],
    ) -> str:
        """Generate human-readable justification for the computed risk score."""
        parts = []
        if attack_paths:
            path_str = " -> ".join(attack_paths[0]["path"])
            parts.append(f"Direct attack path detected from {path_str}.")
        elif exp >= 7.0:
            parts.append("Exposed to the public Internet with open ingress.")
        else:
            parts.append("Internal cloud asset without direct external attack path.")

        if blast_info.get("has_admin_privilege", False):
            parts.append("Reaches administrative IAM privileges, maximizing blast radius.")
        elif blast_info.get("resource_count", 0) > 1:
            parts.append(f"Reaches {blast_info['resource_count']} downstream cloud components.")
        else:
            parts.append("Blast radius is localized to this component.")

        return " ".join(parts)

    def _resource_label(self, finding: Dict[str, Any]) -> str:
        """Map a security finding to its corresponding graph node key."""
        resource_id = finding.get("resource_id", "")
        resource_type = finding.get("resource_type")

        if resource_type == "S3Bucket":
            return f"S3:{resource_id}"
        if resource_type == "SecurityGroup":
            return f"SG:{resource_id}"
        if resource_type == "IAMRole":
            return f"IAM:{resource_id}"
        if resource_type == "IAMPolicy":
            return f"POLICY:{resource_id}"
        if resource_type == "RDSInstance":
            return f"RDS:{resource_id}"
        if resource_type == "EC2Instance":
            return f"EC2:{resource_id}"

        if resource_id.startswith("sg-") or resource_id.startswith("SG:"):
            return f"SG:{resource_id.replace('SG:', '')}"
        if resource_id.startswith("arn:aws:s3:::"):
            return f"S3:{resource_id.split(':::')[-1]}"
        if resource_id.startswith("arn:aws:iam::"):
            return f"IAM:{resource_id.split('/')[-1]}"
        if resource_id in {"public-data-bucket", "vulnerable-prod-db", "admin-role"}:
            prefixes = {"public-data-bucket": "S3", "vulnerable-prod-db": "RDS", "admin-role": "IAM"}
            return f"{prefixes[resource_id]}:{resource_id}"

        return resource_id

    def _fallback_resource_label(self, resource_id: str, graph: nx.DiGraph) -> str:
        """Attempt to find matching node by suffix or prefix."""
        if resource_id in graph:
            return resource_id
        for node in graph.nodes:
            if node.endswith(f":{resource_id}") or node == resource_id:
                return node
        return resource_id

    @staticmethod
    def _priority_label(score: float) -> str:
        """Map composite score to deterministic priority bands."""
        if score >= 8.0:
            return "CRITICAL"
        if score >= 6.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
