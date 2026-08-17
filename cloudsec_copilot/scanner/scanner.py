from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from cloudsec_copilot.discovery.models import InfrastructureStateModel


class Scanner:
    """Deterministic rule-based cloud vulnerability scanner."""

    SEVERITY_MAP = {
        "LOW": 2,
        "MEDIUM": 4,
        "HIGH": 7,
        "CRITICAL": 9,
    }

    def scan(self, inventory: InfrastructureStateModel) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        resources = inventory.resources

        for bucket in resources.s3_buckets:
            if bucket.is_public:
                findings.append(
                    self._make_finding(
                        "VULN-001",
                        "RULE-S3-PUBLIC",
                        "Public S3 bucket exposure",
                        "CRITICAL",
                        bucket.name,
                        "S3Bucket",
                        {
                            "bucket_name": bucket.name,
                            "acl_public": bucket.acl_public,
                            "policy_public": bucket.policy_public,
                            "arn": bucket.arn,
                        },
                        "Set the bucket to private and disable public ACLs or policy grants.",
                    )
                )
            if not bucket.encryption_enabled:
                findings.append(
                    self._make_finding(
                        "VULN-002",
                        "RULE-S3-NO-ENCRYPTION",
                        "S3 bucket without encryption",
                        "HIGH",
                        bucket.name,
                        "S3Bucket",
                        {"bucket_name": bucket.name, "encryption_enabled": False},
                        "Enable bucket encryption with SSE-S3 or SSE-KMS.",
                    )
                )

        for sg in resources.security_groups:
            if any(rule.cidr_ip == "0.0.0.0/0" for rule in sg.inbound_rules):
                findings.append(
                    self._make_finding(
                        "VULN-003",
                        "RULE-SG-OPEN",
                        "Open security group allowing public ingress",
                        "HIGH",
                        sg.group_id,
                        "SecurityGroup",
                        {
                            "group_name": sg.group_name,
                            "vpc_id": sg.vpc_id,
                            "open_rules": [
                                {
                                    "protocol": rule.protocol,
                                    "from_port": rule.from_port,
                                    "to_port": rule.to_port,
                                    "cidr_ip": rule.cidr_ip,
                                }
                                for rule in sg.inbound_rules
                                if rule.cidr_ip == "0.0.0.0/0"
                            ],
                        },
                        "Restrict inbound traffic to trusted CIDRs and remove 0.0.0.0/0 access.",
                    )
                )

        for db in resources.rds_instances:
            if db.publicly_accessible:
                findings.append(
                    self._make_finding(
                        "VULN-004",
                        "RULE-RDS-PUBLIC",
                        "Publicly accessible RDS instance",
                        "CRITICAL",
                        db.db_instance_identifier,
                        "RDSInstance",
                        {"db_instance_identifier": db.db_instance_identifier, "status": db.status},
                        "Make the database private and restrict public access to approved networks only.",
                    )
                )

        for role in resources.iam_roles:
            if role.is_admin:
                findings.append(
                    self._make_finding(
                        "VULN-005",
                        "RULE-IAM-ADMIN",
                        "IAM role has full administrative privileges",
                        "CRITICAL",
                        role.role_name,
                        "IAMRole",
                        {
                            "role_name": role.role_name,
                            "attached_policies": role.attached_policies,
                            "arn": role.arn,
                        },
                        "Replace broad AdministratorAccess with least-privilege permissions.",
                    )
                )

        return findings

    def export_report(self, inventory: InfrastructureStateModel, output_path: str | None = None) -> Dict[str, Any]:
        findings = self.scan(inventory)
        report = {
            "scan_id": f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
        }

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return report

    @staticmethod
    def _make_finding(
        finding_id: str,
        rule_id: str,
        title: str,
        severity: str,
        resource_id: str,
        resource_type: str,
        details: Dict[str, Any],
        remediation_hint: str,
    ) -> Dict[str, Any]:
        return {
            "id": finding_id,
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "region": "us-east-1",
            "details": details,
            "remediation_hint": remediation_hint,
        }
