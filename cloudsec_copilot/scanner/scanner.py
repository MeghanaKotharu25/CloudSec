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

    SENSITIVE_PORT_MAP = {
        22: ("SSH", "CRITICAL"),
        3389: ("RDP", "CRITICAL"),
        3306: ("MySQL", "CRITICAL"),
        5432: ("PostgreSQL", "CRITICAL"),
        1433: ("MSSQL", "CRITICAL"),
        6379: ("Redis", "CRITICAL"),
        9200: ("Elasticsearch", "CRITICAL"),
    }

    CRITICAL_WILDCARD_SERVICES = {"iam", "sts", "ec2", "s3", "dynamodb", "rds"}

    def scan(self, inventory: InfrastructureStateModel) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        resources = inventory.resources
        region = inventory.region or "us-east-1"

        # VULN-001 & VULN-002: S3 Buckets
        for bucket in resources.s3_buckets:
            if bucket.is_public or bucket.acl_public or bucket.policy_public:
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
                        region=region,
                    )
                )
            if not bucket.encryption_enabled:
                findings.append(
                    self._make_finding(
                        "VULN-008",
                        "RULE-S3-NO-ENCRYPTION",
                        "S3 bucket without encryption",
                        "HIGH",
                        bucket.name,
                        "S3Bucket",
                        {"bucket_name": bucket.name, "encryption_enabled": False},
                        "Enable bucket encryption with SSE-S3 or SSE-KMS.",
                        region=region,
                    )
                )
            if not getattr(bucket, "versioning_enabled", False):
                findings.append(
                    self._make_finding(
                        "VULN-009",
                        "RULE-S3-NO-VERSIONING",
                        "S3 bucket versioning disabled",
                        "MEDIUM",
                        bucket.name,
                        "S3Bucket",
                        {"bucket_name": bucket.name, "versioning_enabled": False},
                        "Enable S3 bucket versioning to protect against accidental deletion or overwrite.",
                        region=region,
                    )
                )
            if getattr(bucket, "website_enabled", False):
                findings.append(
                    self._make_finding(
                        "VULN-010",
                        "RULE-S3-WEBSITE-ENABLED",
                        "S3 static website hosting enabled",
                        "MEDIUM",
                        bucket.name,
                        "S3Bucket",
                        {
                            "bucket_name": bucket.name,
                            "website_enabled": True,
                            "website_configuration": getattr(bucket, "website_configuration", None),
                        },
                        "Disable S3 website hosting unless explicitly required for public web traffic.",
                        region=region,
                    )
                )

        # VULN-003 & VULN-006: Security Groups
        for sg in resources.security_groups:
            open_rules = [r for r in sg.inbound_rules if r.cidr_ip == "0.0.0.0/0"]
            if open_rules:
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
                                for rule in open_rules
                            ],
                        },
                        "Restrict inbound traffic to trusted CIDRs and remove 0.0.0.0/0 access.",
                        region=region,
                    )
                )

            # VULN-006: Check for sensitive ports exposed to 0.0.0.0/0
            seen_sg_findings = set()
            for rule in open_rules:
                proto = str(rule.protocol).lower()
                from_p = rule.from_port
                to_p = rule.to_port

                if proto == "-1":
                    dedup_key = (sg.group_id, "ALL")
                    if dedup_key not in seen_sg_findings:
                        seen_sg_findings.add(dedup_key)
                        findings.append(
                            self._make_finding(
                                "VULN-006",
                                "RULE-SG-SENSITIVE-PORT",
                                "Unrestricted traffic (all protocols/ports) publicly exposed through Security Group",
                                "CRITICAL",
                                sg.group_id,
                                "SecurityGroup",
                                {
                                    "group_id": sg.group_id,
                                    "group_name": sg.group_name,
                                    "vpc_id": sg.vpc_id,
                                    "protocol": "-1",
                                    "from_port": from_p,
                                    "to_port": to_p,
                                    "cidr_ip": rule.cidr_ip,
                                    "service": "All Traffic (Unrestricted)",
                                    "port": "0-65535",
                                },
                                "Restrict inbound traffic to trusted CIDRs and remove unrestricted 0.0.0.0/0 access.",
                                region=region,
                            )
                        )
                    continue

                for sensitive_port, (service_name, port_severity) in self.SENSITIVE_PORT_MAP.items():
                    port_matches = False
                    if from_p is not None and to_p is not None:
                        if from_p <= sensitive_port <= to_p:
                            port_matches = True
                    elif from_p is not None and to_p is None:
                        if from_p == sensitive_port:
                            port_matches = True

                    if port_matches:
                        dedup_key = (sg.group_id, sensitive_port, service_name)
                        if dedup_key not in seen_sg_findings:
                            seen_sg_findings.add(dedup_key)
                            findings.append(
                                self._make_finding(
                                    "VULN-006",
                                    "RULE-SG-SENSITIVE-PORT",
                                    f"Sensitive service ({service_name}) publicly exposed through Security Group",
                                    port_severity,
                                    sg.group_id,
                                    "SecurityGroup",
                                    {
                                        "group_id": sg.group_id,
                                        "group_name": sg.group_name,
                                        "vpc_id": sg.vpc_id,
                                        "protocol": rule.protocol,
                                        "from_port": from_p,
                                        "to_port": to_p,
                                        "cidr_ip": rule.cidr_ip,
                                        "service": service_name,
                                        "port": sensitive_port,
                                    },
                                    f"Restrict inbound {service_name} traffic (port {sensitive_port}) to trusted IP addresses instead of 0.0.0.0/0.",
                                    region=region,
                                )
                            )

        # VULN-004: Publicly accessible EC2 instances
        for instance in resources.ec2_instances:
            if instance.public_ip and instance.public_ip.strip():
                findings.append(
                    self._make_finding(
                        "VULN-004",
                        "RULE-EC2-PUBLIC",
                        "Publicly accessible EC2 instance",
                        "HIGH",
                        instance.instance_id,
                        "EC2Instance",
                        {
                            "instance_id": instance.instance_id,
                            "public_ip": instance.public_ip,
                            "private_ip": instance.private_ip,
                            "security_groups": instance.security_groups,
                            "iam_instance_profile": instance.iam_instance_profile,
                            "instance_type": instance.instance_type,
                            "state": instance.state,
                        },
                        "Remove unnecessary public exposure and place the instance behind appropriate network controls such as private subnets, load balancers, or restricted ingress.",
                        region=region,
                    )
                )

        # VULN-005 & VULN-007: IAM Roles
        seen_iam_findings = set()
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
                        region=region,
                    )
                )

            # VULN-007: Inspect policy documents for wildcard permissions
            for doc in getattr(role, "policy_documents", []):
                if not isinstance(doc, dict):
                    continue
                policy_name = doc.get("PolicyName", role.role_name)
                wildcard_findings = self._inspect_policy_document_for_wildcards(
                    doc=doc,
                    resource_id=role.role_name,
                    resource_type="IAMRole",
                    policy_name=policy_name,
                    region=region,
                    seen=seen_iam_findings,
                )
                findings.extend(wildcard_findings)

            # VULN-011: Inspect IAM trust policy for wildcard principal
            trust_doc = getattr(role, "assume_role_policy_document", None)
            trust_wildcard = getattr(role, "trust_allows_wildcard", False)
            if not trust_wildcard and isinstance(trust_doc, dict):
                stmts = trust_doc.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                for stmt in stmts:
                    if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
                        princ = stmt.get("Principal")
                        if princ == "*" or (isinstance(princ, dict) and (princ.get("AWS") == "*" or "*" in princ.get("AWS", []))):
                            trust_wildcard = True
                            break

            if trust_wildcard:
                findings.append(
                    self._make_finding(
                        "VULN-011",
                        "RULE-IAM-WILDCARD-TRUST",
                        "IAM role trust policy allows wildcard principal (*)",
                        "CRITICAL",
                        role.role_name,
                        "IAMRole",
                        {
                            "role_name": role.role_name,
                            "arn": role.arn,
                            "assume_role_policy_document": trust_doc,
                        },
                        "Restrict the trust relationship to authorized service principals (e.g. ec2.amazonaws.com) or trusted AWS accounts only.",
                        region=region,
                    )
                )

        # VULN-007: Inspect IAM Policies
        for policy in resources.iam_policies:
            doc = getattr(policy, "policy_document", None)
            stmts = getattr(policy, "statements", [])
            if doc:
                wildcard_findings = self._inspect_policy_document_for_wildcards(
                    doc=doc,
                    resource_id=policy.policy_name,
                    resource_type="IAMPolicy",
                    policy_name=policy.policy_name,
                    region=region,
                    seen=seen_iam_findings,
                )
                findings.extend(wildcard_findings)
            elif stmts:
                wildcard_findings = self._inspect_policy_document_for_wildcards(
                    doc={"Statement": stmts},
                    resource_id=policy.policy_name,
                    resource_type="IAMPolicy",
                    policy_name=policy.policy_name,
                    region=region,
                    seen=seen_iam_findings,
                )
                findings.extend(wildcard_findings)

        # VULN-009 & VULN-010: RDS Instances
        for db in resources.rds_instances:
            if db.publicly_accessible:
                findings.append(
                    self._make_finding(
                        "VULN-009",
                        "RULE-RDS-PUBLIC",
                        "Publicly accessible RDS database instance",
                        "CRITICAL",
                        db.db_instance_identifier,
                        "RDSInstance",
                        {
                            "db_instance_identifier": db.db_instance_identifier,
                            "engine": db.engine,
                            "db_instance_class": db.db_instance_class,
                            "publicly_accessible": db.publicly_accessible,
                            "storage_encrypted": db.storage_encrypted,
                            "status": db.status,
                        },
                        "Disable public accessibility for the RDS instance and place it in a private database subnet group.",
                        region=region,
                    )
                )

            if not db.storage_encrypted:
                findings.append(
                    self._make_finding(
                        "VULN-010",
                        "RULE-RDS-NO-ENCRYPTION",
                        "Unencrypted RDS database storage",
                        "HIGH",
                        db.db_instance_identifier,
                        "RDSInstance",
                        {
                            "db_instance_identifier": db.db_instance_identifier,
                            "engine": db.engine,
                            "storage_encrypted": False,
                            "status": db.status,
                        },
                        "Enable storage encryption using AWS KMS for the RDS instance.",
                        region=region,
                    )
                )

        return findings

    def _inspect_policy_document_for_wildcards(
        self,
        doc: Dict[str, Any],
        resource_id: str,
        resource_type: str,
        policy_name: str,
        region: str,
        seen: set,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not isinstance(doc, dict):
            return findings

        raw_statements = doc.get("Statement", [])
        if isinstance(raw_statements, dict):
            statements = [raw_statements]
        elif isinstance(raw_statements, list):
            statements = raw_statements
        else:
            return findings

        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") != "Allow":
                continue

            raw_actions = stmt.get("Action", [])
            actions = [raw_actions] if isinstance(raw_actions, str) else list(raw_actions) if isinstance(raw_actions, list) else []

            raw_resources = stmt.get("Resource", [])
            resources = [raw_resources] if isinstance(raw_resources, str) else list(raw_resources) if isinstance(raw_resources, list) else []

            has_global_action_wildcard = any(a == "*" for a in actions)
            has_global_resource_wildcard = any(r == "*" for r in resources)

            service_wildcards = [
                a for a in actions if a != "*" and (a.endswith(":*") or ":*:" in a)
            ]

            # Case 1: Global wildcard Action="*" and Resource="*"
            if has_global_action_wildcard and has_global_resource_wildcard:
                dedup_key = (resource_type, resource_id, policy_name, "GLOBAL_WILDCARD")
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        self._make_finding(
                            "VULN-007",
                            "RULE-IAM-WILDCARD",
                            f"IAM policy grants full wildcard access (*:*) in {policy_name}",
                            "CRITICAL",
                            resource_id,
                            resource_type,
                            {
                                "policy_name": policy_name,
                                "wildcard_type": "GLOBAL_WILDCARD",
                                "action": "*",
                                "resource": "*",
                                "statement": stmt,
                            },
                            "Scope down IAM permissions to specific required actions and specific resource ARNs following the principle of least privilege.",
                            region=region,
                        )
                    )
                continue

            # Case 2: Service wildcard Action="service:*" and Resource="*"
            if service_wildcards and has_global_resource_wildcard:
                is_critical_service = any(
                    sw.split(":")[0].lower() in self.CRITICAL_WILDCARD_SERVICES for sw in service_wildcards
                )
                severity = "CRITICAL" if is_critical_service else "HIGH"
                sw_str = ", ".join(service_wildcards)
                dedup_key = (resource_type, resource_id, policy_name, f"SERVICE_WILDCARD_{sw_str}")
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        self._make_finding(
                            "VULN-007",
                            "RULE-IAM-WILDCARD",
                            f"IAM policy grants wildcard service permissions ({sw_str}) on all resources in {policy_name}",
                            severity,
                            resource_id,
                            resource_type,
                            {
                                "policy_name": policy_name,
                                "wildcard_type": "SERVICE_WILDCARD",
                                "action": service_wildcards,
                                "resource": "*",
                                "statement": stmt,
                            },
                            "Scope down IAM permissions to specific required actions and specific resource ARNs following the principle of least privilege.",
                            region=region,
                        )
                    )
                continue

            # Case 3: Multiple wildcard actions with specific resources or broad actions
            if service_wildcards or (has_global_action_wildcard and not has_global_resource_wildcard):
                wildcard_actions = ["*"] if has_global_action_wildcard else service_wildcards
                sw_str = ", ".join(wildcard_actions)
                dedup_key = (resource_type, resource_id, policy_name, f"SCOPED_WILDCARD_{sw_str}")
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        self._make_finding(
                            "VULN-007",
                            "RULE-IAM-WILDCARD",
                            f"IAM policy grants broad wildcard actions ({sw_str}) in {policy_name}",
                            "HIGH",
                            resource_id,
                            resource_type,
                            {
                                "policy_name": policy_name,
                                "wildcard_type": "BROAD_ACTION_WILDCARD",
                                "action": wildcard_actions,
                                "resource": resources,
                                "statement": stmt,
                            },
                            "Scope down IAM permissions to specific required actions and specific resource ARNs following the principle of least privilege.",
                            region=region,
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
        region: str = "us-east-1",
    ) -> Dict[str, Any]:
        return {
            "id": finding_id,
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "region": region,
            "details": details,
            "remediation_hint": remediation_hint,
        }
