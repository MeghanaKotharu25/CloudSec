from __future__ import annotations

from typing import Any, Dict, List, Optional


class RemediationPlanner:
    """Builds validated, deterministic remediation actions and rollback metadata from approved allowlists."""

    SUPPORTED_RULES = {
        "RULE-S3-PUBLIC": {
            "action": "BLOCK_S3_PUBLIC_ACCESS",
            "resource_type": "s3",
        },
        "RULE-SG-OPEN": {
            "action": "REVOKE_SG_INGRESS",
            "resource_type": "security_group",
        },
        "RULE-IAM-ADMIN": {
            "action": "REPLACE_IAM_POLICY",
            "resource_type": "iam",
        },
    }

    def plan(
        self,
        rule_id: str,
        target: str,
        dry_run: bool = True,
        finding_details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a structured, safe remediation plan.
        
        Only approved allowlisted actions are returned. Unsupported rules
        return a REVIEW_RESOURCE plan which cannot be executed automatically.
        """
        safety_metadata = {
            "is_destructive": False,
            "requires_human_approval": True,
            "predefined_allowlist": True,
            "rule_id": rule_id,
            "target": target,
        }

        if rule_id == "RULE-S3-PUBLIC":
            action_dict = {
                "action": "BLOCK_S3_PUBLIC_ACCESS",
                "resource_type": "s3",
                "resource_id": target,
                "rule_id": rule_id,
                "dry_run": dry_run,
                "parameters": {
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True,
                },
                "safety_metadata": safety_metadata,
            }
            rollback_dict = {
                "action": "RESTORE_S3_PUBLIC_ACCESS",
                "resource_type": "s3",
                "resource_id": target,
                "parameters": {},
            }
            return {
                "rule_id": rule_id,
                "target": target,
                "dry_run": dry_run,
                "action": action_dict,
                "rollback": rollback_dict,
                "safety_metadata": safety_metadata,
            }

        if rule_id == "RULE-SG-OPEN":
            ports = [22, 80]
            if finding_details and "open_ports" in finding_details and isinstance(finding_details["open_ports"], list):
                ports = [p for p in finding_details["open_ports"] if isinstance(p, int)]
                if not ports:
                    ports = [22, 80]

            action_dict = {
                "action": "REVOKE_SG_INGRESS",
                "resource_type": "security_group",
                "resource_id": target,
                "rule_id": rule_id,
                "dry_run": dry_run,
                "parameters": {"cidr": "0.0.0.0/0", "protocol": "tcp", "ports": ports},
                "safety_metadata": safety_metadata,
            }
            rollback_dict = {
                "action": "RESTORE_SG_INGRESS",
                "resource_type": "security_group",
                "resource_id": target,
                "parameters": {"cidr": "0.0.0.0/0", "protocol": "tcp", "ports": ports},
            }
            return {
                "rule_id": rule_id,
                "target": target,
                "dry_run": dry_run,
                "action": action_dict,
                "rollback": rollback_dict,
                "safety_metadata": safety_metadata,
            }

        if rule_id == "RULE-IAM-ADMIN":
            least_privilege_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ReadOnlyDiagnostics",
                        "Effect": "Allow",
                        "Action": [
                            "s3:ListBucket",
                            "s3:GetBucketLocation",
                            "s3:GetObject",
                            "ec2:DescribeInstances",
                            "ec2:DescribeSecurityGroups",
                            "logs:DescribeLogGroups",
                        ],
                        "Resource": "*",
                    }
                ],
            }
            action_dict = {
                "action": "REPLACE_IAM_POLICY",
                "resource_type": "iam",
                "resource_id": target,
                "rule_id": rule_id,
                "dry_run": dry_run,
                "parameters": {
                    "current_policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "replacement_policy": least_privilege_policy,
                },
                "safety_metadata": safety_metadata,
            }
            rollback_dict = {
                "action": "RESTORE_IAM_POLICY",
                "resource_type": "iam",
                "resource_id": target,
                "parameters": {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            }
            return {
                "rule_id": rule_id,
                "target": target,
                "dry_run": dry_run,
                "action": action_dict,
                "rollback": rollback_dict,
                "safety_metadata": safety_metadata,
            }

        # Unsupported rule fallback
        safety_metadata["automatic_execution_allowed"] = False
        action_dict = {
            "action": "REVIEW_RESOURCE",
            "resource_type": "unknown",
            "resource_id": target,
            "rule_id": rule_id,
            "dry_run": dry_run,
            "parameters": {},
            "safety_metadata": safety_metadata,
        }
        rollback_dict = {
            "action": "RESTORE_PREVIOUS_CONFIGURATION",
            "resource_type": "unknown",
            "resource_id": target,
            "parameters": {},
        }
        return {
            "rule_id": rule_id,
            "target": target,
            "dry_run": dry_run,
            "action": action_dict,
            "rollback": rollback_dict,
            "safety_metadata": safety_metadata,
        }
