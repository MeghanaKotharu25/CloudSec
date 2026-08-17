from __future__ import annotations

from typing import Any, Dict, List


class RemediationPlanner:
    """Builds validated remediation actions and rollback metadata for supported findings."""

    def plan(self, rule_id: str, target: str, dry_run: bool = True) -> Dict[str, Any]:
        if rule_id == "RULE-S3-PUBLIC":
            return {
                "rule_id": rule_id,
                "target": target,
                "dry_run": dry_run,
                "action": {
                    "action": "BLOCK_S3_PUBLIC_ACCESS",
                    "resource_type": "s3",
                    "resource_id": target,
                    "parameters": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                },
                "rollback": {
                    "action": "RESTORE_S3_PUBLIC_ACCESS",
                    "resource_type": "s3",
                    "resource_id": target,
                    "parameters": {},
                },
            }

        if rule_id == "RULE-SG-OPEN":
            return {
                "rule_id": rule_id,
                "target": target,
                "dry_run": dry_run,
                "action": {
                    "action": "REVOKE_SG_INGRESS",
                    "resource_type": "security_group",
                    "resource_id": target,
                    "parameters": {"cidr": "0.0.0.0/0", "protocol": "tcp", "ports": [22, 80]},
                },
                "rollback": {
                    "action": "RESTORE_SG_INGRESS",
                    "resource_type": "security_group",
                    "resource_id": target,
                    "parameters": {"cidr": "0.0.0.0/0", "protocol": "tcp", "ports": [22, 80]},
                },
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
            return {
                "rule_id": rule_id,
                "target": target,
                "dry_run": dry_run,
                "action": {
                    "action": "REPLACE_IAM_POLICY",
                    "resource_type": "iam",
                    "resource_id": target,
                    "parameters": {
                        "current_policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "replacement_policy": least_privilege_policy,
                    },
                },
                "rollback": {
                    "action": "RESTORE_IAM_POLICY",
                    "resource_type": "iam",
                    "resource_id": target,
                    "parameters": {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                },
            }

        return {
            "rule_id": rule_id,
            "target": target,
            "dry_run": dry_run,
            "action": {
                "action": "REVIEW_RESOURCE",
                "resource_type": "unknown",
                "resource_id": target,
                "parameters": {},
            },
            "rollback": {
                "action": "RESTORE_PREVIOUS_CONFIGURATION",
                "resource_type": "unknown",
                "resource_id": target,
                "parameters": {},
            },
        }
