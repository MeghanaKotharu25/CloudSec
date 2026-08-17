from __future__ import annotations

from typing import Any, Dict, List


class RemediationPlanner:
    """Builds safe remediation plans and rollback actions without executing changes."""

    def plan(self, rule_id: str, target: str, dry_run: bool = True) -> Dict[str, Any]:
        actions: List[str] = []
        rollback: List[str] = []

        if rule_id == "RULE-S3-PUBLIC":
            actions = [
                f"aws s3api put-public-access-block --bucket {target} --public-access-block Configuration='{{\"BlockPublicAcls\":true,\"IgnorePublicAcls\":true,\"BlockPublicPolicy\":true,\"RestrictPublicBuckets\":true}}'",
                f"aws s3api delete-bucket-policy --bucket {target}",
            ]
            rollback = [
                f"aws s3api put-bucket-policy --bucket {target} --policy '<restore original policy>'",
            ]
        elif rule_id == "RULE-SG-OPEN":
            actions = [
                f"aws ec2 revoke-security-group-ingress --group-id {target} --protocol tcp --port 22 --cidr 0.0.0.0/0",
                f"aws ec2 revoke-security-group-ingress --group-id {target} --protocol tcp --port 80 --cidr 0.0.0.0/0",
            ]
            rollback = [
                f"aws ec2 authorize-security-group-ingress --group-id {target} --protocol tcp --port 22 --cidr 0.0.0.0/0",
            ]
        elif rule_id == "RULE-IAM-ADMIN":
            actions = [
                f"aws iam attach-role-policy --role-name {target} --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess",
                f"aws iam detach-role-policy --role-name {target} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            ]
            rollback = [
                f"aws iam attach-role-policy --role-name {target} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            ]
        elif rule_id == "RULE-RDS-PUBLIC":
            actions = [
                f"aws rds modify-db-instance --db-instance-identifier {target} --publicly-accessible false --apply-immediately",
            ]
            rollback = [
                f"aws rds modify-db-instance --db-instance-identifier {target} --publicly-accessible true --apply-immediately",
            ]
        else:
            actions = [f"No remediation template available for rule {rule_id}"]
            rollback = ["No rollback action defined; review configuration manually."]

        return {
            "rule_id": rule_id,
            "target": target,
            "dry_run": dry_run,
            "actions": actions,
            "rollback": rollback,
        }
