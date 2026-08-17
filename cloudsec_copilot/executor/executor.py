from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class Executor:
    """Executes approved remediation actions against the configured cloud endpoint and records an audit trail."""

    def __init__(self, audit_path: str = "audit_log.json"):
        self.audit_path = Path(audit_path)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_client(self, service_name: str):
        endpoint_url = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")
        return boto3.client(
            service_name,
            endpoint_url=endpoint_url,
            region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
        )

    def _apply_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        action_name = action.get("action")
        resource_id = action.get("resource_id")
        params = action.get("parameters", {})

        if action_name == "BLOCK_S3_PUBLIC_ACCESS":
            s3 = self._get_client("s3")
            s3.put_public_access_block(
                Bucket=resource_id,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": params.get("block_public_acls", True),
                    "IgnorePublicAcls": params.get("ignore_public_acls", True),
                    "BlockPublicPolicy": params.get("block_public_policy", True),
                    "RestrictPublicBuckets": params.get("restrict_public_buckets", True),
                },
            )
            s3.put_bucket_acl(Bucket=resource_id, ACL="private")
            return {"status": "APPLIED", "service": "s3", "resource_id": resource_id}

        if action_name == "REVOKE_SG_INGRESS":
            ec2 = self._get_client("ec2")
            ports = params.get("ports", [22, 80])
            cidr = params.get("cidr", "0.0.0.0/0")
            permissions = []
            for port in ports:
                permissions.append(
                    {
                        "IpProtocol": params.get("protocol", "tcp"),
                        "FromPort": port,
                        "ToPort": port,
                        "IpRanges": [{"CidrIp": cidr}],
                    }
                )
            ec2.revoke_security_group_ingress(GroupId=resource_id, IpPermissions=permissions)
            return {"status": "APPLIED", "service": "ec2", "resource_id": resource_id}

        if action_name == "REMOVE_IAM_POLICY":
            iam = self._get_client("iam")
            iam.detach_role_policy(
                RoleName=resource_id,
                PolicyArn=params.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess"),
            )
            return {"status": "APPLIED", "service": "iam", "resource_id": resource_id}

        raise ValueError(f"Unsupported action for execution: {action_name}")

    def execute(self, plan: Dict[str, Any], finding: Dict[str, Any], approved: bool = False) -> Dict[str, Any]:
        if not approved:
            return {"status": "CANCELLED", "reason": "User did not approve the remediation."}

        action = plan.get("action")
        if not action or not action.get("action"):
            return {"status": "FAILED", "reason": "No valid remediation action was generated."}

        try:
            result = self._apply_action(action)
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "finding_id": finding.get("id"),
                "resource_id": finding.get("resource_id"),
                "rule_id": finding.get("rule_id"),
                "action": action,
                "rollback": plan.get("rollback", {}),
                "status": "APPLIED",
                "executor_result": result,
            }

            existing: List[Dict[str, Any]] = []
            if self.audit_path.exists():
                try:
                    existing = json.loads(self.audit_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    existing = []

            existing.append(record)
            self.audit_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            return {"status": "APPLIED", "audit_record": record}
        except (BotoCoreError, ClientError, ValueError, OSError) as exc:
            return {"status": "FAILED", "reason": str(exc)}
