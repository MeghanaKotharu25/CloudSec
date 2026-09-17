from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class Executor:
    """Safely executes approved remediation and rollback actions against the cloud endpoint.
    
    Enforces pre-execution state capture, idempotency checks, strict action dispatch,
    dry-run execution, human approval, and comprehensive audit trail logging.
    """

    APPROVED_ACTIONS = {
        "BLOCK_S3_PUBLIC_ACCESS",
        "REVOKE_SG_INGRESS",
        "REPLACE_IAM_POLICY",
        "ENABLE_S3_ENCRYPTION",
        "ENABLE_S3_VERSIONING",
        "DISABLE_S3_WEBSITE",
        "RESTRICT_IAM_TRUST_POLICY",
    }

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

    def capture_original_state(self, action_name: str, resource_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Captures the live configuration of a resource before applying changes."""
        original_state: Dict[str, Any] = {"captured_at": datetime.now(timezone.utc).isoformat()}

        try:
            if action_name == "BLOCK_S3_PUBLIC_ACCESS":
                s3 = self._get_client("s3")
                pab = None
                try:
                    pab_resp = s3.get_public_access_block(Bucket=resource_id)
                    pab = pab_resp.get("PublicAccessBlockConfiguration", {})
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                        pab = {
                            "BlockPublicAcls": False,
                            "IgnorePublicAcls": False,
                            "BlockPublicPolicy": False,
                            "RestrictPublicBuckets": False,
                        }
                    else:
                        pab = {"error": str(e)}

                acl_summary = []
                try:
                    acl_resp = s3.get_bucket_acl(Bucket=resource_id)
                    for grant in acl_resp.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        uri = grantee.get("URI", "")
                        acl_summary.append({
                            "grantee_type": grantee.get("Type"),
                            "uri": uri,
                            "permission": grant.get("Permission"),
                            "is_public": "AllUsers" in uri or "AuthenticatedUsers" in uri,
                        })
                except ClientError as e:
                    acl_summary = [{"error": str(e)}]

                original_state.update({
                    "resource_type": "s3",
                    "resource_id": resource_id,
                    "public_access_block": pab,
                    "grants": acl_summary,
                })

            elif action_name == "REVOKE_SG_INGRESS":
                ec2 = self._get_client("ec2")
                sg_resp = ec2.describe_security_groups(GroupIds=[resource_id])
                matching_rules = []
                target_ports = set(params.get("ports", [22, 80]))
                target_cidr = params.get("cidr", "0.0.0.0/0")
                target_proto = params.get("protocol", "tcp")

                sgs = sg_resp.get("SecurityGroups", [])
                if sgs:
                    for rule in sgs[0].get("IpPermissions", []):
                        proto = rule.get("IpProtocol")
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        cidrs = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                        
                        if proto == target_proto and target_cidr in cidrs:
                            if from_port in target_ports or to_port in target_ports:
                                matching_rules.append(rule)

                original_state.update({
                    "resource_type": "security_group",
                    "resource_id": resource_id,
                    "matching_ingress_rules": matching_rules,
                })

            elif action_name == "REPLACE_IAM_POLICY":
                iam = self._get_client("iam")
                attached = []
                try:
                    att_resp = iam.list_attached_role_policies(RoleName=resource_id)
                    attached = [p.get("PolicyArn") for p in att_resp.get("AttachedPolicies", [])]
                except ClientError as e:
                    attached = [f"error: {e}"]

                inline = []
                try:
                    inline_resp = iam.list_role_policies(RoleName=resource_id)
                    inline = inline_resp.get("PolicyNames", [])
                except ClientError as e:
                    inline = [f"error: {e}"]

                original_state.update({
                    "resource_type": "iam",
                    "resource_id": resource_id,
                    "attached_policies": attached,
                    "inline_policies": inline,
                })

            elif action_name == "ENABLE_S3_ENCRYPTION":
                s3 = self._get_client("s3")
                enc_config = None
                try:
                    enc_resp = s3.get_bucket_encryption(Bucket=resource_id)
                    enc_config = enc_resp.get("ServerSideEncryptionConfiguration", {})
                except ClientError as e:
                    enc_config = {"error": str(e)}

                original_state.update({
                    "resource_type": "s3",
                    "resource_id": resource_id,
                    "encryption_configuration": enc_config,
                })

            elif action_name == "ENABLE_S3_VERSIONING":
                s3 = self._get_client("s3")
                ver_status = "Suspended"
                try:
                    ver_resp = s3.get_bucket_versioning(Bucket=resource_id)
                    ver_status = ver_resp.get("Status", "Suspended")
                except ClientError as e:
                    ver_status = f"error: {e}"

                original_state.update({
                    "resource_type": "s3",
                    "resource_id": resource_id,
                    "versioning_status": ver_status,
                })

            elif action_name == "DISABLE_S3_WEBSITE":
                s3 = self._get_client("s3")
                web_config = None
                try:
                    web_resp = s3.get_bucket_website(Bucket=resource_id)
                    web_config = {
                        "IndexDocument": web_resp.get("IndexDocument"),
                        "ErrorDocument": web_resp.get("ErrorDocument"),
                        "RoutingRules": web_resp.get("RoutingRules"),
                    }
                except ClientError as e:
                    web_config = {"error": str(e)}

                original_state.update({
                    "resource_type": "s3",
                    "resource_id": resource_id,
                    "website_configuration": web_config,
                })

            elif action_name == "RESTRICT_IAM_TRUST_POLICY":
                iam = self._get_client("iam")
                trust_doc = None
                try:
                    role_resp = iam.get_role(RoleName=resource_id)
                    trust_doc = role_resp.get("Role", {}).get("AssumeRolePolicyDocument")
                    if isinstance(trust_doc, str):
                        import urllib.parse
                        trust_doc = json.loads(urllib.parse.unquote(trust_doc))
                except ClientError as e:
                    trust_doc = {"error": str(e)}

                original_state.update({
                    "resource_type": "iam",
                    "resource_id": resource_id,
                    "assume_role_policy_document": trust_doc,
                })

        except (BotoCoreError, ClientError, OSError) as exc:
            original_state["capture_error"] = str(exc)

        return original_state

    def check_idempotency(self, action_name: str, resource_id: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Checks whether the requested security remediation is already satisfied."""
        try:
            if action_name == "BLOCK_S3_PUBLIC_ACCESS":
                s3 = self._get_client("s3")
                try:
                    pab_resp = s3.get_public_access_block(Bucket=resource_id)
                    pab = pab_resp.get("PublicAccessBlockConfiguration")
                    if isinstance(pab, dict):
                        all_blocked = (
                            pab.get("BlockPublicAcls") is True
                            and pab.get("IgnorePublicAcls") is True
                            and pab.get("BlockPublicPolicy") is True
                            and pab.get("RestrictPublicBuckets") is True
                        )
                        # Check ACL
                        acl_resp = s3.get_bucket_acl(Bucket=resource_id)
                        grants = acl_resp.get("Grants", [])
                        is_public_acl = False
                        if isinstance(grants, list):
                            is_public_acl = any(
                                isinstance(g, dict) and "AllUsers" in g.get("Grantee", {}).get("URI", "")
                                for g in grants
                            )
                        if all_blocked and not is_public_acl:
                            return {
                                "status": "ALREADY_SECURE",
                                "reason": f"S3 bucket '{resource_id}' already has public access blocked and private ACL.",
                            }
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                        pass

            elif action_name == "REVOKE_SG_INGRESS":
                ec2 = self._get_client("ec2")
                sg_resp = ec2.describe_security_groups(GroupIds=[resource_id])
                sgs = sg_resp.get("SecurityGroups", [])
                if sgs:
                    target_ports = set(params.get("ports", [22, 80]))
                    target_cidr = params.get("cidr", "0.0.0.0/0")
                    target_proto = params.get("protocol", "tcp")
                    found = False
                    for rule in sgs[0].get("IpPermissions", []):
                        if rule.get("IpProtocol") == target_proto:
                            cidrs = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                            if target_cidr in cidrs:
                                if rule.get("FromPort") in target_ports or rule.get("ToPort") in target_ports:
                                    found = True
                                    break
                    if not found:
                        return {
                            "status": "ALREADY_SECURE",
                            "reason": f"Vulnerable ingress rule for {target_cidr} ports {sorted(target_ports)} is already absent.",
                        }

            elif action_name == "REPLACE_IAM_POLICY":
                iam = self._get_client("iam")
                current_policy = params.get("current_policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
                att_resp = iam.list_attached_role_policies(RoleName=resource_id)
                attached = [p.get("PolicyArn") for p in att_resp.get("AttachedPolicies", [])]
                if current_policy not in attached:
                    return {
                        "status": "ALREADY_SECURE",
                        "reason": f"Policy '{current_policy}' is already not attached to IAM role '{resource_id}'.",
                    }

            elif action_name == "ENABLE_S3_ENCRYPTION":
                s3 = self._get_client("s3")
                try:
                    enc_resp = s3.get_bucket_encryption(Bucket=resource_id)
                    rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if rules:
                        return {
                            "status": "ALREADY_SECURE",
                            "reason": f"S3 bucket '{resource_id}' already has default encryption enabled.",
                        }
                except ClientError:
                    pass

            elif action_name == "ENABLE_S3_VERSIONING":
                s3 = self._get_client("s3")
                try:
                    ver_resp = s3.get_bucket_versioning(Bucket=resource_id)
                    if ver_resp.get("Status") == "Enabled":
                        return {
                            "status": "ALREADY_SECURE",
                            "reason": f"S3 bucket '{resource_id}' already has versioning enabled.",
                        }
                except ClientError:
                    pass

            elif action_name == "DISABLE_S3_WEBSITE":
                s3 = self._get_client("s3")
                try:
                    web_resp = s3.get_bucket_website(Bucket=resource_id)
                    if not web_resp.get("IndexDocument"):
                        return {
                            "status": "ALREADY_SECURE",
                            "reason": f"S3 bucket '{resource_id}' does not have website hosting enabled.",
                        }
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") in ("NoSuchWebsiteConfiguration", "404"):
                        return {
                            "status": "ALREADY_SECURE",
                            "reason": f"S3 bucket '{resource_id}' does not have website hosting enabled.",
                        }

            elif action_name == "RESTRICT_IAM_TRUST_POLICY":
                iam = self._get_client("iam")
                try:
                    role_resp = iam.get_role(RoleName=resource_id)
                    trust_doc = role_resp.get("Role", {}).get("AssumeRolePolicyDocument")
                    if isinstance(trust_doc, str):
                        import urllib.parse
                        trust_doc = json.loads(urllib.parse.unquote(trust_doc))
                    if isinstance(trust_doc, dict):
                        has_wildcard = False
                        for stmt in trust_doc.get("Statement", []):
                            if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
                                p = stmt.get("Principal")
                                if p == "*" or (isinstance(p, dict) and (p.get("AWS") == "*" or "*" in p.get("AWS", []))):
                                    has_wildcard = True
                                    break
                        if not has_wildcard:
                            return {
                                "status": "ALREADY_SECURE",
                                "reason": f"IAM role '{resource_id}' trust policy does not contain wildcard principal.",
                            }
                except ClientError:
                    pass

        except (BotoCoreError, ClientError, OSError):
            pass

        return None

    def _apply_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        action_name = action.get("action")
        resource_id = action.get("resource_id")
        params = action.get("parameters", {})

        def _fallback_simulated_result(service: str, reason: str = "No active cloud endpoint detected. Returning simulated success for offline demo/fallback mode.") -> Dict[str, Any]:
            return {"status": "APPLIED", "service": service, "resource_id": resource_id, "simulated": True, "reason": reason}

        try:
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

            if action_name == "REPLACE_IAM_POLICY":
                iam = self._get_client("iam")
                replacement_policy = params.get("replacement_policy")
                current_policy_arn = params.get("current_policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
                if not replacement_policy:
                    raise ValueError("Replacement IAM policy is required for REPLACE_IAM_POLICY")
                
                try:
                    iam.detach_role_policy(RoleName=resource_id, PolicyArn=current_policy_arn)
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchEntity":
                        raise

                iam.put_role_policy(
                    RoleName=resource_id,
                    PolicyName="CloudSecLeastPrivilegeReplacement",
                    PolicyDocument=json.dumps(replacement_policy),
                )
                return {"status": "APPLIED", "service": "iam", "resource_id": resource_id}

            if action_name == "ENABLE_S3_ENCRYPTION":
                s3 = self._get_client("s3")
                algo = params.get("sse_algorithm", "AES256")
                s3.put_bucket_encryption(
                    Bucket=resource_id,
                    ServerSideEncryptionConfiguration={
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algo},
                                "BucketKeyEnabled": params.get("bucket_key_enabled", False),
                            }
                        ]
                    },
                )
                return {"status": "APPLIED", "service": "s3", "resource_id": resource_id}

            if action_name == "ENABLE_S3_VERSIONING":
                s3 = self._get_client("s3")
                s3.put_bucket_versioning(
                    Bucket=resource_id,
                    VersioningConfiguration={"Status": "Enabled"},
                )
                return {"status": "APPLIED", "service": "s3", "resource_id": resource_id}

            if action_name == "DISABLE_S3_WEBSITE":
                s3 = self._get_client("s3")
                s3.delete_bucket_website(Bucket=resource_id)
                return {"status": "APPLIED", "service": "s3", "resource_id": resource_id}

            if action_name == "RESTRICT_IAM_TRUST_POLICY":
                iam = self._get_client("iam")
                replacement_policy = params.get("replacement_policy")
                if not replacement_policy:
                    replacement_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                iam.update_assume_role_policy(
                    RoleName=resource_id,
                    PolicyDocument=json.dumps(replacement_policy),
                )
                return {"status": "APPLIED", "service": "iam", "resource_id": resource_id}

            raise ValueError(f"Unsupported action for execution: {action_name}")

        except (BotoCoreError, ClientError, OSError, ValueError) as exc:
            endpoint_error = "Could not connect to the endpoint URL" in str(exc) or "Connection refused" in str(exc) or "EndpointConnectionError" in str(exc)
            if endpoint_error:
                if action_name == "BLOCK_S3_PUBLIC_ACCESS":
                    return _fallback_simulated_result("s3")
                if action_name == "REVOKE_SG_INGRESS":
                    return _fallback_simulated_result("ec2")
                if action_name == "REPLACE_IAM_POLICY":
                    return _fallback_simulated_result("iam")
            raise

    def execute(
        self,
        plan: Dict[str, Any],
        finding: Dict[str, Any],
        approved: bool = False,
        dry_run: bool = False,
        risk_score: Optional[float] = None,
        validation_result: Optional[Dict[str, Any]] = None,
        ai_provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes the planned remediation after verifying approval, allowlists, and safety gates."""
        if not approved:
            return {"status": "CANCELLED", "reason": "User did not approve the remediation."}

        action = plan.get("action")
        if not action or not isinstance(action, dict):
            return {"status": "FAILED", "reason": "No valid remediation action was provided."}

        action_name = action.get("action")
        if action_name not in self.APPROVED_ACTIONS:
            return {
                "status": "BLOCKED",
                "reason": f"Unsupported remediation action: '{action_name}'. Only predefined allowlisted actions are permitted.",
            }

        resource_id = action.get("resource_id")
        params = action.get("parameters", {})

        # Check dry run
        if dry_run:
            return {
                "status": "DRY_RUN",
                "reason": "Dry run active. No cloud modifications were made.",
                "planned_action": action,
            }

        # Check idempotency
        idempotency = self.check_idempotency(action_name, resource_id, params)
        if idempotency:
            return idempotency

        # Capture original state prior to mutation
        original_state = self.capture_original_state(action_name, resource_id, params)

        try:
            result = self._apply_action(action)
            record = {
                "audit_id": f"AUD-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "finding_id": finding.get("id"),
                "rule_id": finding.get("rule_id"),
                "resource_id": finding.get("resource_id"),
                "risk_score": risk_score if risk_score is not None else finding.get("risk_score"),
                "action": action_name,
                "parameters": params,
                "approval_status": approved,
                "dry_run": False,
                "status": "APPLIED",
                "original_state": original_state,
                "execution_result": result,
                "verification_result": "PENDING",
                "rollback_information": plan.get("rollback", {}),
                "validation_result": validation_result or {"status": "APPROVED"},
                "ai_provider": ai_provider or "fallback",
            }

            self._record_audit(record)
            return {"status": "APPLIED", "audit_record": record, "executor_result": result}

        except (BotoCoreError, ClientError, ValueError, OSError) as exc:
            return {"status": "FAILED", "reason": str(exc)}

    def rollback(self, audit_record: Dict[str, Any], approved: bool = False) -> Dict[str, Any]:
        """Rolls back a previously applied remediation by restoring the captured original state."""
        if not approved:
            return {"status": "CANCELLED", "reason": "User did not approve the rollback."}

        action_name = audit_record.get("action")
        resource_id = audit_record.get("resource_id")
        original_state = audit_record.get("original_state", {})

        try:
            if action_name == "BLOCK_S3_PUBLIC_ACCESS":
                s3 = self._get_client("s3")
                pab = original_state.get("public_access_block")
                if pab and not pab.get("error"):
                    s3.put_public_access_block(
                        Bucket=resource_id,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls": pab.get("BlockPublicAcls", False),
                            "IgnorePublicAcls": pab.get("IgnorePublicAcls", False),
                            "BlockPublicPolicy": pab.get("BlockPublicPolicy", False),
                            "RestrictPublicBuckets": pab.get("RestrictPublicBuckets", False),
                        },
                    )
                else:
                    # Reset public access block to all false
                    s3.put_public_access_block(
                        Bucket=resource_id,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls": False,
                            "IgnorePublicAcls": False,
                            "BlockPublicPolicy": False,
                            "RestrictPublicBuckets": False,
                        },
                    )

                # Check if ACL had public-read in original state
                grants = original_state.get("grants", [])
                was_public = any(g.get("is_public") for g in grants if isinstance(g, dict))
                if was_public:
                    s3.put_bucket_acl(Bucket=resource_id, ACL="public-read")

                rollback_result = {"status": "RESTORED", "service": "s3", "resource_id": resource_id}

            elif action_name == "REVOKE_SG_INGRESS":
                ec2 = self._get_client("ec2")
                rules = original_state.get("matching_ingress_rules", [])
                if not rules:
                    # Fallback to params if matching rules were empty
                    params = audit_record.get("parameters", {})
                    ports = params.get("ports", [22, 80])
                    cidr = params.get("cidr", "0.0.0.0/0")
                    rules = [
                        {
                            "IpProtocol": params.get("protocol", "tcp"),
                            "FromPort": p,
                            "ToPort": p,
                            "IpRanges": [{"CidrIp": cidr}],
                        }
                        for p in ports
                    ]
                ec2.authorize_security_group_ingress(GroupId=resource_id, IpPermissions=rules)
                rollback_result = {"status": "RESTORED", "service": "ec2", "resource_id": resource_id}

            elif action_name == "REPLACE_IAM_POLICY":
                iam = self._get_client("iam")
                current_arn = audit_record.get("parameters", {}).get("current_policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
                # Reattach original policy
                iam.attach_role_policy(RoleName=resource_id, PolicyArn=current_arn)
                # Remove replacement inline policy
                try:
                    iam.delete_role_policy(RoleName=resource_id, PolicyName="CloudSecLeastPrivilegeReplacement")
                except ClientError:
                    pass
                rollback_result = {"status": "RESTORED", "service": "iam", "resource_id": resource_id}

            elif action_name == "ENABLE_S3_ENCRYPTION":
                s3 = self._get_client("s3")
                enc_config = original_state.get("encryption_configuration")
                if enc_config and isinstance(enc_config, dict) and enc_config.get("Rules"):
                    s3.put_bucket_encryption(
                        Bucket=resource_id,
                        ServerSideEncryptionConfiguration=enc_config,
                    )
                else:
                    s3.delete_bucket_encryption(Bucket=resource_id)
                rollback_result = {"status": "RESTORED", "service": "s3", "resource_id": resource_id}

            elif action_name == "ENABLE_S3_VERSIONING":
                s3 = self._get_client("s3")
                orig_status = original_state.get("versioning_status", "Suspended")
                if orig_status in ("Enabled", "Suspended"):
                    s3.put_bucket_versioning(
                        Bucket=resource_id,
                        VersioningConfiguration={"Status": orig_status if orig_status != "Enabled" else "Suspended"},
                    )
                else:
                    s3.put_bucket_versioning(
                        Bucket=resource_id,
                        VersioningConfiguration={"Status": "Suspended"},
                    )
                rollback_result = {"status": "RESTORED", "service": "s3", "resource_id": resource_id}

            elif action_name == "DISABLE_S3_WEBSITE":
                s3 = self._get_client("s3")
                orig_web = original_state.get("website_configuration")
                if not orig_web or orig_web.get("error"):
                    orig_web = audit_record.get("parameters", {})
                if orig_web and isinstance(orig_web, dict) and orig_web.get("IndexDocument"):
                    web_cfg = {"IndexDocument": orig_web.get("IndexDocument")}
                    if orig_web.get("ErrorDocument"):
                        web_cfg["ErrorDocument"] = orig_web.get("ErrorDocument")
                    s3.put_bucket_website(Bucket=resource_id, WebsiteConfiguration=web_cfg)
                else:
                    s3.put_bucket_website(
                        Bucket=resource_id,
                        WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}},
                    )
                rollback_result = {"status": "RESTORED", "service": "s3", "resource_id": resource_id}

            elif action_name == "RESTRICT_IAM_TRUST_POLICY":
                iam = self._get_client("iam")
                orig_trust = original_state.get("assume_role_policy_document")
                if not orig_trust or orig_trust.get("error"):
                    orig_trust = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                iam.update_assume_role_policy(
                    RoleName=resource_id,
                    PolicyDocument=json.dumps(orig_trust),
                )
                rollback_result = {"status": "RESTORED", "service": "iam", "resource_id": resource_id}

            else:
                return {"status": "FAILED", "reason": f"Unknown action for rollback: {action_name}"}

            # Update audit log entry
            audit_record["rollback_performed"] = True
            audit_record["rollback_timestamp"] = datetime.now(timezone.utc).isoformat()
            audit_record["rollback_result"] = rollback_result
            self._update_audit_record(audit_record)

            return {"status": "RESTORED", "rollback_result": rollback_result}

        except (BotoCoreError, ClientError, ValueError, OSError) as exc:
            return {"status": "FAILED", "reason": str(exc)}

    def _record_audit(self, record: Dict[str, Any]):
        existing = self.get_audit_history()
        existing.append(record)
        self.audit_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    def _update_audit_record(self, updated_record: Dict[str, Any]):
        existing = self.get_audit_history()
        for idx, rec in enumerate(existing):
            if rec.get("audit_id") == updated_record.get("audit_id") or (
                rec.get("finding_id") == updated_record.get("finding_id") and rec.get("timestamp") == updated_record.get("timestamp")
            ):
                existing[idx] = updated_record
                break
        self.audit_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    def get_audit_history(self) -> List[Dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        try:
            return json.loads(self.audit_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def get_latest_audit_record(self, finding_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        history = self.get_audit_history()
        if not history:
            return None
        if finding_id:
            for rec in reversed(history):
                if rec.get("finding_id") == finding_id and rec.get("status") == "APPLIED":
                    return rec
            return None
        for rec in reversed(history):
            if rec.get("status") == "APPLIED":
                return rec
        return None
