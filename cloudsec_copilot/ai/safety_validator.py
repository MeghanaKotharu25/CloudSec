from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


class AISafetyValidator:
    """AI Safety Validation Gate.

    Enforces strict allowlists, target binding, parameter validation,
    network/IAM safety rules, and blocks destructive actions or arbitrary code.
    Fails closed if any validation rule is violated.
    """

    APPROVED_ACTIONS = {
        "BLOCK_S3_PUBLIC_ACCESS": {
            "allowed_resource_types": {"s3", "s3bucket", "s3_bucket"},
            "allowed_params": {"block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"},
        },
        "REVOKE_SG_INGRESS": {
            "allowed_resource_types": {"security_group", "securitygroup", "sg"},
            "allowed_params": {"cidr", "protocol", "ports"},
        },
        "REPLACE_IAM_POLICY": {
            "allowed_resource_types": {"iam", "iamrole", "iam_role"},
            "allowed_params": {"current_policy_arn", "replacement_policy"},
        },
        "ENABLE_S3_ENCRYPTION": {
            "allowed_resource_types": {"s3", "s3bucket", "s3_bucket"},
            "allowed_params": {"sse_algorithm", "bucket_key_enabled"},
        },
        "ENABLE_S3_VERSIONING": {
            "allowed_resource_types": {"s3", "s3bucket", "s3_bucket"},
            "allowed_params": {"status"},
        },
        "DISABLE_S3_WEBSITE": {
            "allowed_resource_types": {"s3", "s3bucket", "s3_bucket"},
            "allowed_params": set(),
        },
        "RESTRICT_IAM_TRUST_POLICY": {
            "allowed_resource_types": {"iam", "iamrole", "iam_role"},
            "allowed_params": {"replacement_principal", "replacement_policy"},
        },
    }

    # Prohibited dangerous keywords or command execution attempts
    DANGEROUS_PATTERNS = [
        re.compile(r"\b(delete|terminate|drop|destroy|purge|truncate)\b", re.IGNORECASE),
        re.compile(r"\b(rm\s+-rf|shutdown|reboot|mkfs)\b", re.IGNORECASE),
        re.compile(r"\b(os\.system|subprocess|eval|exec|import\s+os|import\s+sys)\b", re.IGNORECASE),
        re.compile(r"\b(boto3\.client|boto3\.resource)\b", re.IGNORECASE),
    ]

    APPROVED_LEAST_PRIVILEGE_ACTIONS = {
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "logs:DescribeLogGroups",
    }

    def validate(
        self,
        finding: Dict[str, Any],
        planned_action: Dict[str, Any],
        ai_recommendation: Optional[Dict[str, Any]] = None,
        risk_score: Optional[float] = None,
        graph_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validates the planned remediation against strict safety policies.

        Returns:
            Dict containing:
                - status: 'APPROVED' or 'BLOCKED'
                - reason: Explanation of the validation outcome
                - validation_errors: List of specific policy violations
        """
        errors: List[str] = []

        if not planned_action or not isinstance(planned_action, dict):
            return {
                "status": "BLOCKED",
                "reason": "Planned action is missing or invalid.",
                "validation_errors": ["Action is None or not a dictionary."],
            }

        action_name = planned_action.get("action")
        target_resource_id = planned_action.get("resource_id")
        target_resource_type = str(planned_action.get("resource_type") or "").lower().replace(" ", "_")
        params = planned_action.get("parameters", {})

        # A. ACTION ALLOWLIST
        if action_name not in self.APPROVED_ACTIONS:
            errors.append(f"Action '{action_name}' is not in the approved remediation allowlist.")

        # B. TARGET BINDING
        finding_resource_id = finding.get("resource_id")
        if not target_resource_id or target_resource_id != finding_resource_id:
            errors.append(
                f"Target binding violation: Action resource_id '{target_resource_id}' "
                f"does not match finding resource_id '{finding_resource_id}'."
            )

        # C. RESOURCE TYPE BINDING
        finding_resource_type = str(finding.get("resource_type") or "").lower().replace(" ", "_")
        allowed_types = (
            self.APPROVED_ACTIONS.get(action_name, {}).get("allowed_resource_types", set())
            if action_name in self.APPROVED_ACTIONS
            else set()
        )
        if allowed_types:
            if not any(f_type in target_resource_type for f_type in allowed_types) or not any(
                f_type in finding_resource_type for f_type in allowed_types
            ):
                errors.append(
                    f"Resource type mismatch: Action type '{target_resource_type}' "
                    f"incompatible with finding type '{finding_resource_type}' for action '{action_name}'."
                )

        # D. PARAMETER VALIDATION
        if action_name in self.APPROVED_ACTIONS:
            allowed_params = self.APPROVED_ACTIONS[action_name]["allowed_params"]
            if not isinstance(params, dict):
                errors.append("Action parameters must be a dictionary.")
            else:
                extra_params = set(params.keys()) - allowed_params
                if extra_params:
                    errors.append(f"Disallowed parameters detected: {sorted(extra_params)}.")

        # E. NETWORK SAFETY
        if action_name == "REVOKE_SG_INGRESS":
            cidr = params.get("cidr")
            if cidr != "0.0.0.0/0":
                errors.append(f"Network safety violation: Expected CIDR '0.0.0.0/0', received '{cidr}'.")
            
            protocol = params.get("protocol")
            if protocol != "tcp":
                errors.append(f"Network safety violation: Expected protocol 'tcp', received '{protocol}'.")

            ports = params.get("ports")
            if not isinstance(ports, list) or not ports or not all(isinstance(p, int) for p in ports):
                errors.append(f"Network safety violation: Ports must be a non-empty list of integers, received: {ports}")
            else:
                # Check that only vulnerable ports from finding details are specified
                finding_details = finding.get("details", {})
                finding_open_ports = finding_details.get("open_ports")
                if finding_open_ports and isinstance(finding_open_ports, list):
                    unrelated_ports = set(ports) - set(finding_open_ports)
                    if unrelated_ports:
                        errors.append(f"Network safety violation: Attempting to modify ports {unrelated_ports} not present in finding.")

        # F. IAM SAFETY
        if action_name == "REPLACE_IAM_POLICY":
            current_arn = params.get("current_policy_arn")
            if current_arn != "arn:aws:iam::aws:policy/AdministratorAccess":
                errors.append(f"IAM safety violation: Invalid current_policy_arn '{current_arn}'.")

            replacement = params.get("replacement_policy")
            if not isinstance(replacement, dict):
                errors.append("IAM safety violation: Replacement policy must be a dictionary.")
            else:
                statements = replacement.get("Statement", [])
                if not isinstance(statements, list) or not statements:
                    errors.append("IAM safety violation: Replacement policy Statement must be a non-empty list.")
                else:
                    for stmt in statements:
                        effect = stmt.get("Effect")
                        if effect != "Allow":
                            errors.append(f"IAM safety violation: Statement effect must be 'Allow', found '{effect}'.")
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if not all(act in self.APPROVED_LEAST_PRIVILEGE_ACTIONS for act in actions):
                            unapproved = [act for act in actions if act not in self.APPROVED_LEAST_PRIVILEGE_ACTIONS]
                            errors.append(f"IAM safety violation: Unapproved IAM actions in policy: {unapproved}.")

        if action_name == "RESTRICT_IAM_TRUST_POLICY":
            repl_principal = params.get("replacement_principal")
            if repl_principal != "ec2.amazonaws.com":
                errors.append(f"IAM trust safety violation: Expected replacement_principal 'ec2.amazonaws.com', received '{repl_principal}'.")

            repl_policy = params.get("replacement_policy")
            if not isinstance(repl_policy, dict):
                errors.append("IAM trust safety violation: Replacement policy must be a dictionary.")
            else:
                stmts = repl_policy.get("Statement", [])
                if not isinstance(stmts, list) or not stmts:
                    errors.append("IAM trust safety violation: Replacement policy Statement must be a non-empty list.")
                else:
                    for stmt in stmts:
                        if stmt.get("Effect") != "Allow":
                            errors.append(f"IAM trust safety violation: Statement effect must be 'Allow', found '{stmt.get('Effect')}'.")
                        princ = stmt.get("Principal")
                        if princ == "*" or (isinstance(princ, dict) and (princ.get("AWS") == "*" or "*" in princ.get("AWS", []))):
                            errors.append("IAM trust safety violation: Wildcard principal is strictly prohibited.")
                        if isinstance(princ, dict) and princ.get("Service") != "ec2.amazonaws.com":
                            errors.append(f"IAM trust safety violation: Allowed principal service is 'ec2.amazonaws.com', found '{princ.get('Service')}'.")
                        act = stmt.get("Action")
                        if act != "sts:AssumeRole":
                            errors.append(f"IAM trust safety violation: Action must be 'sts:AssumeRole', found '{act}'.")

        if action_name == "ENABLE_S3_ENCRYPTION":
            algo = params.get("sse_algorithm", "AES256")
            if algo not in {"AES256", "aws:kms"}:
                errors.append(f"S3 encryption safety violation: Invalid sse_algorithm '{algo}'. Must be AES256 or aws:kms.")

        if action_name == "ENABLE_S3_VERSIONING":
            st = params.get("status")
            if st != "Enabled":
                errors.append(f"S3 versioning safety violation: Expected status 'Enabled', received '{st}'.")

        # G. DESTRUCTIVE ACTION & CODE INJECTION BLOCK
        serialized_action = str(planned_action)
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.search(serialized_action):
                errors.append(f"Destructive action or code injection pattern blocked: match '{pattern.pattern}'.")

        # Also inspect AI recommendation if provided to ensure no untrusted injection overrides
        if ai_recommendation and isinstance(ai_recommendation, dict):
            serialized_ai = str(ai_recommendation)
            for pattern in self.DANGEROUS_PATTERNS:
                if pattern.search(serialized_ai):
                    # Warning / blocking if AI recommended destructive action
                    errors.append(f"AI recommendation contained prohibited dangerous pattern: match '{pattern.pattern}'.")

        if errors:
            return {
                "status": "BLOCKED",
                "reason": f"Safety validation failed with {len(errors)} error(s).",
                "validation_errors": errors,
            }

        return {
            "status": "APPROVED",
            "reason": "Planned remediation passed all AI safety guardrails and policy allowlists.",
            "validation_errors": [],
        }
