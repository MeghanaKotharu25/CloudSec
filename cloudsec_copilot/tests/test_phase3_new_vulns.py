"""
Unit and integration tests for four new live vulnerabilities:
- VULN-008: RULE-S3-NO-ENCRYPTION -> ENABLE_S3_ENCRYPTION
- VULN-009: RULE-S3-NO-VERSIONING -> ENABLE_S3_VERSIONING
- VULN-010: RULE-S3-WEBSITE-ENABLED -> DISABLE_S3_WEBSITE
- VULN-011: RULE-IAM-WILDCARD-TRUST -> RESTRICT_IAM_TRUST_POLICY
"""

import json
import pytest
from cloudsec_copilot.discovery.models import (
    InfrastructureStateModel,
    ResourceInventoryModel,
    S3BucketModel,
    IAMRoleModel,
)
from cloudsec_copilot.scanner.scanner import Scanner
from cloudsec_copilot.remediation.remediation import RemediationPlanner
from cloudsec_copilot.ai.safety_validator import AISafetyValidator
from cloudsec_copilot.executor.executor import Executor
from cloudsec_copilot.verifier.verifier import Verifier


# =====================================================================
# 1. SCANNER TESTS FOR VULN-008..011
# =====================================================================

def test_scanner_detects_vuln_008_unencrypted_bucket():
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="cloudsec-vulnerable-unencrypted-bucket",
                    encryption_enabled=False,
                    versioning_enabled=True,
                    website_enabled=False,
                )
            ]
        )
    )
    findings = Scanner().scan(inventory)
    v8 = [f for f in findings if f["id"] == "VULN-008"]
    assert len(v8) == 1
    assert v8[0]["rule_id"] == "RULE-S3-NO-ENCRYPTION"
    assert v8[0]["severity"] == "HIGH"
    assert v8[0]["resource_id"] == "cloudsec-vulnerable-unencrypted-bucket"


def test_scanner_detects_vuln_009_unversioned_bucket():
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="cloudsec-vulnerable-versioning-bucket",
                    encryption_enabled=True,
                    versioning_enabled=False,
                    website_enabled=False,
                )
            ]
        )
    )
    findings = Scanner().scan(inventory)
    v9 = [f for f in findings if f["id"] == "VULN-009"]
    assert len(v9) == 1
    assert v9[0]["rule_id"] == "RULE-S3-NO-VERSIONING"
    assert v9[0]["severity"] == "MEDIUM"
    assert v9[0]["resource_id"] == "cloudsec-vulnerable-versioning-bucket"


def test_scanner_detects_vuln_010_website_bucket():
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="cloudsec-vulnerable-website-bucket",
                    encryption_enabled=True,
                    versioning_enabled=True,
                    website_enabled=True,
                    website_configuration={"IndexDocument": {"Suffix": "index.html"}},
                )
            ]
        )
    )
    findings = Scanner().scan(inventory)
    v10 = [f for f in findings if f["id"] == "VULN-010"]
    assert len(v10) == 1
    assert v10[0]["rule_id"] == "RULE-S3-WEBSITE-ENABLED"
    assert v10[0]["severity"] == "MEDIUM"
    assert v10[0]["resource_id"] == "cloudsec-vulnerable-website-bucket"


def test_scanner_detects_vuln_011_wildcard_trust_role():
    wildcard_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        ],
    }
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            iam_roles=[
                IAMRoleModel(
                    role_name="CloudSecVulnerableTrustRole",
                    arn="arn:aws:iam::123456789012:role/CloudSecVulnerableTrustRole",
                    assume_role_policy_document=wildcard_trust_policy,
                    trust_allows_wildcard=True,
                )
            ]
        )
    )
    findings = Scanner().scan(inventory)
    v11 = [f for f in findings if f["id"] == "VULN-011"]
    assert len(v11) == 1
    assert v11[0]["rule_id"] == "RULE-IAM-WILDCARD-TRUST"
    assert v11[0]["severity"] == "CRITICAL"
    assert v11[0]["resource_id"] == "CloudSecVulnerableTrustRole"


def test_scanner_safe_trust_role_not_flagged():
    safe_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            iam_roles=[
                IAMRoleModel(
                    role_name="SafeEc2Role",
                    arn="arn:aws:iam::123456789012:role/SafeEc2Role",
                    assume_role_policy_document=safe_trust_policy,
                    trust_allows_wildcard=False,
                )
            ]
        )
    )
    findings = Scanner().scan(inventory)
    assert not any(f["id"] == "VULN-011" for f in findings)


# =====================================================================
# 2. REMEDIATION PLANNER TESTS
# =====================================================================

def test_planner_vuln_008():
    planner = RemediationPlanner()
    plan = planner.plan("RULE-S3-NO-ENCRYPTION", "cloudsec-vulnerable-unencrypted-bucket")
    assert plan["action"]["action"] == "ENABLE_S3_ENCRYPTION"
    assert plan["action"]["resource_id"] == "cloudsec-vulnerable-unencrypted-bucket"
    assert plan["action"]["parameters"]["sse_algorithm"] == "AES256"
    assert plan["rollback"]["action"] == "RESTORE_S3_ENCRYPTION"


def test_planner_vuln_009():
    planner = RemediationPlanner()
    plan = planner.plan("RULE-S3-NO-VERSIONING", "cloudsec-vulnerable-versioning-bucket")
    assert plan["action"]["action"] == "ENABLE_S3_VERSIONING"
    assert plan["action"]["resource_id"] == "cloudsec-vulnerable-versioning-bucket"
    assert plan["action"]["parameters"]["status"] == "Enabled"
    assert plan["rollback"]["action"] == "RESTORE_S3_VERSIONING"


def test_planner_vuln_010():
    planner = RemediationPlanner()
    plan = planner.plan("RULE-S3-WEBSITE-ENABLED", "cloudsec-vulnerable-website-bucket")
    assert plan["action"]["action"] == "DISABLE_S3_WEBSITE"
    assert plan["action"]["resource_id"] == "cloudsec-vulnerable-website-bucket"
    assert plan["rollback"]["action"] == "RESTORE_S3_WEBSITE"


def test_planner_vuln_011():
    planner = RemediationPlanner()
    plan = planner.plan("RULE-IAM-WILDCARD-TRUST", "CloudSecVulnerableTrustRole")
    assert plan["action"]["action"] == "RESTRICT_IAM_TRUST_POLICY"
    assert plan["action"]["resource_id"] == "CloudSecVulnerableTrustRole"
    assert plan["action"]["parameters"]["replacement_principal"] == "ec2.amazonaws.com"
    assert plan["rollback"]["action"] == "RESTORE_IAM_TRUST_POLICY"


# =====================================================================
# 3. SAFETY VALIDATOR TESTS
# =====================================================================

def test_safety_validator_approved_plans():
    validator = AISafetyValidator()
    planner = RemediationPlanner()

    # VULN-008
    finding_008 = {"id": "VULN-008", "rule_id": "RULE-S3-NO-ENCRYPTION", "resource_id": "b-008", "resource_type": "s3"}
    plan_008 = planner.plan("RULE-S3-NO-ENCRYPTION", "b-008")
    assert validator.validate(finding_008, plan_008["action"])["status"] == "APPROVED"

    # VULN-009
    finding_009 = {"id": "VULN-009", "rule_id": "RULE-S3-NO-VERSIONING", "resource_id": "b-009", "resource_type": "s3"}
    plan_009 = planner.plan("RULE-S3-NO-VERSIONING", "b-009")
    assert validator.validate(finding_009, plan_009["action"])["status"] == "APPROVED"

    # VULN-010
    finding_010 = {"id": "VULN-010", "rule_id": "RULE-S3-WEBSITE-ENABLED", "resource_id": "b-010", "resource_type": "s3"}
    plan_010 = planner.plan("RULE-S3-WEBSITE-ENABLED", "b-010")
    assert validator.validate(finding_010, plan_010["action"])["status"] == "APPROVED"

    # VULN-011
    finding_011 = {"id": "VULN-011", "rule_id": "RULE-IAM-WILDCARD-TRUST", "resource_id": "role-011", "resource_type": "iam"}
    plan_011 = planner.plan("RULE-IAM-WILDCARD-TRUST", "role-011")
    assert validator.validate(finding_011, plan_011["action"])["status"] == "APPROVED"


def test_safety_validator_blocks_wildcard_principal_in_trust_policy():
    validator = AISafetyValidator()
    finding_011 = {"id": "VULN-011", "rule_id": "RULE-IAM-WILDCARD-TRUST", "resource_id": "role-011", "resource_type": "iam"}
    insecure_action = {
        "action": "RESTRICT_IAM_TRUST_POLICY",
        "resource_type": "iam",
        "resource_id": "role-011",
        "parameters": {
            "replacement_principal": "ec2.amazonaws.com",
            "replacement_policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}],
            },
        },
    }
    res = validator.validate(finding_011, insecure_action)
    assert res["status"] == "BLOCKED"
    assert any("Wildcard principal is strictly prohibited" in e for e in res["validation_errors"])


def test_safety_validator_blocks_target_mismatch():
    validator = AISafetyValidator()
    finding_008 = {"id": "VULN-008", "rule_id": "RULE-S3-NO-ENCRYPTION", "resource_id": "bucket-target-a", "resource_type": "s3"}
    mismatched_action = {
        "action": "ENABLE_S3_ENCRYPTION",
        "resource_type": "s3",
        "resource_id": "bucket-target-b",
        "parameters": {"sse_algorithm": "AES256", "bucket_key_enabled": False},
    }
    res = validator.validate(finding_008, mismatched_action)
    assert res["status"] == "BLOCKED"
    assert any("Target binding violation" in e for e in res["validation_errors"])


def test_safety_validator_blocks_dangerous_injection():
    validator = AISafetyValidator()
    finding = {"id": "VULN-008", "rule_id": "RULE-S3-NO-ENCRYPTION", "resource_id": "my-bucket", "resource_type": "s3"}
    dangerous_action = {
        "action": "ENABLE_S3_ENCRYPTION",
        "resource_type": "s3",
        "resource_id": "my-bucket",
        "parameters": {
            "sse_algorithm": "AES256; rm -rf /",
            "bucket_key_enabled": False,
        },
    }
    res = validator.validate(finding, dangerous_action)
    assert res["status"] == "BLOCKED"


# =====================================================================
# 4. EXECUTOR & VERIFIER TESTS
# =====================================================================

def test_executor_dry_run_for_new_actions(tmp_path):
    audit_file = tmp_path / "test_audit.json"
    executor = Executor(audit_path=str(audit_file))
    planner = RemediationPlanner()

    for rule_id, r_id, r_type in [
        ("RULE-S3-NO-ENCRYPTION", "bucket-8", "s3"),
        ("RULE-S3-NO-VERSIONING", "bucket-9", "s3"),
        ("RULE-S3-WEBSITE-ENABLED", "bucket-10", "s3"),
        ("RULE-IAM-WILDCARD-TRUST", "role-11", "iam"),
    ]:
        plan = planner.plan(rule_id, r_id, dry_run=True)
        finding = {"id": "VULN-TEST", "rule_id": rule_id, "resource_id": r_id, "resource_type": r_type}
        result = executor.execute(plan, finding, approved=True, dry_run=True)
        assert result["status"] == "DRY_RUN"


def test_verifier_confirms_removal_and_rollback():
    verifier = Verifier()

    finding_008 = {"id": "VULN-008", "rule_id": "RULE-S3-NO-ENCRYPTION", "resource_id": "b-8"}
    finding_009 = {"id": "VULN-009", "rule_id": "RULE-S3-NO-VERSIONING", "resource_id": "b-9"}

    before = [finding_008, finding_009]
    after = [finding_009]  # VULN-008 resolved

    res = verifier.verify_finding_removed(before, after, "VULN-008")
    assert res["status"] == "VERIFIED"

    # Rollback verification: finding reappears in after_rollback
    after_rollback = [finding_008, finding_009]
    rb_res = verifier.verify_rollback(after, after_rollback, "VULN-008")
    assert rb_res["status"] == "ROLLBACK_VERIFIED"
