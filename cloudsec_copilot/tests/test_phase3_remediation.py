import json
from unittest.mock import MagicMock, patch

import pytest

from cloudsec_copilot.ai.ai_reasoner import AIReasoner
from cloudsec_copilot.ai.safety_validator import AISafetyValidator
from cloudsec_copilot.discovery.collector import DiscoveryCollector
from cloudsec_copilot.executor.executor import Executor
from cloudsec_copilot.remediation.remediation import RemediationPlanner
from cloudsec_copilot.scanner.scanner import Scanner
from cloudsec_copilot.verifier.verifier import Verifier


@pytest.fixture
def sample_s3_finding():
    return {
        "id": "VULN-001",
        "rule_id": "RULE-S3-PUBLIC",
        "resource_id": "test-public-bucket",
        "resource_type": "s3",
        "title": "Public S3 bucket exposure",
        "severity": "CRITICAL",
        "details": {"bucket_name": "test-public-bucket"},
    }


@pytest.fixture
def sample_sg_finding():
    return {
        "id": "VULN-002",
        "rule_id": "RULE-SG-OPEN",
        "resource_id": "sg-12345",
        "resource_type": "security_group",
        "title": "Open ingress port 22",
        "severity": "CRITICAL",
        "details": {"open_ports": [22, 80]},
    }


@pytest.fixture
def sample_iam_finding():
    return {
        "id": "VULN-003",
        "rule_id": "RULE-IAM-ADMIN",
        "resource_id": "AdminRole",
        "resource_type": "iam",
        "title": "Overly permissive AdministratorAccess role",
        "severity": "HIGH",
        "details": {},
    }


def test_01_valid_s3_remediation_passes_validation(sample_s3_finding):
    plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
    validator = AISafetyValidator()
    result = validator.validate(sample_s3_finding, plan["action"])
    assert result["status"] == "APPROVED"
    assert not result["validation_errors"]


def test_02_valid_sg_remediation_passes_validation(sample_sg_finding):
    plan = RemediationPlanner().plan("RULE-SG-OPEN", sample_sg_finding["resource_id"], dry_run=False, finding_details=sample_sg_finding["details"])
    validator = AISafetyValidator()
    result = validator.validate(sample_sg_finding, plan["action"])
    assert result["status"] == "APPROVED"
    assert not result["validation_errors"]


def test_03_valid_iam_remediation_passes_validation(sample_iam_finding):
    plan = RemediationPlanner().plan("RULE-IAM-ADMIN", sample_iam_finding["resource_id"], dry_run=False)
    validator = AISafetyValidator()
    result = validator.validate(sample_iam_finding, plan["action"])
    assert result["status"] == "APPROVED"
    assert not result["validation_errors"]


def test_04_unknown_action_is_blocked(sample_s3_finding):
    unsafe_action = {
        "action": "DELETE_ALL_BUCKETS",
        "resource_type": "s3",
        "resource_id": sample_s3_finding["resource_id"],
        "parameters": {},
    }
    validator = AISafetyValidator()
    result = validator.validate(sample_s3_finding, unsafe_action)
    assert result["status"] == "BLOCKED"
    assert any("not in the approved remediation allowlist" in err for err in result["validation_errors"])


def test_05_wrong_resource_id_is_blocked(sample_s3_finding):
    plan = RemediationPlanner().plan("RULE-S3-PUBLIC", "different-bucket-id", dry_run=False)
    validator = AISafetyValidator()
    result = validator.validate(sample_s3_finding, plan["action"])
    assert result["status"] == "BLOCKED"
    assert any("Target binding violation" in err for err in result["validation_errors"])


def test_06_wrong_resource_type_is_blocked(sample_s3_finding):
    mismatched_action = {
        "action": "BLOCK_S3_PUBLIC_ACCESS",
        "resource_type": "iam_role",
        "resource_id": sample_s3_finding["resource_id"],
        "parameters": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
    }
    validator = AISafetyValidator()
    result = validator.validate(sample_s3_finding, mismatched_action)
    assert result["status"] == "BLOCKED"
    assert any("Resource type mismatch" in err for err in result["validation_errors"])


def test_07_unknown_parameters_are_blocked(sample_s3_finding):
    plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
    plan["action"]["parameters"]["malicious_extra_param"] = "exploit"
    validator = AISafetyValidator()
    result = validator.validate(sample_s3_finding, plan["action"])
    assert result["status"] == "BLOCKED"
    assert any("Disallowed parameters detected" in err for err in result["validation_errors"])


def test_08_arbitrary_shell_python_boto3_code_is_blocked(sample_sg_finding):
    unsafe_action = {
        "action": "REVOKE_SG_INGRESS",
        "resource_type": "security_group",
        "resource_id": sample_sg_finding["resource_id"],
        "parameters": {"cidr": "0.0.0.0/0", "protocol": "tcp", "ports": [22], "code": "os.system('id')"},
    }
    validator = AISafetyValidator()
    result = validator.validate(sample_sg_finding, unsafe_action)
    assert result["status"] == "BLOCKED"
    assert any("Destructive action or code injection" in err or "Disallowed parameters" in err for err in result["validation_errors"])


def test_09_destructive_action_is_blocked(sample_s3_finding):
    destructive_action = {
        "action": "TERMINATE_INSTANCE",
        "resource_type": "ec2",
        "resource_id": "i-12345",
        "parameters": {},
    }
    validator = AISafetyValidator()
    result = validator.validate(sample_s3_finding, destructive_action)
    assert result["status"] == "BLOCKED"


def test_10_human_approval_is_required(sample_s3_finding, tmp_path):
    plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
    executor = Executor(audit_path=str(tmp_path / "audit_log.json"))
    result = executor.execute(plan, sample_s3_finding, approved=False)
    assert result["status"] == "CANCELLED"
    assert "did not approve" in result["reason"]


def test_11_dry_run_does_not_mutate_cloud(sample_s3_finding, tmp_path):
    plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=True)
    fake_s3 = MagicMock()
    with patch("cloudsec_copilot.executor.executor.boto3.client", return_value=fake_s3):
        executor = Executor(audit_path=str(tmp_path / "audit_log.json"))
        result = executor.execute(plan, sample_s3_finding, approved=True, dry_run=True)
        assert result["status"] == "DRY_RUN"
        fake_s3.put_public_access_block.assert_not_called()
        fake_s3.put_bucket_acl.assert_not_called()


def test_12_original_state_is_captured_before_mutation(sample_s3_finding, tmp_path):
    fake_s3 = MagicMock()
    fake_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }
    fake_s3.get_bucket_acl.return_value = {
        "Grants": [
            {
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }
        ]
    }

    with patch("cloudsec_copilot.executor.executor.boto3.client", return_value=fake_s3):
        executor = Executor(audit_path=str(tmp_path / "audit_log.json"))
        plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
        result = executor.execute(plan, sample_s3_finding, approved=True)
        assert result["status"] == "APPLIED"
        audit_rec = result["audit_record"]
        assert "original_state" in audit_rec
        assert audit_rec["original_state"]["public_access_block"]["BlockPublicAcls"] is False
        assert any(g["is_public"] for g in audit_rec["original_state"]["grants"])


def test_13_successful_remediation_verified_by_rescan(sample_s3_finding):
    before = [sample_s3_finding]
    after = []
    verifier = Verifier()
    result = verifier.verify_finding_removed(before, after, sample_s3_finding["id"])
    assert result["status"] == "VERIFIED"


def test_14_failed_verification_not_reported_as_success(sample_s3_finding):
    before = [sample_s3_finding]
    after = [sample_s3_finding]
    verifier = Verifier()
    result = verifier.verify_finding_removed(before, after, sample_s3_finding["id"])
    assert result["status"] == "REMEDIATION_FAILED"


def test_15_rollback_restores_captured_state(sample_s3_finding, tmp_path):
    fake_s3 = MagicMock()
    with patch("cloudsec_copilot.executor.executor.boto3.client", return_value=fake_s3):
        executor = Executor(audit_path=str(tmp_path / "audit_log.json"))
        audit_record = {
            "audit_id": "AUD-001",
            "action": "BLOCK_S3_PUBLIC_ACCESS",
            "resource_id": sample_s3_finding["resource_id"],
            "original_state": {
                "public_access_block": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "grants": [{"is_public": True}],
            },
        }
        res = executor.rollback(audit_record, approved=True)
        assert res["status"] == "RESTORED"
        fake_s3.put_public_access_block.assert_called_once()
        fake_s3.put_bucket_acl.assert_called_once_with(Bucket=sample_s3_finding["resource_id"], ACL="public-read")


def test_16_rollback_verification_works(sample_s3_finding):
    verifier = Verifier()
    verified_res = verifier.verify_rollback([], [sample_s3_finding], sample_s3_finding["id"])
    assert verified_res["status"] == "ROLLBACK_VERIFIED"

    failed_res = verifier.verify_rollback([], [], sample_s3_finding["id"])
    assert failed_res["status"] == "ROLLBACK_FAILED"


def test_17_rerunning_already_applied_remediation_handled_safely(sample_s3_finding, tmp_path):
    fake_s3 = MagicMock()
    fake_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    fake_s3.get_bucket_acl.return_value = {"Grants": []}

    with patch("cloudsec_copilot.executor.executor.boto3.client", return_value=fake_s3):
        executor = Executor(audit_path=str(tmp_path / "audit_log.json"))
        plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
        result = executor.execute(plan, sample_s3_finding, approved=True)
        assert result["status"] == "ALREADY_SECURE"


def test_18_llm_output_cannot_override_planner_approved_action(sample_s3_finding):
    malicious_ai_recommendation = {
        "action": {"action": "delete_bucket", "resource_id": "different-target"},
        "summary": "Attacker injecting delete bucket",
    }
    plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
    validator = AISafetyValidator()
    val_result = validator.validate(sample_s3_finding, plan["action"], ai_recommendation=malicious_ai_recommendation)
    assert val_result["status"] == "BLOCKED"
    assert any("prohibited dangerous pattern" in err for err in val_result["validation_errors"])


def test_19_llm_failure_uses_deterministic_fallback_safely(sample_s3_finding):
    with patch.dict("os.environ", {}, clear=True):
        reasoner = AIReasoner()
        output = reasoner.reason(sample_s3_finding, 8.5, {"entry_points": ["INTERNET"]})
        assert output["provider"] == "fallback"
        assert output["summary"]

        plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
        validator = AISafetyValidator()
        val = validator.validate(sample_s3_finding, plan["action"], ai_recommendation=output)
        assert val["status"] == "APPROVED"


def test_20_audit_log_contains_required_fields(sample_s3_finding, tmp_path):
    audit_file = tmp_path / "audit_log.json"
    fake_s3 = MagicMock()
    fake_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }
    fake_s3.get_bucket_acl.return_value = {
        "Grants": [
            {
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }
        ]
    }
    with patch("cloudsec_copilot.executor.executor.boto3.client", return_value=fake_s3):
        executor = Executor(audit_path=str(audit_file))
        plan = RemediationPlanner().plan("RULE-S3-PUBLIC", sample_s3_finding["resource_id"], dry_run=False)
        executor.execute(plan, sample_s3_finding, approved=True, risk_score=8.5)

    assert audit_file.exists()
    records = json.loads(audit_file.read_text(encoding="utf-8"))
    assert len(records) >= 1
    rec = records[-1]

    required_fields = [
        "timestamp",
        "finding_id",
        "rule_id",
        "resource_id",
        "risk_score",
        "action",
        "parameters",
        "approval_status",
        "dry_run",
        "original_state",
        "execution_result",
        "verification_result",
        "rollback_information",
        "validation_result",
    ]
    for field in required_fields:
        assert field in rec, f"Missing required audit field: {field}"

    raw_text = audit_file.read_text()
    for sensitive_word in ["AWS_SECRET_ACCESS_KEY", "OPENROUTER_API_KEY", "HF_API_TOKEN"]:
        assert sensitive_word not in raw_text


def test_21_live_localstack_closed_loop_pipeline():
    try:
        from scripts.setup_vulnerable_lab import setup_public_s3_bucket
        setup_public_s3_bucket("cloudsec-vulnerable-public-bucket")
    except Exception:
        pass

    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)
    s3_finding = next((f for f in findings if f["rule_id"] == "RULE-S3-PUBLIC"), None)
    if not s3_finding:
        pytest.skip("LocalStack S3 public bucket finding not present; skipping live pipeline check.")

    plan = RemediationPlanner().plan("RULE-S3-PUBLIC", s3_finding["resource_id"], dry_run=False)
    validator = AISafetyValidator()
    val = validator.validate(s3_finding, plan["action"])
    assert val["status"] == "APPROVED"

    executor = Executor()
    exec_result = executor.execute(plan, s3_finding, approved=True)
    assert exec_result["status"] in {"APPLIED", "ALREADY_SECURE"}

    after_snapshot = collector.collect_all()
    after_findings = Scanner().scan(after_snapshot)
    verifier = Verifier()
    ver_result = verifier.verify_finding_removed([s3_finding], after_findings, s3_finding["id"])
    assert ver_result["status"] == "VERIFIED"

    # Rollback test on live LocalStack
    audit_rec = exec_result.get("audit_record") or executor.get_latest_audit_record(s3_finding["id"])
    assert audit_rec is not None
    rb_result = executor.rollback(audit_rec, approved=True)
    assert rb_result["status"] == "RESTORED"

    rb_snapshot = collector.collect_all()
    rb_findings = Scanner().scan(rb_snapshot)
    rb_ver = verifier.verify_rollback([], rb_findings, s3_finding["id"])
    assert rb_ver["status"] == "ROLLBACK_VERIFIED"
