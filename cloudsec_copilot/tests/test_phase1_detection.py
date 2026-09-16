"""
Unit tests for Phase 1: Expanded and Hardened Vulnerability Detection
"""

import pytest
from cloudsec_copilot.discovery.models import (
    InfrastructureStateModel,
    ResourceInventoryModel,
    S3BucketModel,
    SecurityGroupModel,
    InboundRuleModel,
    IAMRoleModel,
    IAMPolicyModel,
    RDSInstanceModel,
    EC2InstanceModel,
)
from cloudsec_copilot.scanner.scanner import Scanner


def test_s3_public_acl_detection():
    inventory = InfrastructureStateModel(
        region="eu-west-1",
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="acl-public-bucket",
                    is_public=True,
                    acl_public=True,
                    policy_public=False,
                    encryption_enabled=True,
                )
            ]
        ),
    )
    findings = Scanner().scan(inventory)
    s3_findings = [f for f in findings if f["id"] == "VULN-001"]
    assert len(s3_findings) == 1
    assert s3_findings[0]["rule_id"] == "RULE-S3-PUBLIC"
    assert s3_findings[0]["severity"] == "CRITICAL"
    assert s3_findings[0]["resource_id"] == "acl-public-bucket"
    assert s3_findings[0]["region"] == "eu-west-1"
    assert s3_findings[0]["details"]["acl_public"] is True
    # Bucket is encrypted, so no VULN-002
    assert not any(f["id"] == "VULN-002" for f in findings)


def test_s3_public_policy_detection():
    inventory = InfrastructureStateModel(
        region="us-west-2",
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="policy-public-bucket",
                    is_public=True,
                    acl_public=False,
                    policy_public=True,
                    encryption_enabled=False,
                )
            ]
        ),
    )
    findings = Scanner().scan(inventory)
    vuln_001 = [f for f in findings if f["id"] == "VULN-001"]
    vuln_002 = [f for f in findings if f["id"] == "VULN-002"]
    assert len(vuln_001) == 1
    assert vuln_001[0]["details"]["policy_public"] is True
    assert len(vuln_002) == 1
    assert vuln_002[0]["rule_id"] == "RULE-S3-NO-ENCRYPTION"
    assert vuln_001[0]["region"] == "us-west-2"


def test_s3_secure_bucket():
    inventory = InfrastructureStateModel(
        region="us-east-1",
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="secure-bucket",
                    is_public=False,
                    acl_public=False,
                    policy_public=False,
                    encryption_enabled=True,
                )
            ]
        ),
    )
    findings = Scanner().scan(inventory)
    assert len(findings) == 0


def test_ec2_public_detection():
    inventory = InfrastructureStateModel(
        region="ap-south-1",
        resources=ResourceInventoryModel(
            ec2_instances=[
                EC2InstanceModel(
                    instance_id="i-public-001",
                    instance_type="t3.medium",
                    state="running",
                    public_ip="13.233.10.20",
                    private_ip="10.0.1.5",
                    security_groups=["sg-12345"],
                    iam_instance_profile="AppRole",
                ),
                EC2InstanceModel(
                    instance_id="i-private-002",
                    instance_type="t3.small",
                    state="running",
                    public_ip=None,
                    private_ip="10.0.2.10",
                    security_groups=["sg-12345"],
                ),
            ]
        ),
    )
    findings = Scanner().scan(inventory)
    ec2_findings = [f for f in findings if f["id"] == "VULN-004"]
    assert len(ec2_findings) == 1
    assert ec2_findings[0]["rule_id"] == "RULE-EC2-PUBLIC"
    assert ec2_findings[0]["severity"] == "HIGH"
    assert ec2_findings[0]["resource_id"] == "i-public-001"
    assert ec2_findings[0]["resource_type"] == "EC2Instance"
    assert ec2_findings[0]["region"] == "ap-south-1"
    assert ec2_findings[0]["details"]["public_ip"] == "13.233.10.20"
    assert ec2_findings[0]["details"]["instance_type"] == "t3.medium"


def test_security_group_sensitive_port_detection():
    inventory = InfrastructureStateModel(
        region="us-east-1",
        resources=ResourceInventoryModel(
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-sensitive-1",
                    group_name="vulnerable-ports",
                    vpc_id="vpc-111",
                    inbound_rules=[
                        InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0"),
                        InboundRuleModel(protocol="tcp", from_port=3306, to_port=3306, cidr_ip="0.0.0.0/0"),
                        InboundRuleModel(protocol="tcp", from_port=80, to_port=80, cidr_ip="0.0.0.0/0"),
                        # Duplicate identical rule to test deduplication:
                        InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0"),
                    ],
                ),
                SecurityGroupModel(
                    group_id="sg-restricted-2",
                    group_name="internal-only",
                    vpc_id="vpc-222",
                    inbound_rules=[
                        InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="10.0.0.0/8"),
                        InboundRuleModel(protocol="tcp", from_port=3306, to_port=3306, cidr_ip="192.168.1.0/24"),
                    ],
                ),
            ]
        ),
    )
    findings = Scanner().scan(inventory)

    # VULN-003 for sg-sensitive-1 only
    open_findings = [f for f in findings if f["id"] == "VULN-003"]
    assert len(open_findings) == 1
    assert open_findings[0]["resource_id"] == "sg-sensitive-1"

    # VULN-006: Port 22 (SSH) and Port 3306 (MySQL)
    sensitive_findings = [f for f in findings if f["id"] == "VULN-006"]
    assert len(sensitive_findings) == 2  # SSH and MySQL (no duplicate for the second 22 rule, port 80 is not in sensitive DB/admin map)
    services = {f["details"]["service"] for f in sensitive_findings}
    assert services == {"SSH", "MySQL"}
    assert all(f["severity"] == "CRITICAL" for f in sensitive_findings)

    # sg-restricted-2 has no 0.0.0.0/0 rules, so no findings for it
    assert not any(f["resource_id"] == "sg-restricted-2" for f in findings)


def test_security_group_unrestricted_protocol_all():
    inventory = InfrastructureStateModel(
        region="us-east-1",
        resources=ResourceInventoryModel(
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-all-traffic",
                    group_name="allow-all",
                    inbound_rules=[
                        InboundRuleModel(protocol="-1", from_port=None, to_port=None, cidr_ip="0.0.0.0/0")
                    ],
                )
            ]
        ),
    )
    findings = Scanner().scan(inventory)
    vuln_006 = [f for f in findings if f["id"] == "VULN-006"]
    assert len(vuln_006) == 1
    assert vuln_006[0]["severity"] == "CRITICAL"
    assert vuln_006[0]["details"]["service"] == "All Traffic (Unrestricted)"


def test_iam_admin_and_wildcard_detection():
    inventory = InfrastructureStateModel(
        region="us-east-1",
        resources=ResourceInventoryModel(
            iam_roles=[
                IAMRoleModel(
                    role_name="FullAdminRole",
                    arn="arn:aws:iam::123456789012:role/FullAdminRole",
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                    policy_documents=[
                        {
                            "PolicyName": "AdministratorAccess",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            ],
                        }
                    ],
                ),
                IAMRoleModel(
                    role_name="S3WildcardRole",
                    arn="arn:aws:iam::123456789012:role/S3WildcardRole",
                    is_admin=False,
                    policy_documents=[
                        {
                            "PolicyName": "S3AllAccess",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:*"],
                                    "Resource": "*",
                                }
                            ],
                        }
                    ],
                ),
                IAMRoleModel(
                    role_name="LeastPrivilegeRole",
                    arn="arn:aws:iam::123456789012:role/LeastPrivilegeRole",
                    is_admin=False,
                    policy_documents=[
                        {
                            "PolicyName": "ReadOnlyS3",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject", "s3:ListBucket"],
                                    "Resource": "arn:aws:s3:::mybucket/*",
                                }
                            ],
                        }
                    ],
                ),
            ],
            iam_policies=[
                IAMPolicyModel(
                    policy_name="DangerousCustomPolicy",
                    arn="arn:aws:iam::123456789012:policy/DangerousCustomPolicy",
                    policy_document={
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["iam:*", "ec2:*"],
                                "Resource": "*",
                            }
                        ]
                    },
                )
            ],
        ),
    )
    findings = Scanner().scan(inventory)

    # VULN-005 for FullAdminRole
    admin_findings = [f for f in findings if f["id"] == "VULN-005"]
    assert len(admin_findings) == 1
    assert admin_findings[0]["resource_id"] == "FullAdminRole"

    # VULN-007 for wildcard permissions
    wildcard_findings = [f for f in findings if f["id"] == "VULN-007"]
    assert len(wildcard_findings) >= 3

    # Check FullAdminRole has global wildcard (*:*)
    full_admin_wildcard = [f for f in wildcard_findings if f["resource_id"] == "FullAdminRole"]
    assert len(full_admin_wildcard) == 1
    assert full_admin_wildcard[0]["severity"] == "CRITICAL"
    assert full_admin_wildcard[0]["details"]["wildcard_type"] == "GLOBAL_WILDCARD"

    # Check S3WildcardRole has service wildcard (s3:*)
    s3_wildcard = [f for f in wildcard_findings if f["resource_id"] == "S3WildcardRole"]
    assert len(s3_wildcard) == 1
    assert s3_wildcard[0]["details"]["wildcard_type"] == "SERVICE_WILDCARD"

    # Check DangerousCustomPolicy has service wildcard (iam:*, ec2:*)
    custom_policy_wildcard = [f for f in wildcard_findings if f["resource_id"] == "DangerousCustomPolicy"]
    assert len(custom_policy_wildcard) == 1

    # LeastPrivilegeRole must NOT have any VULN-007 finding
    assert not any(f["resource_id"] == "LeastPrivilegeRole" for f in findings)


def test_iam_scanner_resilience_to_malformed_docs():
    inventory = InfrastructureStateModel(
        region="us-east-1",
        resources=ResourceInventoryModel(
            iam_roles=[
                IAMRoleModel(
                    role_name="MalformedRole",
                    arn="arn:aws:iam::123456789012:role/MalformedRole",
                    policy_documents=["not-a-dict", {}, {"Statement": "invalid-statement"}],
                )
            ]
        ),
    )
    # Must not raise exceptions
    findings = Scanner().scan(inventory)
    assert len(findings) == 0


def test_rds_vulnerabilities():
    inventory = InfrastructureStateModel(
        region="ca-central-1",
        resources=ResourceInventoryModel(
            rds_instances=[
                RDSInstanceModel(
                    db_instance_identifier="vulnerable-db",
                    engine="mysql",
                    db_instance_class="db.t3.medium",
                    publicly_accessible=True,
                    storage_encrypted=False,
                    status="available",
                ),
                RDSInstanceModel(
                    db_instance_identifier="secure-db",
                    engine="postgres",
                    publicly_accessible=False,
                    storage_encrypted=True,
                    status="available",
                ),
            ]
        ),
    )
    findings = Scanner().scan(inventory)

    vuln_009 = [f for f in findings if f["id"] == "VULN-009"]
    vuln_010 = [f for f in findings if f["id"] == "VULN-010"]

    assert len(vuln_009) == 1
    assert vuln_009[0]["rule_id"] == "RULE-RDS-PUBLIC"
    assert vuln_009[0]["severity"] == "CRITICAL"
    assert vuln_009[0]["resource_id"] == "vulnerable-db"
    assert vuln_009[0]["region"] == "ca-central-1"

    assert len(vuln_010) == 1
    assert vuln_010[0]["rule_id"] == "RULE-RDS-NO-ENCRYPTION"
    assert vuln_010[0]["severity"] == "HIGH"
    assert vuln_010[0]["resource_id"] == "vulnerable-db"

    # secure-db has neither VULN-009 nor VULN-010
    assert not any(f["resource_id"] == "secure-db" for f in findings)


def test_ebs_vuln_008_not_implemented():
    inventory = InfrastructureStateModel(
        region="us-east-1",
        resources=ResourceInventoryModel(
            ec2_instances=[
                EC2InstanceModel(instance_id="i-test-01", public_ip=None, private_ip="10.0.0.1")
            ]
        ),
    )
    findings = Scanner().scan(inventory)
    # VULN-008 must not be fabricated
    assert not any(f["id"] == "VULN-008" for f in findings)
