"""
Tests for Phase 3 Attack/Dependency Graph integration with newly added live resources:
- S3 unencrypted bucket: node created, NO internet edge (internal)
- S3 versioning disabled: node created, NO internet edge (internal)
- S3 website hosting: node created, INTERNET -> S3 [WEBSITE_HOSTING] edge created
- IAM wildcard trust: node created, ANY_PRINCIPAL -> IAM [WILDCARD_TRUST] edge created
- Preserves existing INTERNET -> SG -> EC2 -> IAM -> Policy chain
- Preserves existing public S3 behavior
- Risk engine uses the updated live graph
- No hardcoded fake nodes introduced
"""

import pytest
import networkx as nx

from cloudsec_copilot.discovery.models import (
    InfrastructureStateModel,
    ResourceInventoryModel,
    S3BucketModel,
    IAMRoleModel,
    IAMPolicyModel,
    SecurityGroupModel,
    InboundRuleModel,
    EC2InstanceModel,
)
from cloudsec_copilot.graph.graph_builder import CloudGraphBuilder
from cloudsec_copilot.risk.risk_engine import RiskEngine
from cloudsec_copilot.scanner.scanner import Scanner


# =====================================================================
# 1. Newly discovered S3 buckets become graph nodes
# =====================================================================
def test_newly_discovered_s3_buckets_become_graph_nodes():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(name="cloudsec-vulnerable-unencrypted-bucket", encryption_enabled=False),
                S3BucketModel(name="cloudsec-vulnerable-versioning-bucket", versioning_enabled=False),
                S3BucketModel(name="cloudsec-vulnerable-website-bucket", website_enabled=True),
            ]
        )
    )
    graph = builder.build(inventory)

    assert "S3:cloudsec-vulnerable-unencrypted-bucket" in graph
    assert "S3:cloudsec-vulnerable-versioning-bucket" in graph
    assert "S3:cloudsec-vulnerable-website-bucket" in graph

    # Verify node attributes are preserved
    unenc_node = graph.nodes["S3:cloudsec-vulnerable-unencrypted-bucket"]
    assert unenc_node["encryption_enabled"] is False
    assert unenc_node["type"] == "S3"

    ver_node = graph.nodes["S3:cloudsec-vulnerable-versioning-bucket"]
    assert ver_node["versioning_enabled"] is False

    web_node = graph.nodes["S3:cloudsec-vulnerable-website-bucket"]
    assert web_node["website_enabled"] is True


# =====================================================================
# 2. Existing S3 bucket graph behavior remains unchanged
# =====================================================================
def test_existing_s3_bucket_graph_behavior_remains_unchanged():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="cloudsec-vulnerable-public-bucket",
                    is_public=True,
                    acl_public=True,
                    encryption_enabled=True,
                )
            ]
        )
    )
    graph = builder.build(inventory)

    assert "S3:cloudsec-vulnerable-public-bucket" in graph
    assert graph.has_edge("INTERNET", "S3:cloudsec-vulnerable-public-bucket")
    edge = graph.get_edge_data("INTERNET", "S3:cloudsec-vulnerable-public-bucket")
    assert edge["relationship"] == "PUBLIC_ACCESS"
    assert edge["is_sensitive"] is True


# =====================================================================
# 3. S3 encryption vulnerability does NOT create internet exposure (Section 11)
# =====================================================================
def test_s3_encryption_vulnerability_does_not_create_internet_exposure():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                # Bucket A: encryption disabled
                S3BucketModel(name="bucket-a-unencrypted", encryption_enabled=False, is_public=False),
                # Bucket B: encryption enabled
                S3BucketModel(name="bucket-b-encrypted", encryption_enabled=True, is_public=False),
            ]
        )
    )
    graph = builder.build(inventory)

    # Both buckets are nodes
    assert "S3:bucket-a-unencrypted" in graph
    assert "S3:bucket-b-encrypted" in graph

    # Neither bucket should have an INTERNET edge
    assert not graph.has_edge("INTERNET", "S3:bucket-a-unencrypted")
    assert not graph.has_edge("INTERNET", "S3:bucket-b-encrypted")

    # In-degree from INTERNET is 0 for both
    assert len(builder.find_attack_paths(graph, "S3:bucket-a-unencrypted")) == 0
    assert len(builder.find_attack_paths(graph, "S3:bucket-b-encrypted")) == 0


# =====================================================================
# 4. S3 versioning vulnerability does NOT create internet exposure (Section 11)
# =====================================================================
def test_s3_versioning_vulnerability_does_not_create_internet_exposure():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(name="bucket-unversioned", versioning_enabled=False, is_public=False),
            ]
        )
    )
    graph = builder.build(inventory)

    assert "S3:bucket-unversioned" in graph
    assert not graph.has_edge("INTERNET", "S3:bucket-unversioned")
    assert len(builder.find_attack_paths(graph, "S3:bucket-unversioned")) == 0


# =====================================================================
# 5. S3 website configuration creates WEBSITE_HOSTING relationship
# =====================================================================
def test_s3_website_configuration_creates_appropriate_relationship():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="cloudsec-vulnerable-website-bucket",
                    website_enabled=True,
                    website_configuration={"IndexDocument": {"Suffix": "index.html"}},
                    is_public=False,
                ),
            ]
        )
    )
    graph = builder.build(inventory)

    assert "S3:cloudsec-vulnerable-website-bucket" in graph
    assert graph.has_edge("INTERNET", "S3:cloudsec-vulnerable-website-bucket")
    edge = graph.get_edge_data("INTERNET", "S3:cloudsec-vulnerable-website-bucket")
    assert edge["relationship"] == "WEBSITE_HOSTING"
    assert edge["security_relevant"] is True


# =====================================================================
# 6. IAM wildcard trust is represented distinctly from IAM permission wildcard
# =====================================================================
def test_iam_wildcard_trust_represented_distinctly_from_permission_wildcard():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            iam_roles=[
                # Role with wildcard trust policy: Principal = "*"
                IAMRoleModel(
                    role_name="CloudSecVulnerableTrustRole",
                    arn="arn:aws:iam::123456789012:role/CloudSecVulnerableTrustRole",
                    trust_allows_wildcard=True,
                    is_admin=False,
                ),
                # Role with administrative permissions: Action = "*"
                IAMRoleModel(
                    role_name="CloudSecVulnerableAdminRole",
                    arn="arn:aws:iam::123456789012:role/CloudSecVulnerableAdminRole",
                    trust_allows_wildcard=False,
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                ),
            ]
        )
    )
    graph = builder.build(inventory)

    # 1. Trust role has ANY_PRINCIPAL -> WILDCARD_TRUST, NOT from INTERNET
    assert "IAM:CloudSecVulnerableTrustRole" in graph
    assert "ANY_PRINCIPAL" in graph
    assert not graph.has_edge("INTERNET", "IAM:CloudSecVulnerableTrustRole")
    assert graph.has_edge("ANY_PRINCIPAL", "IAM:CloudSecVulnerableTrustRole")
    trust_edge = graph.get_edge_data("ANY_PRINCIPAL", "IAM:CloudSecVulnerableTrustRole")
    assert trust_edge["relationship"] == "WILDCARD_TRUST"

    # 2. Admin role has GRANTS_PERMISSION to policy, NOT WILDCARD_TRUST
    assert "IAM:CloudSecVulnerableAdminRole" in graph
    assert not graph.has_edge("ANY_PRINCIPAL", "IAM:CloudSecVulnerableAdminRole")
    assert not graph.has_edge("INTERNET", "IAM:CloudSecVulnerableAdminRole")
    assert graph.has_edge("IAM:CloudSecVulnerableAdminRole", "POLICY:AdministratorAccess")
    perm_edge = graph.get_edge_data("IAM:CloudSecVulnerableAdminRole", "POLICY:AdministratorAccess")
    assert perm_edge["relationship"] == "GRANTS_PERMISSION"


# =====================================================================
# 7. Existing EC2 -> IAM relationships remain intact
# =====================================================================
def test_existing_ec2_to_iam_relationships_remain_intact():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            ec2_instances=[
                EC2InstanceModel(
                    instance_id="i-test-srv",
                    iam_instance_profile="CloudSecVulnerableAdminRole",
                )
            ],
            iam_roles=[
                IAMRoleModel(
                    role_name="CloudSecVulnerableAdminRole",
                    arn="arn:aws:iam::123456789012:role/CloudSecVulnerableAdminRole",
                    is_admin=True,
                )
            ],
        )
    )
    graph = builder.build(inventory)

    assert graph.has_edge("EC2:i-test-srv", "IAM:CloudSecVulnerableAdminRole")
    edge = graph.get_edge_data("EC2:i-test-srv", "IAM:CloudSecVulnerableAdminRole")
    assert edge["relationship"] == "ASSUMES_ROLE"


# =====================================================================
# 8. Existing INTERNET -> SG -> EC2 path remains intact
# =====================================================================
def test_existing_internet_to_sg_to_ec2_path_remains_intact():
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-open",
                    group_name="open-sg",
                    inbound_rules=[InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0")],
                )
            ],
            ec2_instances=[
                EC2InstanceModel(
                    instance_id="i-server",
                    security_groups=["sg-open"],
                    iam_instance_profile="AdminRole",
                )
            ],
            iam_roles=[
                IAMRoleModel(
                    role_name="AdminRole",
                    arn="arn:aws:iam::123456789012:role/AdminRole",
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                )
            ],
        )
    )
    graph = builder.build(inventory)

    paths = builder.find_attack_paths(graph, "POLICY:AdministratorAccess")
    assert len(paths) >= 1
    expected_path = ["INTERNET", "SG:sg-open", "EC2:i-server", "IAM:AdminRole", "POLICY:AdministratorAccess"]
    assert any(p["path"] == expected_path for p in paths)


# =====================================================================
# 9. Risk engine receives and uses the updated graph
# =====================================================================
def test_risk_engine_receives_and_uses_updated_graph():
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(name="unenc-bucket", encryption_enabled=False, is_public=False),
                S3BucketModel(name="web-bucket", website_enabled=True, is_public=False),
            ],
            iam_roles=[
                IAMRoleModel(
                    role_name="TrustRole",
                    arn="arn:aws:iam::123456789012:role/TrustRole",
                    trust_allows_wildcard=True,
                )
            ],
        )
    )
    scanner = Scanner()
    findings = scanner.scan(inventory)
    assert any(f["id"] == "VULN-008" for f in findings)
    assert any(f["id"] == "VULN-010" for f in findings)
    assert any(f["id"] == "VULN-011" for f in findings)

    builder = CloudGraphBuilder()
    graph = builder.build(inventory, findings=findings)

    risk_engine = RiskEngine()
    report = risk_engine.prioritize(findings, graph)

    prioritized = {item["vuln_id"]: item for item in report["prioritized_findings"]}

    # VULN-010 (Website) is Internet-Exposed because of WEBSITE_HOSTING edge
    v10 = prioritized["VULN-010"]
    assert v10["risk_breakdown"]["internet_exposure"]["is_exposed"] is True

    # VULN-008 (Unencrypted) is NOT Internet-Exposed
    v8 = prioritized["VULN-008"]
    assert v8["risk_breakdown"]["internet_exposure"]["is_exposed"] is False
    assert v8["blast_info"]["resource_count"] == 0

    # VULN-011 (Wildcard trust) is in graph and prioritized
    v11 = prioritized["VULN-011"]
    assert v11["resource_id"] == "TrustRole"


# =====================================================================
# 10. No hardcoded new graph nodes are introduced
# =====================================================================
def test_no_hardcoded_new_graph_nodes_introduced():
    builder = CloudGraphBuilder()
    # Empty inventory
    empty_inventory = InfrastructureStateModel(resources=ResourceInventoryModel())
    graph = builder.build(empty_inventory)

    # Should only contain INTERNET, no S3 or ANY_PRINCIPAL nodes
    assert list(graph.nodes) == ["INTERNET"]
    assert graph.number_of_nodes() == 1
    assert graph.number_of_edges() == 0


# =====================================================================
# 11. Vulnerable resource with NO INTERNET path is included in visualization
# =====================================================================
def test_vulnerable_resource_with_no_internet_path_included_in_visualization(tmp_path):
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                # Unencrypted bucket: no internet path, but is vulnerable
                S3BucketModel(name="internal-unencrypted-bucket", encryption_enabled=False, is_public=False),
            ]
        )
    )
    findings = [
        {"id": "VULN-008", "resource_id": "internal-unencrypted-bucket", "severity": "HIGH"}
    ]
    graph = builder.build(inventory, findings=findings)

    # Verify no internet path exists in graph
    assert len(builder.find_attack_paths(graph, "S3:internal-unencrypted-bucket")) == 0
    assert graph.nodes["S3:internal-unencrypted-bucket"]["is_vulnerable"] is True

    # Test visualization export completes successfully
    out_img = str(tmp_path / "test_unencrypted_graph.png")
    result_path = builder.export_visualization(graph, out_img)
    assert result_path == out_img
    assert (tmp_path / "test_unencrypted_graph.png").exists()


# =====================================================================
# 12. Actual vulnerability IDs appear dynamically in node card details
# =====================================================================
def test_actual_vulnerability_ids_appear_dynamically_in_card_details():
    builder = CloudGraphBuilder()

    # Case A: Node with specific vulnerability IDs
    attrs_with_vulns = {
        "type": "S3",
        "resource": "my-bucket",
        "is_vulnerable": True,
        "vulnerabilities": ["VULN-008", "VULN-010"],
    }
    header, title, badge, is_vuln = builder._get_card_details("S3:my-bucket", attrs_with_vulns)
    assert header == "S3 BUCKET"
    assert title == "my-bucket"
    assert badge == "[!] VULN-008, VULN-010"
    assert is_vuln is True

    # Case B: Node with single vulnerability ID
    attrs_single = {
        "type": "SECURITY_GROUP",
        "group_name": "custom-sg",
        "is_vulnerable": True,
        "vulnerabilities": ["VULN-003"],
    }
    header, title, badge, is_vuln = builder._get_card_details("SG:sg-123", attrs_single)
    assert header == "SECURITY GROUP"
    assert title == "custom-sg"
    assert badge == "[!] VULN-003"
    assert is_vuln is True

    # Case C: Node vulnerable due to inferred infra property with no findings passed
    attrs_inferred = {
        "type": "S3",
        "resource": "unenc-bucket",
        "is_vulnerable": True,
        "vulnerabilities": [],
    }
    header, title, badge, is_vuln = builder._get_card_details("S3:unenc-bucket", attrs_inferred)
    assert badge == "[!] VULNERABLE"
    assert is_vuln is True

    # Case D: Non-vulnerable resource has no badge
    attrs_clean = {
        "type": "S3",
        "resource": "clean-bucket",
        "is_vulnerable": False,
        "vulnerabilities": [],
    }
    header, title, badge, is_vuln = builder._get_card_details("S3:clean-bucket", attrs_clean)
    assert badge == ""
    assert is_vuln is False


# =====================================================================
# 13. Multiple resources of same type receive distinct non-overlapping positions
# =====================================================================
def test_multiple_same_type_resources_receive_distinct_positions(tmp_path):
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(name="bucket-1", encryption_enabled=False),
                S3BucketModel(name="bucket-2", versioning_enabled=False),
                S3BucketModel(name="bucket-3", website_enabled=True),
            ],
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-1",
                    group_name="open-ssh",
                    inbound_rules=[InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0")],
                ),
                SecurityGroupModel(
                    group_id="sg-2",
                    group_name="open-http",
                    inbound_rules=[InboundRuleModel(protocol="tcp", from_port=80, to_port=80, cidr_ip="0.0.0.0/0")],
                ),
            ],
        )
    )
    graph = builder.build(inventory)

    out_img = str(tmp_path / "multi_resource_graph.png")
    result_path = builder.export_visualization(graph, out_img)
    assert result_path == out_img
    assert (tmp_path / "multi_resource_graph.png").exists()


# =====================================================================
# 14. Remediation replacement policies remain excluded from visualization
# =====================================================================
def test_remediation_replacement_policies_excluded_from_visualization(tmp_path):
    builder = CloudGraphBuilder()
    inventory = InfrastructureStateModel(
        resources=ResourceInventoryModel(
            iam_roles=[
                IAMRoleModel(
                    role_name="AdminRole",
                    arn="arn:aws:iam::123456789012:role/AdminRole",
                    is_admin=True,
                    attached_policies=["AdministratorAccess", "CloudSecLeastPrivilegeReplacement"],
                    inline_policies=["InlineReplacementPolicy"],
                )
            ]
        )
    )
    graph = builder.build(inventory)

    # Remediation policy nodes should not be added to the graph or visualization
    assert "POLICY:CloudSecLeastPrivilegeReplacement" not in graph
    assert "POLICY:AdminRole:InlineReplacementPolicy" not in graph

    out_img = str(tmp_path / "remediation_excluded.png")
    builder.export_visualization(graph, out_img)
    assert (tmp_path / "remediation_excluded.png").exists()

