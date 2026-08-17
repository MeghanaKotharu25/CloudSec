"""
Unit tests for Cloud Discovery Engine.
"""

import os
import json
import pytest
from cloudsec_copilot.discovery.collector import DiscoveryCollector
from cloudsec_copilot.discovery.models import (
    InfrastructureStateModel,
    S3BucketModel,
    SecurityGroupModel,
    IAMRoleModel,
    RDSInstanceModel,
)

def test_discovery_collector_initialization():
    collector = DiscoveryCollector(endpoint_url="http://localhost:4566")
    assert collector.endpoint_url == "http://localhost:4566"
    assert collector.region_name == "us-east-1"

def test_list_buckets():
    collector = DiscoveryCollector(endpoint_url="http://localhost:4566")
    buckets = collector.list_buckets()
    assert isinstance(buckets, list)
    assert len(buckets) >= 1
    assert isinstance(buckets[0], S3BucketModel)

def test_list_security_groups():
    collector = DiscoveryCollector(endpoint_url="http://localhost:4566")
    sgs = collector.list_security_groups()
    assert isinstance(sgs, list)
    assert len(sgs) >= 1
    assert isinstance(sgs[0], SecurityGroupModel)

def test_list_iam_roles():
    collector = DiscoveryCollector(endpoint_url="http://localhost:4566")
    roles = collector.list_iam_roles()
    assert isinstance(roles, list)
    assert len(roles) >= 1
    assert isinstance(roles[0], IAMRoleModel)

def test_list_rds_instances():
    collector = DiscoveryCollector(endpoint_url="http://localhost:4566")
    rds_instances = collector.list_rds_instances()

    assert isinstance(rds_instances, list)
    assert all(isinstance(db, RDSInstanceModel) for db in rds_instances)
    assert len(rds_instances) >= 0

def test_export_snapshot(tmp_path):
    output_file = tmp_path / "infra_state.json"
    collector = DiscoveryCollector(endpoint_url="http://localhost:4566")
    snapshot = collector.export_snapshot(output_path=str(output_file))
    
    assert isinstance(snapshot, InfrastructureStateModel)
    assert os.path.exists(output_file)
    
    with open(output_file, "r") as f:
        data = json.load(f)
        
    assert "account_id" in data
    assert "resources" in data
    assert "s3_buckets" in data["resources"]
    assert "security_groups" in data["resources"]
