"""
Pydantic data models for normalized cloud infrastructure resource state.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class InboundRuleModel(BaseModel):
    protocol: str = Field(default="-1")
    from_port: Optional[int] = Field(default=None)
    to_port: Optional[int] = Field(default=None)
    cidr_ip: str = Field(default="0.0.0.0/0")

class SecurityGroupModel(BaseModel):
    group_id: str
    group_name: str
    vpc_id: Optional[str] = None
    description: Optional[str] = None
    inbound_rules: List[InboundRuleModel] = Field(default_factory=list)

class S3BucketModel(BaseModel):
    name: str
    creation_date: Optional[str] = None
    is_public: bool = False
    acl_public: bool = False
    policy_public: bool = False
    encryption_enabled: bool = False
    arn: Optional[str] = None

class IAMRoleModel(BaseModel):
    role_name: str
    role_id: Optional[str] = None
    arn: str
    is_admin: bool = False
    attached_policies: List[str] = Field(default_factory=list)
    inline_policies: List[str] = Field(default_factory=list)

class IAMPolicyModel(BaseModel):
    policy_name: str
    policy_id: Optional[str] = None
    arn: str
    is_admin: bool = False

class RDSInstanceModel(BaseModel):
    db_instance_identifier: str
    engine: str = Field(default="postgres")
    db_instance_class: Optional[str] = "db.t3.micro"
    publicly_accessible: bool = False
    storage_encrypted: bool = False
    status: str = Field(default="available")

class EC2InstanceModel(BaseModel):
    instance_id: str
    instance_type: str = Field(default="t3.micro")
    state: str = Field(default="running")
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    security_groups: List[str] = Field(default_factory=list)
    iam_instance_profile: Optional[str] = None

class ResourceInventoryModel(BaseModel):
    s3_buckets: List[S3BucketModel] = Field(default_factory=list)
    security_groups: List[SecurityGroupModel] = Field(default_factory=list)
    iam_roles: List[IAMRoleModel] = Field(default_factory=list)
    iam_policies: List[IAMPolicyModel] = Field(default_factory=list)
    rds_instances: List[RDSInstanceModel] = Field(default_factory=list)
    ec2_instances: List[EC2InstanceModel] = Field(default_factory=list)

class InfrastructureStateModel(BaseModel):
    account_id: str = Field(default="123456789012")
    region: str = Field(default="us-east-1")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resources: ResourceInventoryModel = Field(default_factory=ResourceInventoryModel)
