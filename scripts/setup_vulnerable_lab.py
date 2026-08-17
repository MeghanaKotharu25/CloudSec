#!/usr/bin/env python3
"""
Setup script to provision vulnerable test cloud resources in LocalStack for CloudSec-Copilot.
Target Endpoint: http://localhost:4566 (LocalStack)
"""

import os
import sys
import time
from urllib import error, request

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

LOCALSTACK_ENDPOINT = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")


def wait_for_localstack(timeout_seconds: int = 120, interval_seconds: int = 2):
    """Wait until LocalStack health endpoint is ready before calling AWS APIs."""
    health_url = f"{LOCALSTACK_ENDPOINT}/_localstack/health"
    deadline = time.time() + timeout_seconds
    last_error = None

    while time.time() < deadline:
        try:
            with request.urlopen(health_url, timeout=5) as response:
                if response.status == 200:
                    return True
        except (error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
        time.sleep(interval_seconds)

    raise RuntimeError(
        f"LocalStack did not become ready within {timeout_seconds}s at {health_url}. "
        f"Last error: {last_error}"
    )


def get_boto3_client(service_name):
    return boto3.client(
        service_name,
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=AWS_REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test"
    )

def setup_public_s3_bucket(bucket_name="cloudsec-vulnerable-public-bucket"):
    print(f"[*] Creating S3 Bucket: {bucket_name}...")
    s3 = get_boto3_client("s3")
    try:
        s3.create_bucket(Bucket=bucket_name)
        print(f"[+] Bucket '{bucket_name}' created successfully.")
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" in str(e) or "BucketAlreadyExists" in str(e):
            print(f"[!] Bucket '{bucket_name}' already exists.")
        else:
            print(f"[-] Error creating bucket: {e}")

    # Remove Public Access Block to make it public
    try:
        s3.delete_public_access_block(Bucket=bucket_name)
        print(f"[+] Deleted public access block on bucket '{bucket_name}'.")
    except Exception as e:
        print(f"[!] Note on public access block: {e}")

    # Set ACL to public-read
    try:
        s3.put_bucket_acl(Bucket=bucket_name, ACL='public-read')
        print(f"[+] ACL set to public-read on '{bucket_name}'.")
    except Exception as e:
        print(f"[-] Failed to set ACL: {e}")

def setup_open_security_group():
    print("[*] Creating Open Security Group (0.0.0.0/0)...")
    ec2 = get_boto3_client("ec2")
    try:
        vpcs = ec2.describe_vpcs()
        vpc_id = vpcs['Vpcs'][0]['VpcId']
    except Exception as e:
        print(f"[-] Could not describe VPCs: {e}")
        return

    group_name = "open-secgroup-vulnerable"
    try:
        sg = ec2.create_security_group(
            GroupName=group_name,
            Description="Vulnerable security group open to world",
            VpcId=vpc_id
        )
        sg_id = sg['GroupId']
        print(f"[+] Security Group '{group_name}' created with ID: {sg_id}")
    except ClientError as e:
        if "InvalidGroup.Duplicate" in str(e):
            sgs = ec2.describe_security_groups(GroupNames=[group_name])
            sg_id = sgs['SecurityGroups'][0]['GroupId']
            print(f"[!] Security Group '{group_name}' already exists ({sg_id}).")
        else:
            print(f"[-] Error creating Security Group: {e}")
            return

    # Add 0.0.0.0/0 ingress rule for port 22 and 80
    try:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
        print(f"[+] Ingress 0.0.0.0/0 rules (port 22, 80) added to SG '{sg_id}'.")
    except ClientError as e:
        if "InvalidPermission.Duplicate" in str(e):
            print("[!] Ingress rules already exist.")
        else:
            print(f"[-] Error authorizing ingress: {e}")

def setup_admin_iam_role():
    print("[*] Creating Overly Permissive IAM Role...")
    iam = get_boto3_client("iam")
    role_name = "CloudSecVulnerableAdminRole"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    import json
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Vulnerable role with AdministratorAccess"
        )
        print(f"[+] IAM Role '{role_name}' created.")
    except ClientError as e:
        if "EntityAlreadyExists" in str(e):
            print(f"[!] IAM Role '{role_name}' already exists.")
        else:
            print(f"[-] Error creating IAM Role: {e}")

    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        print(f"[+] Attached 'AdministratorAccess' to IAM Role '{role_name}'.")
    except Exception as e:
        print(f"[-] Error attaching policy: {e}")

def setup_public_rds_instance():
    print("[*] Provisioning Vulnerable RDS Database...")
    rds = get_boto3_client("rds")
    db_id = "vulnerable-prod-db"
    try:
        rds.create_db_instance(
            DBInstanceIdentifier=db_id,
            AllocatedStorage=5,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="VulnerablePassword123!",
            PubliclyAccessible=True,
            StorageEncrypted=False
        )
        print(f"[+] RDS DB Instance '{db_id}' provisioned (PubliclyAccessible=True).")
    except ClientError as e:
        if "DBInstanceAlreadyExists" in str(e):
            print(f"[!] RDS DB Instance '{db_id}' already exists.")
        else:
            print(f"[-] Error creating RDS instance: {e}")

def main():
    print("==================================================")
    print(" CloudSec-Copilot: Vulnerable Lab Provisioner ")
    print(f" Target Endpoint: {LOCALSTACK_ENDPOINT}")
    print("==================================================")

    try:
        wait_for_localstack()
        print("[+] LocalStack is ready. Provisioning vulnerable resources...")
    except RuntimeError as exc:
        print(f"[-] {exc}")
        print("[!] Start LocalStack with: docker compose up -d")
        sys.exit(1)

    setup_public_s3_bucket()
    print("-" * 50)
    setup_open_security_group()
    print("-" * 50)
    setup_admin_iam_role()
    print("-" * 50)
    setup_public_rds_instance()
    print("==================================================")
    print(" Setup Complete! Ready for CloudSec-Copilot scan.")
    print("==================================================")

if __name__ == "__main__":
    main()
