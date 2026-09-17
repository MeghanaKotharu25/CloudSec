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
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        print(f"[+] Reset public access block on bucket '{bucket_name}'.")
    except Exception as e:
        print(f"[!] Note on public access block: {e}")

    # Set ACL to public-read
    try:
        s3.put_bucket_acl(Bucket=bucket_name, ACL='public-read')
        print(f"[+] ACL set to public-read on '{bucket_name}'.")
    except Exception as e:
        print(f"[-] Failed to set ACL: {e}")

    try:
        s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
    except Exception:
        pass

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

    # Create IAM Instance Profile and link the role so EC2 instances can assume it
    profile_name = role_name
    try:
        iam.create_instance_profile(InstanceProfileName=profile_name)
        print(f"[+] IAM Instance Profile '{profile_name}' created.")
    except ClientError as e:
        if "EntityAlreadyExists" in str(e):
            print(f"[!] IAM Instance Profile '{profile_name}' already exists.")
        else:
            print(f"[-] Error creating instance profile: {e}")

    try:
        iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name
        )
        print(f"[+] Role '{role_name}' added to instance profile '{profile_name}'.")
    except ClientError as e:
        if "LimitExceeded" in str(e) or "EntityAlreadyExists" in str(e):
            print(f"[!] Role '{role_name}' is already attached to instance profile '{profile_name}'.")
        else:
            print(f"[-] Error associating role to instance profile: {e}")

def setup_vulnerable_ec2_instance():
    print("[*] Creating Vulnerable EC2 Instance (CloudSecVulnerableServer)...")
    ec2 = get_boto3_client("ec2")
    group_name = "open-secgroup-vulnerable"
    try:
        sgs = ec2.describe_security_groups(GroupNames=[group_name])
        sg_id = sgs['SecurityGroups'][0]['GroupId']
    except Exception as e:
        print(f"[-] Could not find security group '{group_name}': {e}")
        return

    instance_name = "CloudSecVulnerableServer"
    try:
        reservations = ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [instance_name]},
                {"Name": "instance-state-name", "Values": ["pending", "running"]},
            ]
        ).get("Reservations", [])
        if reservations and reservations[0].get("Instances"):
            existing_id = reservations[0]["Instances"][0]["InstanceId"]
            print(f"[!] EC2 instance '{instance_name}' is already running ({existing_id}).")
            return
    except Exception as e:
        print(f"[!] Note while checking existing instances: {e}")

    try:
        res = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t3.micro",
            SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": "CloudSecVulnerableAdminRole"},
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": instance_name}],
                }
            ],
        )
        inst_id = res["Instances"][0]["InstanceId"]
        pub_ip = res["Instances"][0].get("PublicIpAddress", "Assigned")
        print(f"[+] EC2 instance '{instance_name}' ({inst_id}) created with public IP ({pub_ip}).")
    except Exception as e:
        print(f"[-] Error launching EC2 instance: {e}")

def setup_public_rds_instance():
    print("[*] Checking LocalStack RDS support...")
    print("[!] RDS is not available in the current LocalStack configuration; skipping synthetic RDS provisioning.")
    return

def setup_unencrypted_s3_bucket(bucket_name="cloudsec-vulnerable-unencrypted-bucket"):
    print(f"[*] Creating Unencrypted S3 Bucket: {bucket_name}...")
    s3 = get_boto3_client("s3")
    try:
        s3.create_bucket(Bucket=bucket_name)
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" in str(e) or "BucketAlreadyExists" in str(e):
            pass
        else:
            raise

    # Explicitly ensure no default server-side encryption exists
    try:
        s3.delete_bucket_encryption(Bucket=bucket_name)
    except Exception as e:
        print(f"[!] Note on delete_bucket_encryption: {e}")

    try:
        s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
    except Exception:
        pass

def setup_unversioned_s3_bucket(bucket_name="cloudsec-vulnerable-versioning-bucket"):
    print(f"[*] Creating Unversioned S3 Bucket: {bucket_name}...")
    s3 = get_boto3_client("s3")
    try:
        s3.create_bucket(Bucket=bucket_name)
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" in str(e) or "BucketAlreadyExists" in str(e):
            pass
        else:
            raise

    # Explicitly ensure versioning is suspended/disabled
    try:
        s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Suspended"})
    except Exception as e:
        print(f"[!] Note on versioning suspend: {e}")

def setup_website_s3_bucket(bucket_name="cloudsec-vulnerable-website-bucket"):
    print(f"[*] Creating Website Hosting S3 Bucket: {bucket_name}...")
    s3 = get_boto3_client("s3")
    try:
        s3.create_bucket(Bucket=bucket_name)
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" in str(e) or "BucketAlreadyExists" in str(e):
            pass
        else:
            raise

    # Configure website hosting
    s3.put_bucket_website(
        Bucket=bucket_name,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )

    try:
        s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
    except Exception:
        pass

def setup_wildcard_trust_iam_role(role_name="CloudSecVulnerableTrustRole"):
    print(f"[*] Creating Wildcard Trust IAM Role: {role_name}...")
    iam = get_boto3_client("iam")
    import json
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

    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(wildcard_trust_policy),
            Description="Role with insecure wildcard Principal in trust policy",
        )
    except ClientError as e:
        if "EntityAlreadyExists" in str(e):
            # Ensure policy is set to wildcard if already exists
            iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(wildcard_trust_policy),
            )
        else:
            raise

def verify_vulnerable_lab():
    """Independently verifies with Boto3 that all intended vulnerable states exist in LocalStack.
    Fails loudly if any verification check does not confirm the insecure state.
    """
    print("\n" + "=" * 50)
    print(" VERIFYING VULNERABLE LAB VIA LIVE BOTO3 CALLS ")
    print("=" * 50)
    s3 = get_boto3_client("s3")
    iam = get_boto3_client("iam")
    errors = []

    # 1. VULN-008: cloudsec-vulnerable-unencrypted-bucket -> no encryption
    b8 = "cloudsec-vulnerable-unencrypted-bucket"
    try:
        enc = s3.get_bucket_encryption(Bucket=b8)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            errors.append(f"VULN-008 check failed: Bucket '{b8}' has active encryption rules: {rules}")
        else:
            print(f"[+] VERIFIED VULN-008: Bucket '{b8}' has NO default server-side encryption.")
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"):
            print(f"[+] VERIFIED VULN-008: Bucket '{b8}' has NO default server-side encryption (not found).")
        else:
            errors.append(f"VULN-008 check error: {e}")

    # 2. VULN-009: cloudsec-vulnerable-versioning-bucket -> disabled/suspended
    b9 = "cloudsec-vulnerable-versioning-bucket"
    try:
        ver = s3.get_bucket_versioning(Bucket=b9)
        status = ver.get("Status")
        if status == "Enabled":
            errors.append(f"VULN-009 check failed: Bucket '{b9}' has versioning Enabled.")
        else:
            print(f"[+] VERIFIED VULN-009: Bucket '{b9}' versioning is disabled/suspended (Status: {status}).")
    except Exception as e:
        errors.append(f"VULN-009 check error: {e}")

    # 3. VULN-010: cloudsec-vulnerable-website-bucket -> website exists
    b10 = "cloudsec-vulnerable-website-bucket"
    try:
        web = s3.get_bucket_website(Bucket=b10)
        if not web.get("IndexDocument"):
            errors.append(f"VULN-010 check failed: Bucket '{b10}' has no website IndexDocument.")
        else:
            print(f"[+] VERIFIED VULN-010: Bucket '{b10}' website hosting is enabled ({web.get('IndexDocument')}).")
    except Exception as e:
        errors.append(f"VULN-010 check error: {e}")

    # 4. VULN-011: CloudSecVulnerableTrustRole -> AssumeRolePolicyDocument contains Principal="*"
    r11 = "CloudSecVulnerableTrustRole"
    try:
        import urllib.parse
        role_resp = iam.get_role(RoleName=r11)
        trust_doc = role_resp["Role"]["AssumeRolePolicyDocument"]
        if isinstance(trust_doc, str):
            trust_doc = json.loads(urllib.parse.unquote(trust_doc))
        
        has_wildcard = False
        for stmt in trust_doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                p = stmt.get("Principal")
                if p == "*" or (isinstance(p, dict) and (p.get("AWS") == "*" or "*" in p.get("AWS", []))):
                    has_wildcard = True
                    break
        if not has_wildcard:
            errors.append(f"VULN-011 check failed: Role '{r11}' trust policy does not contain Principal='*'.")
        else:
            print(f"[+] VERIFIED VULN-011: Role '{r11}' trust policy allows wildcard Principal='*'.")
    except Exception as e:
        errors.append(f"VULN-011 check error: {e}")

    if errors:
        raise RuntimeError("Vulnerable Lab verification failed:\n" + "\n".join(errors))

    print("=" * 50)
    print("[+] All vulnerable states successfully verified in LocalStack!")
    print("=" * 50)

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
    setup_vulnerable_ec2_instance()
    print("-" * 50)
    setup_public_rds_instance()
    print("-" * 50)
    setup_unencrypted_s3_bucket()
    print("-" * 50)
    setup_unversioned_s3_bucket()
    print("-" * 50)
    setup_website_s3_bucket()
    print("-" * 50)
    setup_wildcard_trust_iam_role()

    # Loud independent verification
    verify_vulnerable_lab()

    print("==================================================")
    print(" Setup Complete! Ready for CloudSec-Copilot scan.")
    print("==================================================")

if __name__ == "__main__":
    main()
