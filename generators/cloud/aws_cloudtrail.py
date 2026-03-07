#!/usr/bin/env python3
"""
AWS CloudTrail Log Generator

Generates realistic AWS CloudTrail audit logs for:
- EC2 instances (RunInstances, TerminateInstances, etc.)
- IAM operations (CreateUser, AttachUserPolicy, etc.)
- S3 operations (PutObject, GetObject, DeleteBucket, etc.)
- Lambda functions (CreateFunction, Invoke, etc.)
- KMS operations (Decrypt, GenerateDataKey, etc.)
- STS operations (AssumeRole, GetSessionToken, etc.)

CloudTrail logs are in JSON format and sent to S3 or CloudWatch Logs.
"""

import json
import random
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Handle imports for both module and script execution
try:
    from ...core import LogEvent, EventSeverity, AssetInventory
    from ...generators.base import BaseGenerator
except ImportError:
    from core import LogEvent, EventSeverity, AssetInventory
    from generators.base import BaseGenerator


class AWSCloudTrailGenerator(BaseGenerator):
    """
    Generator for AWS CloudTrail audit logs.
    
    Simulates API calls across AWS services with realistic patterns
    including both normal operations and suspicious activities.
    """
    
    # AWS Services and their common events
    SERVICES = {
        "ec2": {
            "eventSource": "ec2.amazonaws.com",
            "events": [
                ("RunInstances", "info", 0.3),
                ("TerminateInstances", "info", 0.15),
                ("DescribeInstances", "info", 0.25),
                ("CreateVolume", "info", 0.1),
                ("AttachVolume", "info", 0.08),
                ("AuthorizeSecurityGroupIngress", "warn", 0.05),
                ("RevokeSecurityGroupIngress", "info", 0.04),
                ("ModifyInstanceAttribute", "warn", 0.03),
            ]
        },
        "iam": {
            "eventSource": "iam.amazonaws.com",
            "events": [
                ("CreateUser", "info", 0.1),
                ("DeleteUser", "warn", 0.05),
                ("CreateAccessKey", "warn", 0.08),
                ("DeleteAccessKey", "info", 0.05),
                ("AttachUserPolicy", "warn", 0.1),
                ("DetachUserPolicy", "info", 0.05),
                ("CreateRole", "info", 0.15),
                ("AssumeRole", "info", 0.25),
                ("CreatePolicy", "info", 0.08),
                ("PutUserPolicy", "warn", 0.05),
                ("ListUsers", "info", 0.1),
            ]
        },
        "s3": {
            "eventSource": "s3.amazonaws.com",
            "events": [
                ("PutObject", "info", 0.35),
                ("GetObject", "info", 0.30),
                ("DeleteObject", "info", 0.15),
                ("CreateBucket", "info", 0.05),
                ("DeleteBucket", "warn", 0.03),
                ("PutBucketPolicy", "warn", 0.05),
                ("PutBucketAcl", "warn", 0.04),
                ("ListBuckets", "info", 0.03),
            ]
        },
        "lambda": {
            "eventSource": "lambda.amazonaws.com",
            "events": [
                ("CreateFunction", "info", 0.15),
                ("UpdateFunctionCode", "info", 0.25),
                ("Invoke", "info", 0.40),
                ("DeleteFunction", "warn", 0.05),
                ("AddPermission", "warn", 0.1),
                ("RemovePermission", "info", 0.05),
            ]
        },
        "kms": {
            "eventSource": "kms.amazonaws.com",
            "events": [
                ("Decrypt", "info", 0.35),
                ("Encrypt", "info", 0.30),
                ("GenerateDataKey", "info", 0.20),
                ("CreateKey", "info", 0.05),
                ("DisableKey", "warn", 0.05),
                ("ScheduleKeyDeletion", "warn", 0.05),
            ]
        },
        "sts": {
            "eventSource": "sts.amazonaws.com",
            "events": [
                ("AssumeRole", "info", 0.50),
                ("AssumeRoleWithSAML", "info", 0.20),
                ("GetSessionToken", "info", 0.20),
                ("AssumeRoleWithWebIdentity", "info", 0.10),
            ]
        },
        "cloudtrail": {
            "eventSource": "cloudtrail.amazonaws.com",
            "events": [
                ("LookupEvents", "info", 0.40),
                ("CreateTrail", "info", 0.15),
                ("UpdateTrail", "info", 0.20),
                ("DeleteTrail", "warn", 0.10),
                ("StartLogging", "info", 0.10),
                ("StopLogging", "critical", 0.05),
            ]
        },
        "rds": {
            "eventSource": "rds.amazonaws.com",
            "events": [
                ("CreateDBInstance", "info", 0.25),
                ("DeleteDBInstance", "warn", 0.10),
                ("ModifyDBInstance", "info", 0.30),
                ("CreateDBSnapshot", "info", 0.20),
                ("RestoreDBInstanceFromDBSnapshot", "info", 0.10),
                ("DeleteDBSnapshot", "warn", 0.05),
            ]
        },
    }
    
    # AWS Regions
    REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        "ap-south-1", "ca-central-1", "sa-east-1"
    ]
    
    # User agents
    USER_AGENTS = [
        "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0 source/x86_64",
        "aws-sdk-java/2.20.0 Linux/5.15.0 OpenJDK_64-Bit_Server_VM",
        "Boto3/1.28.0 Python/3.10.12",
        "aws-sdk-go/1.44.0 (go1.20.5; linux; amd64)",
        "console.amazonaws.com",
        "AWS Internal",
        "aws-sdk-nodejs/2.1400.0 linux/v18.16.0",
        "Terraform/1.5.0 (+https://www.terraform.io)"
    ]
    
    # Source IP ranges (simulating corporate network + external)
    SOURCE_IPS = [
        "203.0.113.",    # Corporate office
        "198.51.100.",   # VPN range
        "192.0.2.",      # Datacenter
    ]
    
    # Account IDs
    ACCOUNT_IDS = [
        "123456789012", "234567890123", "345678901234",
        "456789012345", "567890123456"
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: Optional[AssetInventory] = None):
        """
        Initialize AWS CloudTrail generator.
        
        Args:
            config: Generator configuration
            inventory: Asset inventory (optional, not used for cloud)
        """
        super().__init__(config)
        self.eps = config.get('eps', 100)
        self.inventory = inventory
        
    def _get_random_service(self) -> tuple:
        """Get a random AWS service and event."""
        service_name = random.choice(list(self.SERVICES.keys()))
        service = self.SERVICES[service_name]
        
        events = service["events"]
        event_names, levels, weights = zip(*events)
        event_name = random.choices(event_names, weights=weights)[0]
        level = levels[event_names.index(event_name)]
        
        return service_name, service["eventSource"], event_name, level
    
    def _get_severity(self, level: str) -> EventSeverity:
        """Map CloudTrail level to EventSeverity."""
        mapping = {
            "info": EventSeverity.LOW,
            "warn": EventSeverity.MEDIUM,
            "critical": EventSeverity.CRITICAL
        }
        return mapping.get(level, EventSeverity.LOW)
    
    def _generate_cloudtrail_event(self) -> Dict[str, Any]:
        """Generate a single CloudTrail event structure."""
        service_name, event_source, event_name, level = self._get_random_service()
        
        # Build base event
        event = {
            "eventVersion": "1.08",
            "userIdentity": self._generate_user_identity(),
            "eventTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": event_source,
            "eventName": event_name,
            "awsRegion": random.choice(self.REGIONS),
            "sourceIPAddress": self._generate_source_ip(),
            "userAgent": random.choice(self.USER_AGENTS),
            "requestParameters": self._generate_request_params(service_name, event_name),
            "responseElements": self._generate_response_elements(service_name, event_name),
            "requestID": str(uuid.uuid4()),
            "eventID": str(uuid.uuid4()),
            "readOnly": event_name.startswith(("Describe", "List", "Get", "Head")),
            "eventType": "AwsApiCall",
            "apiVersion": None,
            "managementEvent": True,
            "recipientAccountId": random.choice(self.ACCOUNT_IDS),
            "eventCategory": "Management"
        }
        
        # Add error information occasionally (5% error rate)
        if random.random() < 0.05:
            event["errorCode"] = random.choice([
                "AccessDenied",
                "UnauthorizedOperation",
                "InvalidParameterValue",
                "ResourceNotFoundException"
            ])
            event["errorMessage"] = f"User is not authorized to perform {event_name}"
            level = "critical"
        
        return event, level
    
    def _generate_user_identity(self) -> Dict[str, Any]:
        """Generate AWS user identity block."""
        identity_types = ["IAMUser", "AssumedRole", "Root", "FederatedUser"]
        identity_type = random.choices(
            identity_types, 
            weights=[0.5, 0.35, 0.05, 0.1]
        )[0]
        
        base = {
            "type": identity_type,
            "principalId": f"AID{uuid.uuid4().hex[:16].upper()}",
            "arn": f"arn:aws:iam::{random.choice(self.ACCOUNT_IDS)}:user/admin",
            "accountId": random.choice(self.ACCOUNT_IDS),
            "accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}"
        }
        
        if identity_type == "IAMUser":
            base["userName"] = random.choice([
                "admin", "developer", "deploy-user", "backup-service",
                "terraform", "ci-cd-pipeline", "security-audit"
            ])
        elif identity_type == "AssumedRole":
            role_name = random.choice([
                "AdminRole", "ReadOnlyRole", "DeploymentRole",
                "SecurityAuditRole", "CrossAccountRole"
            ])
            base["arn"] = f"arn:aws:sts::{base['accountId']}:assumed-role/{role_name}/session-name"
            base["sessionContext"] = {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": f"AROA{uuid.uuid4().hex[:16].upper()}",
                    "arn": f"arn:aws:iam::{base['accountId']}:role/{role_name}",
                    "accountId": base['accountId'],
                    "userName": role_name
                },
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "mfaAuthenticated": random.choice(["true", "false"])
                }
            }
        
        return base
    
    def _generate_source_ip(self) -> str:
        """Generate a realistic source IP address."""
        if random.random() < 0.7:  # 70% from corporate network
            prefix = random.choice(self.SOURCE_IPS)
            return f"{prefix}{random.randint(1, 254)}"
        else:  # 30% from external/public IPs
            return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _generate_request_params(self, service: str, event: str) -> Optional[Dict[str, Any]]:
        """Generate realistic request parameters."""
        params = {}
        
        if service == "ec2":
            if event == "RunInstances":
                params = {
                    "instancesSet": {"items": [{"imageId": f"ami-{uuid.uuid4().hex[:8]}"}]},
                    "instanceType": random.choice(["t3.micro", "t3.small", "m5.large", "c5.xlarge"]),
                    "blockDeviceMapping": {},
                    "monitoring": {"enabled": False},
                    "disableApiTermination": False
                }
            elif event == "AuthorizeSecurityGroupIngress":
                params = {
                    "groupId": f"sg-{uuid.uuid4().hex[:8]}",
                    "ipPermissions": {
                        "items": [{
                            "ipProtocol": random.choice(["tcp", "udp", "icmp"]),
                            "fromPort": random.choice([22, 80, 443, 3389]),
                            "toPort": random.choice([22, 80, 443, 3389]),
                            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}
                        }]
                    }
                }
        
        elif service == "iam":
            if event == "CreateUser":
                params = {"userName": f"user-{random.randint(1000, 9999)}"}
            elif event == "AttachUserPolicy":
                params = {
                    "userName": random.choice(["admin", "developer", "deploy-user"]),
                    "policyArn": f"arn:aws:iam::aws:policy/{random.choice(['AdministratorAccess', 'ReadOnlyAccess', 'PowerUserAccess'])}"
                }
            elif event == "AssumeRole":
                params = {
                    "roleArn": f"arn:aws:iam::{random.choice(self.ACCOUNT_IDS)}:role/{random.choice(['AdminRole', 'CrossAccountRole'])}",
                    "roleSessionName": f"session-{random.randint(1000, 9999)}"
                }
        
        elif service == "s3":
            if event == "PutObject":
                params = {
                    "bucketName": f"my-bucket-{random.randint(10000, 99999)}",
                    "key": random.choice([
                        "data/exports/backup.zip",
                        "logs/application.log",
                        "uploads/document.pdf",
                        "configs/settings.json"
                    ])
                }
            elif event == "PutBucketPolicy":
                params = {
                    "bucketName": f"my-bucket-{random.randint(10000, 99999)}",
                    "policy": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::example-bucket/*"
                        }]
                    })
                }
        
        elif service == "kms":
            if event == "Decrypt":
                params = {"keyId": f"arn:aws:kms:us-east-1:{random.choice(self.ACCOUNT_IDS)}:key/{uuid.uuid4()}"}
            elif event == "CreateKey":
                params = {"description": "Key for encrypting application data"}
        
        return params if params else None
    
    def _generate_response_elements(self, service: str, event: str) -> Optional[Dict[str, Any]]:
        """Generate realistic response elements."""
        if random.random() < 0.1:  # 10% no response (error cases)
            return None
        
        response = {"_return": True}
        
        if service == "ec2" and event == "RunInstances":
            response["instancesSet"] = {
                "items": [{
                    "instanceId": f"i-{uuid.uuid4().hex[:16]}",
                    "currentState": {"code": 0, "name": "pending"},
                    "previousState": {"code": 48, "name": "terminated"}
                }]
            }
        elif service == "iam" and event == "CreateUser":
            response["user"] = {
                "arn": f"arn:aws:iam::{random.choice(self.ACCOUNT_IDS)}:user/test-user",
                "createDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "userId": f"AID{uuid.uuid4().hex[:16].upper()}",
                "userName": "test-user"
            }
        
        return response
    
    def generate_event(self) -> LogEvent:
        """
        Generate a CloudTrail log event.
        
        Returns:
            LogEvent in CloudTrail JSON format
        """
        cloudtrail_data, level = self._generate_cloudtrail_event()
        
        # Determine source information
        source_ip = cloudtrail_data.get("sourceIPAddress", "unknown")
        region = cloudtrail_data.get("awsRegion", "us-east-1")
        
        # Create message
        user = cloudtrail_data["userIdentity"].get("userName", 
               cloudtrail_data["userIdentity"].get("type", "unknown"))
        message = f"AWS API Call: {cloudtrail_data['eventName']} by {user} from {source_ip}"
        
        # Add error info to message if present
        if "errorCode" in cloudtrail_data:
            message += f" - ERROR: {cloudtrail_data['errorCode']}"
        
        # Convert to JSON string for raw_log
        raw_log = json.dumps(cloudtrail_data, indent=None)
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="aws_cloudtrail",
            source_ip=source_ip,
            source_host=f"cloudtrail-{region}.amazonaws.com",
            message=message,
            raw_log=raw_log,
            fields={
                "eventSource": cloudtrail_data["eventSource"],
                "eventName": cloudtrail_data["eventName"],
                "awsRegion": region,
                "accountId": cloudtrail_data["recipientAccountId"],
                "userIdentity": cloudtrail_data["userIdentity"],
                "readOnly": cloudtrail_data["readOnly"],
                "eventCategory": cloudtrail_data["eventCategory"],
                "errorCode": cloudtrail_data.get("errorCode"),
                "errorMessage": cloudtrail_data.get("errorMessage")
            },
            tags=["aws", "cloudtrail", cloudtrail_data["eventSource"].split(".")[0]],
            severity=self._get_severity(level)
        )


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("AWS CloudTrail Generator Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    config = {"eps": 10}
    
    generator = AWSCloudTrailGenerator(config, inventory)
    
    for i in range(5):
        event = generator.generate_event()
        print(f"\nEvent {i+1}:")
        print(f"  Source: {event.source_type}")
        print(f"  Message: {event.message}")
        print(f"  Severity: {event.severity.name}")
        print(f"  Raw log preview: {event.raw_log[:150]}...")
