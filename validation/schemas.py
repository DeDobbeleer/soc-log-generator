#!/usr/bin/env python3
"""
Log Schema Definitions

Reference schemas for validating generated logs against real-world formats.
Based on official vendor documentation and sample logs.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class FieldType(Enum):
    """Field data types."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    IP = "ip_address"
    UUID = "uuid"
    JSON = "json"
    ENUM = "enum"


@dataclass
class FieldSchema:
    """Schema for a single field."""
    name: str
    field_type: FieldType
    required: bool = True
    pattern: Optional[str] = None
    allowed_values: Optional[List[str]] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    description: str = ""


@dataclass
class LogSchema:
    """Complete schema for a log type."""
    name: str
    description: str
    fields: List[FieldSchema]
    format_type: str  # json, syslog, csv, etc.
    sample_event: Optional[Dict[str, Any]] = None


class SchemaRegistry:
    """
    Registry of reference schemas for log validation.
    
    Provides schemas based on official vendor documentation:
    - AWS CloudTrail: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
    - Azure Activity Logs: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
    - Office 365: https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
    - GCP Audit Logs: https://cloud.google.com/logging/docs/audit/understanding-audit-logs
    """
    
    # AWS CloudTrail Schema (Core fields present in generator)
    AWS_CLOUDTRAIL = LogSchema(
        name="aws_cloudtrail",
        description="AWS CloudTrail Management Events",
        format_type="json",
        fields=[
            # Core identity fields
            FieldSchema("userIdentity", FieldType.JSON, required=True),
            FieldSchema("accountId", FieldType.STRING, required=True, pattern=r"^\d{12}$"),
            # Event identification
            FieldSchema("eventSource", FieldType.STRING, required=True, pattern=r"^[\w-]+\.amazonaws\.com$"),
            FieldSchema("eventName", FieldType.STRING, required=True),
            FieldSchema("awsRegion", FieldType.STRING, required=True, pattern=r"^[\w-]+-\d+$"),
            # Event metadata
            FieldSchema("readOnly", FieldType.BOOLEAN, required=False),
            FieldSchema("eventCategory", FieldType.STRING, required=True, allowed_values=["Management", "Data", "Insight"]),
            # Error tracking
            FieldSchema("errorCode", FieldType.STRING, required=False),
            FieldSchema("errorMessage", FieldType.STRING, required=False),
            # Top-level event fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),  # Actually EventSeverity enum
        ],
        sample_event={
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAAAAAAAAAAAAAAAAAA",
                "arn": "arn:aws:iam::123456789012:user/admin",
                "accountId": "123456789012",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "userName": "admin"
            },
            "eventTime": "2023-11-15T10:30:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.45",
            "userAgent": "aws-cli/2.13.0",
            "requestParameters": {"instancesSet": {}, "filterSet": {}},
            "responseElements": None,
            "requestID": "12345678-1234-1234-1234-123456789012",
            "eventID": "87654321-4321-4321-4321-210987654321",
            "readOnly": True,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "eventCategory": "Management"
        }
    )
    
    # Azure Activity Logs Schema (Core fields)
    AZURE_ACTIVITY = LogSchema(
        name="azure_activity",
        description="Azure Activity Logs",
        format_type="json",
        fields=[
            FieldSchema("subscriptionId", FieldType.STRING, required=True),
            FieldSchema("tenantId", FieldType.STRING, required=True),
            FieldSchema("resourceGroup", FieldType.STRING, required=True),
            FieldSchema("resourceProvider", FieldType.STRING, required=True),
            FieldSchema("resourceType", FieldType.STRING, required=True),
            FieldSchema("resourceId", FieldType.STRING, required=True),
            FieldSchema("operation", FieldType.STRING, required=True),
            FieldSchema("category", FieldType.STRING, required=True),
            FieldSchema("status", FieldType.STRING, required=True),
            FieldSchema("caller", FieldType.STRING, required=True),
            FieldSchema("correlationId", FieldType.UUID, required=True),
            FieldSchema("level", FieldType.STRING, required=True),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # Office 365 Schema (Core fields)
    OFFICE_365 = LogSchema(
        name="o365",
        description="Office 365 Unified Audit Logs",
        format_type="json",
        fields=[
            FieldSchema("workload", FieldType.STRING, required=True),
            FieldSchema("operation", FieldType.STRING, required=True),
            FieldSchema("userId", FieldType.STRING, required=True),
            FieldSchema("resultStatus", FieldType.STRING, required=True),
            FieldSchema("recordType", FieldType.INTEGER, required=True),
            FieldSchema("organizationId", FieldType.STRING, required=True),
            FieldSchema("application", FieldType.STRING, required=True),
            FieldSchema("objectId", FieldType.STRING, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # GCP Audit Logs Schema (Core fields)
    GCP_AUDIT = LogSchema(
        name="gcp_audit",
        description="GCP Cloud Audit Logs",
        format_type="json",
        fields=[
            FieldSchema("serviceName", FieldType.STRING, required=True),
            FieldSchema("methodName", FieldType.STRING, required=True),
            FieldSchema("resourceName", FieldType.STRING, required=True),
            FieldSchema("principalEmail", FieldType.STRING, required=True),
            FieldSchema("project_id", FieldType.STRING, required=True),
            FieldSchema("zone", FieldType.STRING, required=True),
            FieldSchema("severity", FieldType.STRING, required=True),
            FieldSchema("log_type", FieldType.STRING, required=True),
            FieldSchema("status", FieldType.JSON, required=True),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
        ]
    )
    
    # AWS VPC Flow Logs Schema - Core fields
    AWS_VPCFLOW = LogSchema(
        name="aws_vpcflow",
        description="AWS VPC Flow Logs",
        format_type="csv",
        fields=[
            FieldSchema("version", FieldType.INTEGER, required=True),
            FieldSchema("account_id", FieldType.STRING, required=True, pattern=r"^\d{12}$"),
            FieldSchema("interface_id", FieldType.STRING, required=True, pattern=r"^eni-[0-9a-f]{8,17}$"),
            FieldSchema("srcaddr", FieldType.IP, required=True),
            FieldSchema("dstaddr", FieldType.IP, required=True),
            FieldSchema("srcport", FieldType.INTEGER, required=True),
            FieldSchema("dstport", FieldType.INTEGER, required=True),
            FieldSchema("protocol", FieldType.INTEGER, required=True),
            FieldSchema("packets", FieldType.INTEGER, required=True),
            FieldSchema("bytes", FieldType.INTEGER, required=True),
            FieldSchema("action", FieldType.STRING, required=True, allowed_values=["ACCEPT", "REJECT"]),
            FieldSchema("log_status", FieldType.STRING, required=True, allowed_values=["OK", "NODATA", "SKIPDATA"]),
            FieldSchema("vpc_id", FieldType.STRING, required=False, pattern=r"^vpc-[0-9a-f]{8,17}$"),
            FieldSchema("subnet_id", FieldType.STRING, required=False, pattern=r"^subnet-[0-9a-f]{8,17}$"),
            FieldSchema("instance_id", FieldType.STRING, required=False, pattern=r"^i-[0-9a-f]{8,17}$"),
            FieldSchema("region", FieldType.STRING, required=False),
            FieldSchema("flow_direction", FieldType.STRING, required=False, allowed_values=["ingress", "egress"]),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # Azure AD Sign-in Schema - Core fields
    AZURE_SIGNIN = LogSchema(
        name="azure_signin",
        description="Azure AD Sign-in Logs",
        format_type="json",
        fields=[
            FieldSchema("userPrincipalName", FieldType.STRING, required=True),
            FieldSchema("userId", FieldType.STRING, required=True),
            FieldSchema("appId", FieldType.STRING, required=True),
            FieldSchema("appDisplayName", FieldType.STRING, required=True),
            FieldSchema("ipAddress", FieldType.IP, required=True),
            FieldSchema("clientAppUsed", FieldType.STRING, required=False),
            FieldSchema("correlationId", FieldType.UUID, required=True),
            FieldSchema("conditionalAccessStatus", FieldType.STRING, required=False),
            FieldSchema("isInteractive", FieldType.BOOLEAN, required=False),
            FieldSchema("riskLevelAggregated", FieldType.STRING, required=False),
            FieldSchema("riskState", FieldType.STRING, required=False),
            FieldSchema("status", FieldType.JSON, required=True),
            FieldSchema("userType", FieldType.STRING, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # Windows Event Log Schema (Core fields)
    WINDOWS_EVENT = LogSchema(
        name="windows",
        description="Windows Event Logs",
        format_type="xml",
        fields=[
            FieldSchema("EventID", FieldType.INTEGER, required=True),
            FieldSchema("Channel", FieldType.STRING, required=True),
            FieldSchema("Provider", FieldType.STRING, required=False),
            FieldSchema("Level", FieldType.STRING, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("source_host", FieldType.STRING, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # Linux Auth Log Schema (Core fields)
    LINUX_AUTH = LogSchema(
        name="linux",
        description="Linux Auth Logs (syslog)",
        format_type="syslog",
        fields=[
            FieldSchema("service", FieldType.STRING, required=True),
            FieldSchema("user", FieldType.STRING, required=False),
            FieldSchema("source_ip", FieldType.IP, required=False),
            FieldSchema("source_port", FieldType.INTEGER, required=False),
            FieldSchema("facility", FieldType.STRING, required=False),
            FieldSchema("priority", FieldType.STRING, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_host", FieldType.STRING, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # Firewall Schema (Palo Alto) - Core fields
    FIREWALL = LogSchema(
        name="firewall",
        description="Firewall Traffic Logs (Palo Alto)",
        format_type="csv",
        fields=[
            FieldSchema("vendor", FieldType.STRING, required=True),
            FieldSchema("type", FieldType.STRING, required=True),
            FieldSchema("src_ip", FieldType.IP, required=True),
            FieldSchema("dst_ip", FieldType.IP, required=True),
            FieldSchema("src_port", FieldType.INTEGER, required=True),
            FieldSchema("dst_port", FieldType.INTEGER, required=True),
            FieldSchema("protocol", FieldType.STRING, required=True),
            FieldSchema("action", FieldType.STRING, required=True),
            FieldSchema("app", FieldType.STRING, required=True),
            FieldSchema("category", FieldType.STRING, required=True),
            FieldSchema("session_id", FieldType.INTEGER, required=True),
            FieldSchema("bytes_sent", FieldType.INTEGER, required=True),
            FieldSchema("bytes_received", FieldType.INTEGER, required=True),
            FieldSchema("pkts_sent", FieldType.INTEGER, required=False),
            FieldSchema("pkts_received", FieldType.INTEGER, required=False),
            FieldSchema("src_zone", FieldType.STRING, required=False),
            FieldSchema("dst_zone", FieldType.STRING, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("source_ip", FieldType.IP, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # Proxy Schema - Core fields
    PROXY = LogSchema(
        name="proxy",
        description="Web Proxy Logs",
        format_type="csv",
        fields=[
            FieldSchema("vendor", FieldType.STRING, required=True),
            FieldSchema("action", FieldType.STRING, required=True),
            FieldSchema("method", FieldType.STRING, required=True),
            FieldSchema("url", FieldType.STRING, required=True),
            FieldSchema("code", FieldType.INTEGER, required=True),
            FieldSchema("category", FieldType.STRING, required=True),
            FieldSchema("src_ip", FieldType.IP, required=True),
            FieldSchema("bytes_sent", FieldType.INTEGER, required=False),
            FieldSchema("bytes_received", FieldType.INTEGER, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # DNS Schema - Core fields
    DNS = LogSchema(
        name="dns",
        description="DNS Query Logs",
        format_type="csv",
        fields=[
            FieldSchema("vendor", FieldType.STRING, required=True),
            FieldSchema("src_ip", FieldType.IP, required=True),
            FieldSchema("query", FieldType.STRING, required=True),
            FieldSchema("qtype", FieldType.STRING, required=True),
            FieldSchema("rcode", FieldType.INTEGER, required=True),
            FieldSchema("answer", FieldType.STRING, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    # IDS/IPS Schema (Suricata) - Core fields
    IDS = LogSchema(
        name="ids",
        description="IDS/IPS Event Logs (Suricata EVE)",
        format_type="json",
        fields=[
            FieldSchema("vendor", FieldType.STRING, required=True),
            FieldSchema("event_type", FieldType.STRING, required=True),
            FieldSchema("src_ip", FieldType.IP, required=True),
            FieldSchema("src_port", FieldType.INTEGER, required=True),
            FieldSchema("dest_ip", FieldType.IP, required=True),
            FieldSchema("dest_port", FieldType.INTEGER, required=True),
            FieldSchema("proto", FieldType.STRING, required=True),
            FieldSchema("alert", FieldType.JSON, required=False),
            # Top-level fields
            FieldSchema("source_type", FieldType.STRING, required=True),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=False),
        ]
    )
    
    _registry = {
        "aws": AWS_CLOUDTRAIL,
        "aws_cloudtrail": AWS_CLOUDTRAIL,
        "aws-vpcflow": AWS_VPCFLOW,
        "aws_vpcflow": AWS_VPCFLOW,
        "azure": AZURE_ACTIVITY,
        "azure_activity": AZURE_ACTIVITY,
        "azure-signin": AZURE_SIGNIN,
        "azure_signin": AZURE_SIGNIN,
        "o365": OFFICE_365,
        "gcp": GCP_AUDIT,
        "gcp_audit": GCP_AUDIT,
        "windows": WINDOWS_EVENT,
        "linux": LINUX_AUTH,
        "firewall": FIREWALL,
        "proxy": PROXY,
        "dns": DNS,
        "ids": IDS,
    }
    
    @classmethod
    def get_schema(cls, source_type: str) -> Optional[LogSchema]:
        """
        Get schema for a source type.
        
        Args:
            source_type: Log source type (e.g., 'aws_cloudtrail', 'windows')
            
        Returns:
            LogSchema or None if not found
        """
        return cls._registry.get(source_type.lower())
    
    @classmethod
    def list_schemas(cls) -> List[str]:
        """List all available schema names."""
        return list(set(cls._registry.keys()))
    
    @classmethod
    def register_schema(cls, name: str, schema: LogSchema) -> None:
        """
        Register a new schema.
        
        Args:
            name: Schema identifier
            schema: LogSchema instance
        """
        cls._registry[name.lower()] = schema
