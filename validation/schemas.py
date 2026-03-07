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
    
    # AWS CloudTrail Schema
    AWS_CLOUDTRAIL = LogSchema(
        name="aws_cloudtrail",
        description="AWS CloudTrail Management Events",
        format_type="json",
        fields=[
            FieldSchema("eventVersion", FieldType.STRING, required=True, pattern=r"^1\.\d+$"),
            FieldSchema("userIdentity", FieldType.JSON, required=True),
            FieldSchema("eventTime", FieldType.DATETIME, required=True, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"),
            FieldSchema("eventSource", FieldType.STRING, required=True, pattern=r"^[\w-]+\.amazonaws\.com$"),
            FieldSchema("eventName", FieldType.STRING, required=True),
            FieldSchema("awsRegion", FieldType.STRING, required=True, pattern=r"^[\w-]+-\d+$"),
            FieldSchema("sourceIPAddress", FieldType.IP, required=True),
            FieldSchema("userAgent", FieldType.STRING, required=True),
            FieldSchema("errorCode", FieldType.STRING, required=False),
            FieldSchema("errorMessage", FieldType.STRING, required=False),
            FieldSchema("requestParameters", FieldType.JSON, required=False),
            FieldSchema("responseElements", FieldType.JSON, required=False),
            FieldSchema("requestID", FieldType.UUID, required=True),
            FieldSchema("eventID", FieldType.UUID, required=True),
            FieldSchema("eventType", FieldType.STRING, required=True, allowed_values=["AwsApiCall", "AwsServiceEvent"]),
            FieldSchema("apiVersion", FieldType.STRING, required=False),
            FieldSchema("managementEvent", FieldType.BOOLEAN, required=True),
            FieldSchema("readOnly", FieldType.BOOLEAN, required=True),
            FieldSchema("resources", FieldType.JSON, required=False),
            FieldSchema("recipientAccountId", FieldType.STRING, required=True, pattern=r"^\d{12}$"),
            FieldSchema("sharedEventID", FieldType.UUID, required=False),
            FieldSchema("vpcEndpointId", FieldType.STRING, required=False),
            FieldSchema("eventCategory", FieldType.STRING, required=True, allowed_values=["Management", "Data", "Insight"]),
            FieldSchema("addendum", FieldType.JSON, required=False),
            FieldSchema("sessionCredentialFromConsole", FieldType.STRING, required=False),
            FieldSchema("edgeDeviceDetails", FieldType.JSON, required=False),
            FieldSchema("tlsDetails", FieldType.JSON, required=False),
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
    
    # Azure Activity Logs Schema
    AZURE_ACTIVITY = LogSchema(
        name="azure_activity",
        description="Azure Activity Logs",
        format_type="json",
        fields=[
            FieldSchema("time", FieldType.DATETIME, required=True),
            FieldSchema("resourceId", FieldType.STRING, required=True),
            FieldSchema("correlationId", FieldType.UUID, required=True),
            FieldSchema("operationName", FieldType.JSON, required=True),
            FieldSchema("category", FieldType.JSON, required=True),
            FieldSchema("resultType", FieldType.STRING, required=True),
            FieldSchema("resultSignature", FieldType.STRING, required=False),
            FieldSchema("resultDescription", FieldType.STRING, required=False),
            FieldSchema("durationMs", FieldType.INTEGER, required=False),
            FieldSchema("callerIpAddress", FieldType.IP, required=False),
            FieldSchema("correlationId", FieldType.UUID, required=True),
            FieldSchema("identity", FieldType.JSON, required=False),
            FieldSchema("level", FieldType.STRING, required=True, allowed_values=["Informational", "Warning", "Error", "Critical"]),
            FieldSchema("location", FieldType.STRING, required=False),
            FieldSchema("properties", FieldType.JSON, required=False),
        ]
    )
    
    # Office 365 Schema
    OFFICE_365 = LogSchema(
        name="o365",
        description="Office 365 Unified Audit Logs",
        format_type="json",
        fields=[
            FieldSchema("CreationTime", FieldType.DATETIME, required=True),
            FieldSchema("Id", FieldType.UUID, required=True),
            FieldSchema("Operation", FieldType.STRING, required=True),
            FieldSchema("OrganizationId", FieldType.UUID, required=True),
            FieldSchema("RecordType", FieldType.INTEGER, required=True),
            FieldSchema("ResultStatus", FieldType.STRING, required=True),
            FieldSchema("UserKey", FieldType.STRING, required=True),
            FieldSchema("UserType", FieldType.INTEGER, required=True),
            FieldSchema("Version", FieldType.INTEGER, required=True),
            FieldSchema("Workload", FieldType.STRING, required=True),
            FieldSchema("ClientIP", FieldType.IP, required=True),
            FieldSchema("ObjectId", FieldType.STRING, required=False),
            FieldSchema("UserId", FieldType.STRING, required=True),
            FieldSchema("AzureActiveDirectoryEventType", FieldType.INTEGER, required=False),
            FieldSchema("ExtendedProperties", FieldType.JSON, required=False),
            FieldSchema("ModifiedProperties", FieldType.JSON, required=False),
        ]
    )
    
    # GCP Audit Logs Schema
    GCP_AUDIT = LogSchema(
        name="gcp_audit",
        description="GCP Cloud Audit Logs",
        format_type="json",
        fields=[
            FieldSchema("protoPayload", FieldType.JSON, required=True),
            FieldSchema("insertId", FieldType.STRING, required=True),
            FieldSchema("resource", FieldType.JSON, required=True),
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("severity", FieldType.STRING, required=True, allowed_values=["DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY"]),
            FieldSchema("logName", FieldType.STRING, required=True),
            FieldSchema("operation", FieldType.JSON, required=False),
            FieldSchema("receiveTimestamp", FieldType.DATETIME, required=True),
        ]
    )
    
    # AWS VPC Flow Logs Schema
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
            FieldSchema("start", FieldType.INTEGER, required=True),
            FieldSchema("end", FieldType.INTEGER, required=True),
            FieldSchema("action", FieldType.STRING, required=True, allowed_values=["ACCEPT", "REJECT"]),
            FieldSchema("log_status", FieldType.STRING, required=True, allowed_values=["OK", "NODATA", "SKIPDATA"]),
            # Version 2 fields
            FieldSchema("vpc_id", FieldType.STRING, required=False, pattern=r"^vpc-[0-9a-f]{8,17}$"),
            FieldSchema("subnet_id", FieldType.STRING, required=False, pattern=r"^subnet-[0-9a-f]{8,17}$"),
            FieldSchema("instance_id", FieldType.STRING, required=False, pattern=r"^i-[0-9a-f]{8,17}$"),
            FieldSchema("tcp_flags", FieldType.STRING, required=False),
            FieldSchema("type", FieldType.STRING, required=False, allowed_values=["IPv4", "IPv6"]),
            FieldSchema("pkt_srcaddr", FieldType.IP, required=False),
            FieldSchema("pkt_dstaddr", FieldType.IP, required=False),
            FieldSchema("region", FieldType.STRING, required=False),
            FieldSchema("az_id", FieldType.STRING, required=False),
            FieldSchema("sublocation_type", FieldType.STRING, required=False),
            FieldSchema("sublocation_id", FieldType.STRING, required=False),
            FieldSchema("pkt_src_aws_service", FieldType.STRING, required=False),
            FieldSchema("pkt_dst_aws_service", FieldType.STRING, required=False),
            FieldSchema("flow_direction", FieldType.STRING, required=False, allowed_values=["ingress", "egress"]),
            FieldSchema("traffic_path", FieldType.INTEGER, required=False),
        ]
    )
    
    # Azure AD Sign-in Schema
    AZURE_SIGNIN = LogSchema(
        name="azure_signin",
        description="Azure AD Sign-in Logs",
        format_type="json",
        fields=[
            FieldSchema("id", FieldType.UUID, required=True),
            FieldSchema("createdDateTime", FieldType.DATETIME, required=True),
            FieldSchema("userDisplayName", FieldType.STRING, required=True),
            FieldSchema("userPrincipalName", FieldType.STRING, required=True),
            FieldSchema("userId", FieldType.UUID, required=True),
            FieldSchema("appId", FieldType.UUID, required=True),
            FieldSchema("appDisplayName", FieldType.STRING, required=True),
            FieldSchema("ipAddress", FieldType.IP, required=True),
            FieldSchema("clientAppUsed", FieldType.STRING, required=False),
            FieldSchema("userAgent", FieldType.STRING, required=False),
            FieldSchema("correlationId", FieldType.UUID, required=True),
            FieldSchema("conditionalAccessStatus", FieldType.STRING, required=False, allowed_values=["success", "failure", "notApplied", "notEnabled"]),
            FieldSchema("isInteractive", FieldType.BOOLEAN, required=False),
            FieldSchema("riskDetail", FieldType.STRING, required=False),
            FieldSchema("riskLevelAggregated", FieldType.STRING, required=False, allowed_values=["none", "low", "medium", "high"]),
            FieldSchema("riskLevelDuringSignIn", FieldType.STRING, required=False, allowed_values=["none", "low", "medium", "high"]),
            FieldSchema("riskState", FieldType.STRING, required=False, allowed_values=["none", "confirmedSafe", "remediated", "atRisk", "confirmedCompromised", "unknownFutureValue"]),
            FieldSchema("riskEventTypes_v2", FieldType.JSON, required=False),
            FieldSchema("resourceDisplayName", FieldType.STRING, required=False),
            FieldSchema("resourceId", FieldType.UUID, required=False),
            FieldSchema("status", FieldType.JSON, required=True),
            FieldSchema("deviceDetail", FieldType.JSON, required=False),
            FieldSchema("location", FieldType.JSON, required=False),
            FieldSchema("authenticationDetails", FieldType.JSON, required=False),
            FieldSchema("authenticationRequirement", FieldType.STRING, required=False),
            FieldSchema("signInIdentifier", FieldType.STRING, required=False),
            FieldSchema("signInIdentifierType", FieldType.STRING, required=False),
            FieldSchema("servicePrincipalId", FieldType.UUID, required=False),
            FieldSchema("userType", FieldType.STRING, required=False, allowed_values=["Member", "Guest"]),
        ]
    )
    
    # Windows Event Log Schema
    WINDOWS_EVENT = LogSchema(
        name="windows",
        description="Windows Event Logs",
        format_type="xml",
        fields=[
            FieldSchema("EventID", FieldType.INTEGER, required=True),
            FieldSchema("TimeCreated", FieldType.DATETIME, required=True),
            FieldSchema("EventRecordID", FieldType.INTEGER, required=True),
            FieldSchema("Channel", FieldType.STRING, required=True),
            FieldSchema("Computer", FieldType.STRING, required=True),
            FieldSchema("SecurityUserID", FieldType.STRING, required=False),
            FieldSchema("SubjectUserName", FieldType.STRING, required=False),
            FieldSchema("SubjectDomainName", FieldType.STRING, required=False),
            FieldSchema("SubjectLogonId", FieldType.STRING, required=False),
            FieldSchema("TargetUserName", FieldType.STRING, required=False),
            FieldSchema("TargetDomainName", FieldType.STRING, required=False),
            FieldSchema("TargetLogonId", FieldType.STRING, required=False),
            FieldSchema("LogonType", FieldType.INTEGER, required=False),
            FieldSchema("IpAddress", FieldType.IP, required=False),
            FieldSchema("IpPort", FieldType.INTEGER, required=False),
            FieldSchema("ProcessName", FieldType.STRING, required=False),
            FieldSchema("Status", FieldType.STRING, required=False),
            FieldSchema("SubStatus", FieldType.STRING, required=False),
        ]
    )
    
    # Linux Auth Log Schema
    LINUX_AUTH = LogSchema(
        name="linux",
        description="Linux Auth Logs (syslog)",
        format_type="syslog",
        fields=[
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("hostname", FieldType.STRING, required=True),
            FieldSchema("service", FieldType.STRING, required=True),
            FieldSchema("pid", FieldType.INTEGER, required=False),
            FieldSchema("message", FieldType.STRING, required=True),
            FieldSchema("user", FieldType.STRING, required=False),
            FieldSchema("source_ip", FieldType.IP, required=False),
            FieldSchema("source_port", FieldType.INTEGER, required=False),
            FieldSchema("auth_method", FieldType.STRING, required=False),
        ]
    )
    
    # Firewall Schema (Palo Alto)
    FIREWALL = LogSchema(
        name="firewall",
        description="Firewall Traffic Logs (Palo Alto)",
        format_type="csv",
        fields=[
            FieldSchema("receive_time", FieldType.DATETIME, required=True),
            FieldSchema("serial", FieldType.STRING, required=True),
            FieldSchema("type", FieldType.STRING, required=True),
            FieldSchema("subtype", FieldType.STRING, required=True),
            FieldSchema("time_generated", FieldType.DATETIME, required=True),
            FieldSchema("src", FieldType.IP, required=True),
            FieldSchema("dst", FieldType.IP, required=True),
            FieldSchema("natsrc", FieldType.IP, required=False),
            FieldSchema("natdst", FieldType.IP, required=False),
            FieldSchema("rule", FieldType.STRING, required=True),
            FieldSchema("srcuser", FieldType.STRING, required=False),
            FieldSchema("dstuser", FieldType.STRING, required=False),
            FieldSchema("app", FieldType.STRING, required=True),
            FieldSchema("vsys", FieldType.STRING, required=True),
            FieldSchema("from", FieldType.STRING, required=True),
            FieldSchema("to", FieldType.STRING, required=True),
            FieldSchema("inbound_if", FieldType.STRING, required=True),
            FieldSchema("outbound_if", FieldType.STRING, required=True),
            FieldSchema("logset", FieldType.STRING, required=False),
            FieldSchema("time_received", FieldType.DATETIME, required=False),
            FieldSchema("sessionid", FieldType.INTEGER, required=True),
            FieldSchema("repeatcnt", FieldType.INTEGER, required=True),
            FieldSchema("sport", FieldType.INTEGER, required=True),
            FieldSchema("dport", FieldType.INTEGER, required=True),
            FieldSchema("natsport", FieldType.INTEGER, required=False),
            FieldSchema("natdport", FieldType.INTEGER, required=False),
            FieldSchema("flags", FieldType.STRING, required=False),
            FieldSchema("proto", FieldType.STRING, required=True),
            FieldSchema("action", FieldType.STRING, required=True),
            FieldSchema("bytes", FieldType.INTEGER, required=True),
            FieldSchema("bytes_sent", FieldType.INTEGER, required=True),
            FieldSchema("bytes_received", FieldType.INTEGER, required=True),
            FieldSchema("packets", FieldType.INTEGER, required=True),
            FieldSchema("start", FieldType.DATETIME, required=False),
            FieldSchema("elapsed", FieldType.INTEGER, required=False),
            FieldSchema("category", FieldType.STRING, required=True),
            FieldSchema("seqno", FieldType.INTEGER, required=True),
            FieldSchema("actionflags", FieldType.STRING, required=False),
            FieldSchema("srcloc", FieldType.STRING, required=False),
            FieldSchema("dstloc", FieldType.STRING, required=False),
            FieldSchema("pkts_sent", FieldType.INTEGER, required=False),
            FieldSchema("pkts_received", FieldType.INTEGER, required=False),
            FieldSchema("session_end_reason", FieldType.STRING, required=False),
        ]
    )
    
    # Proxy Schema
    PROXY = LogSchema(
        name="proxy",
        description="Web Proxy Logs",
        format_type="csv",
        fields=[
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("time_taken", FieldType.INTEGER, required=True),
            FieldSchema("c_ip", FieldType.IP, required=True),
            FieldSchema("cs_username", FieldType.STRING, required=False),
            FieldSchema("cs_auth_group", FieldType.STRING, required=False),
            FieldSchema("x_exception_id", FieldType.STRING, required=False),
            FieldSchema("sc_filter_result", FieldType.STRING, required=True),
            FieldSchema("cs_categories", FieldType.STRING, required=True),
            FieldSchema("cs_referer", FieldType.STRING, required=False),
            FieldSchema("sc_status", FieldType.INTEGER, required=True),
            FieldSchema("s_action", FieldType.STRING, required=True),
            FieldSchema("cs_method", FieldType.STRING, required=True),
            FieldSchema("rs_content_type", FieldType.STRING, required=False),
            FieldSchema("cs_uri_scheme", FieldType.STRING, required=True),
            FieldSchema("cs_host", FieldType.STRING, required=True),
            FieldSchema("cs_uri_port", FieldType.INTEGER, required=True),
            FieldSchema("cs_uri_path", FieldType.STRING, required=True),
            FieldSchema("cs_uri_query", FieldType.STRING, required=False),
            FieldSchema("cs_uri_extension", FieldType.STRING, required=False),
            FieldSchema("cs_bytes", FieldType.INTEGER, required=True),
            FieldSchema("sc_bytes", FieldType.INTEGER, required=True),
            FieldSchema("cs_user_agent", FieldType.STRING, required=False),
        ]
    )
    
    # DNS Schema
    DNS = LogSchema(
        name="dns",
        description="DNS Query Logs",
        format_type="csv",
        fields=[
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("src_ip", FieldType.IP, required=True),
            FieldSchema("src_port", FieldType.INTEGER, required=True),
            FieldSchema("dst_ip", FieldType.IP, required=True),
            FieldSchema("dst_port", FieldType.INTEGER, required=True),
            FieldSchema("protocol", FieldType.STRING, required=True, allowed_values=["UDP", "TCP"]),
            FieldSchema("query_name", FieldType.STRING, required=True),
            FieldSchema("query_type", FieldType.STRING, required=True),
            FieldSchema("response_code", FieldType.STRING, required=True),
            FieldSchema("answer", FieldType.STRING, required=False),
            FieldSchema("ttl", FieldType.INTEGER, required=False),
            FieldSchema("client", FieldType.STRING, required=False),
            FieldSchema("view", FieldType.STRING, required=False),
        ]
    )
    
    # IDS/IPS Schema (Suricata)
    IDS = LogSchema(
        name="ids",
        description="IDS/IPS Event Logs (Suricata EVE)",
        format_type="json",
        fields=[
            FieldSchema("timestamp", FieldType.DATETIME, required=True),
            FieldSchema("event_type", FieldType.STRING, required=True, allowed_values=["alert", "http", "dns", "tls", "fileinfo", "flow", "stats"]),
            FieldSchema("src_ip", FieldType.IP, required=True),
            FieldSchema("src_port", FieldType.INTEGER, required=True),
            FieldSchema("dest_ip", FieldType.IP, required=True),
            FieldSchema("dest_port", FieldType.INTEGER, required=True),
            FieldSchema("proto", FieldType.STRING, required=True),
            FieldSchema("alert", FieldType.JSON, required=False),
            FieldSchema("app_proto", FieldType.STRING, required=False),
            FieldSchema("flow_id", FieldType.INTEGER, required=False),
            FieldSchema("in_iface", FieldType.STRING, required=False),
            FieldSchema("vlan", FieldType.INTEGER, required=False),
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
