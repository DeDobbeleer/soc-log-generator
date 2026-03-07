#!/usr/bin/env python3
"""
Office 365 / Microsoft 365 Audit Logs Generator

Generates realistic Office 365 Unified Audit Logs for:
- Exchange Online (email operations, calendar, contacts)
- SharePoint Online (file operations, sharing)
- OneDrive (file sync, sharing)
- Teams (chat, meetings, calls)
- Azure AD (sign-ins, directory changes)
"""

import json
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

# Handle imports for both module and script execution
try:
    from ...core import LogEvent, EventSeverity, AssetInventory
    from ...generators.base import BaseGenerator
except ImportError:
    from core import LogEvent, EventSeverity, AssetInventory
    from generators.base import BaseGenerator


class Office365Generator(BaseGenerator):
    """
    Generator for Office 365 Unified Audit Logs.
    
    Simulates user and admin activities across Microsoft 365 services.
    """
    
    # Workload categories
    WORKLOADS = {
        "Exchange": {
            "operations": [
                ("Send", 0.35),
                ("Receive", 0.25),
                ("Create", 0.08),
                ("MoveToDeletedItems", 0.1),
                ("HardDelete", 0.05),
                ("SoftDelete", 0.05),
                ("AddDelegate", 0.03),
                ("RemoveDelegate", 0.02),
                ("UpdateCalendarDelegation", 0.02),
                ("MailboxLogin", 0.03),
                ("UpdateMailboxSettings", 0.02),
            ],
            "object_types": ["Item", "Folder", "Mailbox"]
        },
        "SharePoint": {
            "operations": [
                ("FileAccessed", 0.25),
                ("FileDownloaded", 0.15),
                ("FileModified", 0.15),
                ("FileUploaded", 0.12),
                ("FileDeleted", 0.08),
                ("FileRenamed", 0.05),
                ("FolderCreated", 0.05),
                ("FolderDeleted", 0.03),
                ("SharingSet", 0.06),
                ("SharingRevoked", 0.04),
                ("PageViewed", 0.02),
            ],
            "object_types": ["File", "Folder", "DocumentLibrary", "Site"]
        },
        "OneDrive": {
            "operations": [
                ("FileSyncDownloadedFull", 0.30),
                ("FileSyncUploadedFull", 0.20),
                ("FileAccessed", 0.20),
                ("FileModified", 0.12),
                ("FileDeleted", 0.08),
                ("FileRecycled", 0.05),
                ("FileRestored", 0.03),
                ("FileShared", 0.02),
            ],
            "object_types": ["File", "Folder"]
        },
        "MicrosoftTeams": {
            "operations": [
                ("ChatCreated", 0.15),
                ("ChatMessageSent", 0.25),
                ("MeetingStarted", 0.10),
                ("MeetingEnded", 0.10),
                ("CallStarted", 0.12),
                ("CallEnded", 0.12),
                ("TeamCreated", 0.05),
                ("ChannelCreated", 0.05),
                ("MemberAdded", 0.04),
                ("MemberRemoved", 0.02),
            ],
            "object_types": ["Chat", "Meeting", "Call", "Team", "Channel"]
        },
        "AzureActiveDirectory": {
            "operations": [
                ("UserLoggedIn", 0.40),
                ("UserLoginFailed", 0.10),
                ("AddUser", 0.05),
                ("UpdateUser", 0.08),
                ("DeleteUser", 0.03),
                ("AddGroup", 0.04),
                ("AddMemberToGroup", 0.08),
                ("RemoveMemberFromGroup", 0.05),
                ("AddServicePrincipal", 0.05),
                ("ConsentToApplication", 0.04),
                ("AddAppRoleAssignmentToUser", 0.04),
                ("AddDelegatedPermissionGrant", 0.04),
            ],
            "object_types": ["User", "Group", "ServicePrincipal", "Application"]
        },
    }
    
    # User list
    USERS = [
        "john.doe@contoso.com",
        "jane.smith@contoso.com",
        "admin@contoso.com",
        "sharepoint-admin@contoso.com",
        "exchange-admin@contoso.com",
        "bob.wilson@contoso.com",
        "alice.johnson@contoso.com",
        "mike.brown@contoso.com",
        "sarah.davis@contoso.com",
        "external.user@partner.com",
    ]
    
    # External IPs
    EXTERNAL_IPS = [
        "203.0.113.",
        "198.51.100.",
        "192.0.2.",
    ]
    
    # Device info
    DEVICES = [
        {"name": "CORP-PC-001", "os": "Windows", "browser": "Edge"},
        {"name": "CORP-MAC-002", "os": "MacOS", "browser": "Safari"},
        {"name": "CORP-MOB-003", "os": "iOS", "browser": "Outlook-Mobile"},
        {"name": "CORP-AND-004", "os": "Android", "browser": "Outlook-Mobile"},
        {"name": "Unknown", "os": "Windows", "browser": "Chrome"},
    ]
    
    # Application IDs
    APPS = [
        "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",  # Outlook
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Office 365
        "00000003-0000-0ff1-ce00-000000000000",  # SharePoint
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  # Microsoft Teams
        "00000002-0000-0000-c000-000000000000",  # AAD
    ]
    
    # File extensions for SharePoint/OneDrive
    FILE_EXTENSIONS = [".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".zip", ".jpg", ".png", ".mp4"]
    
    # Folder paths
    FOLDER_PATHS = [
        "/Shared Documents",
        "/Projects/2024",
        "/HR/Confidential",
        "/Finance/Reports",
        "/IT/Documentation",
        "/Sales/Proposals",
        "/Legal/Contracts",
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: Optional[AssetInventory] = None):
        """Initialize Office 365 generator."""
        super().__init__(config)
        self.eps = config.get('eps', 100)
        self.inventory = inventory
    
    def _get_random_workload_operation(self) -> tuple:
        """Get random workload and operation."""
        workload = random.choice(list(self.WORKLOADS.keys()))
        ops = self.WORKLOADS[workload]["operations"]
        op_names, weights = zip(*ops)
        operation = random.choices(op_names, weights=weights)[0]
        object_types = self.WORKLOADS[workload]["object_types"]
        
        return workload, operation, random.choice(object_types)
    
    def _generate_ip(self) -> str:
        """Generate client IP."""
        prefix = random.choice(self.EXTERNAL_IPS)
        return f"{prefix}{random.randint(1, 254)}"
    
    def _generate_audit_record(self) -> Dict[str, Any]:
        """Generate Office 365 audit record."""
        workload, operation, object_type = self._get_random_workload_operation()
        user = random.choice(self.USERS)
        device = random.choice(self.DEVICES)
        ip = self._generate_ip()
        
        record = {
            "CreationTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "Id": str(uuid.uuid4()),
            "Operation": operation,
            "OrganizationId": str(uuid.uuid4()),
            "RecordType": self._get_record_type(workload),
            "ResultStatus": random.choice(["Succeeded", "Succeeded", "Succeeded", "Failed"]),
            "UserKey": f"i:0#.f|membership|{user}",
            "UserType": random.choice([0, 0, 0, 2]),  # 0=Regular, 2=Admin
            "Version": 1,
            "Workload": workload,
            "ClientIP": ip,
            "ObjectId": self._generate_object_id(workload, object_type),
            "UserId": user,
            "ApplicationId": random.choice(self.APPS),
            "Application": self._get_app_name(workload),
        }
        
        # Add extended properties based on workload
        if workload == "Exchange":
            record.update(self._generate_exchange_properties(operation, object_type))
        elif workload in ("SharePoint", "OneDrive"):
            record.update(self._generate_sharepoint_properties(operation, object_type))
        elif workload == "MicrosoftTeams":
            record.update(self._generate_teams_properties(operation, object_type))
        elif workload == "AzureActiveDirectory":
            record.update(self._generate_aad_properties(operation, object_type))
        
        # Add device info
        record["DeviceProperties"] = [
            {"Name": "OS", "Value": device["os"]},
            {"Name": "Browser", "Value": device["browser"]},
            {"Name": "DeviceName", "Value": device["name"]},
        ]
        
        return record, workload, operation
    
    def _get_record_type(self, workload: str) -> int:
        """Get record type number for workload."""
        types = {
            "Exchange": 1,
            "SharePoint": 4,
            "OneDrive": 6,
            "MicrosoftTeams": 25,
            "AzureActiveDirectory": 15,
        }
        return types.get(workload, 1)
    
    def _get_app_name(self, workload: str) -> str:
        """Get application name for workload."""
        apps = {
            "Exchange": "Outlook",
            "SharePoint": "SharePoint",
            "OneDrive": "OneDrive",
            "MicrosoftTeams": "Microsoft Teams",
            "AzureActiveDirectory": "Azure AD",
        }
        return apps.get(workload, "Office 365")
    
    def _generate_object_id(self, workload: str, object_type: str) -> str:
        """Generate object ID for the operation."""
        if workload == "Exchange":
            if object_type == "Item":
                return f"AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0A{uuid.uuid4().hex[:58].upper()}"
            return f"/Personal/{random.choice(['Inbox', 'Sent Items', 'Drafts', 'Deleted Items'])}"
        elif workload in ("SharePoint", "OneDrive"):
            folder = random.choice(self.FOLDER_PATHS)
            filename = f"{random.choice(['document', 'report', 'presentation', 'spreadsheet', 'notes'])}-{random.randint(1, 999)}{random.choice(self.FILE_EXTENSIONS)}"
            return f"https://contoso.sharepoint.com{folder}/{filename}"
        elif workload == "MicrosoftTeams":
            return f"19:{uuid.uuid4().hex}@thread.tacv2"
        elif workload == "AzureActiveDirectory":
            return str(uuid.uuid4())
        return str(uuid.uuid4())
    
    def _generate_exchange_properties(self, operation: str, object_type: str) -> Dict[str, Any]:
        """Generate Exchange-specific properties."""
        props = {}
        
        if operation == "Send":
            props["Item"]= {
                "Id": str(uuid.uuid4()),
                "Subject": random.choice([
                    "Weekly Report",
                    "Meeting Invitation",
                    "Project Update",
                    "RE: Contract Discussion",
                    "Expense Report Approval"
                ]),
                "InternetMessageId": f"<{uuid.uuid4()}@contoso.mail.protection.outlook.com>",
                "Attachments": random.choice([0, 0, 0, 1, 2]),
            }
            props["SendAsUserSMTP"] = random.choice(self.USERS)
            props["RecipientCount"] = random.randint(1, 10)
        
        elif operation in ("Create", "MoveToDeletedItems", "HardDelete", "SoftDelete"):
            props["Item"]= {
                "Id": str(uuid.uuid4()),
                "Subject": random.choice(["Draft Email", "Note", "Reminder"]),
            }
            props["Folder"]= {
                "Id": str(uuid.uuid4()),
                "Name": random.choice(["Inbox", "Sent Items", "Drafts", "Deleted Items"]),
            }
        
        elif "Delegate" in operation:
            props["DelegateUserSMTP"] = random.choice(self.USERS)
            props["MailboxOwnerSMTP"] = random.choice(self.USERS)
        
        return props
    
    def _generate_sharepoint_properties(self, operation: str, object_type: str) -> Dict[str, Any]:
        """Generate SharePoint/OneDrive properties."""
        props = {}
        
        props["SiteUrl"] = "https://contoso.sharepoint.com"
        props["SourceRelativeUrl"] = random.choice(self.FOLDER_PATHS)
        props["SourceFileName"] = f"{random.choice(['doc', 'file', 'report'])}-{random.randint(1, 999)}{random.choice(self.FILE_EXTENSIONS)}"
        props["SourceFileExtension"] = props["SourceFileName"].split(".")[-1]
        
        if "Download" in operation or "Accessed" in operation:
            props["FileSize"] = random.randint(1024, 104857600)  # 1KB to 100MB
        
        if "Sharing" in operation:
            props["TargetUserOrGroupName"] = random.choice(self.USERS[:5])
            props["TargetUserOrGroupType"] = "Member"
            props["Permission"] = random.choice(["Edit", "View"])
        
        if "Sync" in operation:
            props["SyncType"] = "Full"
            props["FileSyncError"] = "None"
        
        return props
    
    def _generate_teams_properties(self, operation: str, object_type: str) -> Dict[str, Any]:
        """Generate Teams-specific properties."""
        props = {}
        
        if "Chat" in operation:
            props["ChatThreadId"] = str(uuid.uuid4())
            props["ChatName"] = f"Chat with {random.choice(self.USERS[:3]).split('@')[0]}"
        
        if "Meeting" in operation:
            props["MeetingId"] = str(uuid.uuid4())
            props["MeetingName"] = random.choice([
                "Weekly Standup",
                "Project Review",
                "Client Call",
                "Team Sync",
                "Quarterly Planning"
            ])
            props["Organizer"] = random.choice(self.USERS[:3])
        
        if "Call" in operation:
            props["CallId"] = str(uuid.uuid4())
            props["CallType"] = random.choice(["P2P", "Conference"])
            props["Duration"] = random.randint(30, 3600) if "Ended" in operation else None
        
        if "Member" in operation:
            props["AddedMembers"] = [random.choice(self.USERS)]
            props["TeamName"] = f"{random.choice(['Engineering', 'Sales', 'Marketing', 'HR'])} Team"
        
        return props
    
    def _generate_aad_properties(self, operation: str, object_type: str) -> Dict[str, Any]:
        """Generate Azure AD properties."""
        props = {}
        
        if "Login" in operation:
            props["LoginStatus"] = 0 if "Failed" not in operation else 50074
            props["LogonError"] = "MfaRequired" if "Failed" in operation else None
            props["Application"] = random.choice(["Outlook", "SharePoint", "Teams"])
        
        if operation in ("AddUser", "UpdateUser", "DeleteUser"):
            props["ModifiedProperties"] = [
                {
                    "Name": "DisplayName",
                    "NewValue": random.choice(["John Doe", "Jane Smith", "Bob Wilson"]),
                    "OldValue": ""
                },
                {
                    "Name": "UserPrincipalName", 
                    "NewValue": random.choice(self.USERS),
                    "OldValue": ""
                }
            ]
        
        if "Group" in operation:
            props["GroupName"] = f"{random.choice(['All', 'Engineering', 'Managers', 'Contractors'])}-{random.choice(['Users', 'Admins', 'Access'])}"
        
        if "ServicePrincipal" in operation:
            props["ServicePrincipalName"] = f"App-{random.randint(100, 999)}"
        
        return props
    
    def _get_severity(self, workload: str, operation: str, status: str) -> EventSeverity:
        """Determine severity."""
        if status == "Failed" and "Login" in operation:
            return EventSeverity.HIGH
        if "Delete" in operation or "Remove" in operation:
            return EventSeverity.MEDIUM
        if workload == "AzureActiveDirectory" and operation in ("AddUser", "DeleteUser"):
            return EventSeverity.MEDIUM
        if "HardDelete" in operation:
            return EventSeverity.MEDIUM
        return EventSeverity.LOW
    
    def generate_event(self) -> LogEvent:
        """Generate Office 365 audit event."""
        record, workload, operation = self._generate_audit_record()
        
        # Create message
        message = f"O365 {workload}: {operation} by {record['UserId']}"
        if record['ResultStatus'] == "Failed":
            message += " - FAILED"
        
        # Convert to JSON
        raw_log = json.dumps(record, indent=None)
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="o365",
            source_ip=record["ClientIP"],
            source_host=f"{workload.lower()}.office.com",
            message=message,
            raw_log=raw_log,
            fields={
                "workload": workload,
                "operation": operation,
                "userId": record["UserId"],
                "resultStatus": record["ResultStatus"],
                "recordType": record["RecordType"],
                "organizationId": record["OrganizationId"],
                "application": record["Application"],
                "objectId": record["ObjectId"],
            },
            tags=["o365", workload.lower(), operation.lower()],
            severity=self._get_severity(workload, operation, record["ResultStatus"])
        )


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("Office 365 Generator Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    config = {"eps": 10}
    
    generator = Office365Generator(config, inventory)
    
    for i in range(5):
        event = generator.generate_event()
        print(f"\nEvent {i+1}:")
        print(f"  Source: {event.source_type}")
        print(f"  Message: {event.message}")
        print(f"  Severity: {event.severity.name}")
        print(f"  Tags: {event.tags}")
