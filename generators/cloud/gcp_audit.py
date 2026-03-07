#!/usr/bin/env python3
"""
GCP Cloud Audit Logs Generator

Generates realistic GCP Audit Logs for:
- Admin Activity (project, IAM, resource management)
- Data Access (storage, BigQuery, etc.)
- System Event (automatic GCP actions)
- Policy Denied (failed authorizations)
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


class GCPAuditGenerator(BaseGenerator):
    """
    Generator for GCP Cloud Audit Logs.
    
    Simulates audit events across GCP services with proper
    protoPayload structure and authentication context.
    """
    
    # GCP Services and methods
    SERVICES = {
        "compute.googleapis.com": {
            "methods": [
                ("v1.compute.instances.insert", 0.20),
                ("v1.compute.instances.delete", 0.10),
                ("v1.compute.instances.start", 0.15),
                ("v1.compute.instances.stop", 0.10),
                ("v1.compute.instances.setMetadata", 0.08),
                ("v1.compute.firewalls.insert", 0.08),
                ("v1.compute.firewalls.patch", 0.05),
                ("v1.compute.networks.insert", 0.07),
                ("v1.compute.disks.createSnapshot", 0.07),
                ("v1.compute.instanceGroups.addInstances", 0.05),
                ("v1.compute.autoscalers.update", 0.05),
            ]
        },
        "storage.googleapis.com": {
            "methods": [
                ("storage.buckets.create", 0.15),
                ("storage.buckets.delete", 0.05),
                ("storage.buckets.setIamPolicy", 0.20),
                ("storage.objects.create", 0.25),
                ("storage.objects.delete", 0.10),
                ("storage.objects.get", 0.15),
                ("storage.objects.list", 0.10),
            ]
        },
        "iam.googleapis.com": {
            "methods": [
                ("google.iam.admin.v1.CreateRole", 0.10),
                ("google.iam.admin.v1.CreateServiceAccount", 0.15),
                ("google.iam.admin.v1.DeleteServiceAccount", 0.08),
                ("google.iam.admin.v1.CreateServiceAccountKey", 0.12),
                ("google.iam.admin.v1.DeleteServiceAccountKey", 0.08),
                ("google.iam.v1.SetIamPolicy", 0.25),
                ("google.iam.v1.GetIamPolicy", 0.15),
                ("google.iam.admin.v1.EnableServiceAccount", 0.07),
            ]
        },
        "cloudresourcemanager.googleapis.com": {
            "methods": [
                ("google.cloudresourcemanager.projects.create", 0.15),
                ("google.cloudresourcemanager.projects.delete", 0.05),
                ("google.cloudresourcemanager.projects.update", 0.15),
                ("google.cloudresourcemanager.projects.setIamPolicy", 0.25),
                ("google.cloudresourcemanager.folders.create", 0.10),
                ("google.cloudresourcemanager.folders.move", 0.08),
                ("google.cloudresourcemanager.organizations.setIamPolicy", 0.12),
                ("google.cloudresourcemanager.projects.get", 0.10),
            ]
        },
        "logging.googleapis.com": {
            "methods": [
                ("google.logging.v2.ConfigServiceV2.CreateSink", 0.25),
                ("google.logging.v2.ConfigServiceV2.UpdateSink", 0.20),
                ("google.logging.v2.ConfigServiceV2.DeleteSink", 0.10),
                ("google.logging.v2.LoggingServiceV2.WriteLogEntries", 0.30),
                ("google.logging.v2.ConfigServiceV2.CreateExclusion", 0.15),
            ]
        },
        "cloudfunctions.googleapis.com": {
            "methods": [
                ("google.cloud.functions.v1.CloudFunctionsService.CreateFunction", 0.30),
                ("google.cloud.functions.v1.CloudFunctionsService.UpdateFunction", 0.25),
                ("google.cloud.functions.v1.CloudFunctionsService.DeleteFunction", 0.15),
                ("google.cloud.functions.v1.CloudFunctionsService.CallFunction", 0.20),
                ("google.cloud.functions.v1.CloudFunctionsService.SetIamPolicy", 0.10),
            ]
        },
        "bigquery.googleapis.com": {
            "methods": [
                ("google.cloud.bigquery.v2.JobService.InsertJob", 0.25),
                ("google.cloud.bigquery.v2.TableService.InsertTable", 0.20),
                ("google.cloud.bigquery.v2.TableService.PatchTable", 0.15),
                ("google.cloud.bigquery.v2.DatasetService.InsertDataset", 0.15),
                ("google.cloud.bigquery.v2.DatasetService.PatchDataset", 0.15),
                ("google.cloud.bigquery.v2.JobService.Query", 0.10),
            ]
        },
        "sqladmin.googleapis.com": {
            "methods": [
                ("cloudsql.instances.create", 0.20),
                ("cloudsql.instances.delete", 0.10),
                ("cloudsql.instances.start", 0.15),
                ("cloudsql.instances.stop", 0.10),
                ("cloudsql.instances.clone", 0.10),
                ("cloudsql.instances.patch", 0.20),
                ("cloudsql.users.create", 0.15),
            ]
        },
    }
    
    # GCP Regions
    REGIONS = [
        "us-central1", "us-east1", "us-west1", "us-west2",
        "europe-west1", "europe-west2", "europe-west3", "europe-west4",
        "asia-east1", "asia-east2", "asia-northeast1", "asia-southeast1",
        "australia-southeast1", "southamerica-east1",
    ]
    
    # Projects
    PROJECTS = [
        "my-project-123456",
        "production-789012",
        "staging-345678",
        "shared-services-901234",
        "analytics-567890",
    ]
    
    # Organizations
    ORGANIZATIONS = [
        "123456789012",
        "987654321098",
    ]
    
    # Users and service accounts
    PRINCIPALS = [
        "user:admin@example.com",
        "user:developer@example.com",
        "user:analyst@example.com",
        "serviceAccount:terraform@my-project-123456.iam.gserviceaccount.com",
        "serviceAccount:ci-cd@production-789012.iam.gserviceaccount.com",
        "serviceAccount:backup-service@shared-services-901234.iam.gserviceaccount.com",
        "serviceAccount:compute@developer.gserviceaccount.com",
    ]
    
    # Caller IPs
    CALLER_IPS = [
        "203.0.113.",
        "198.51.100.",
        "192.0.2.",
        "10.0.0.",
        "172.16.0.",
    ]
    
    # User agents
    USER_AGENTS = [
        "google-cloud-sdk gcloud/440.0.0",
        "Terraform/1.5.0 (+https://www.terraform.io) TPG/4.0.0",
        "google-api-python-client/2.95.0",
        "GKE-Metadata-Server/1.0",
        "grpc-go/1.57.0",
        "Mozilla/5.0 (compatible; Google-Cloud-Functions/2.0)",
    ]
    
    # Log types
    LOG_TYPES = [
        ("ADMIN_READ", 0.20),
        ("ADMIN_WRITE", 0.45),
        ("DATA_READ", 0.15),
        ("DATA_WRITE", 0.15),
        ("POLICY_DENIED", 0.05),
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: Optional[AssetInventory] = None):
        """Initialize GCP Audit generator."""
        super().__init__(config)
        self.eps = config.get('eps', 100)
        self.inventory = inventory
    
    def _get_random_service_method(self) -> tuple:
        """Get random service and method."""
        service = random.choice(list(self.SERVICES.keys()))
        methods = self.SERVICES[service]["methods"]
        method_names, weights = zip(*methods)
        method = random.choices(method_names, weights=weights)[0]
        return service, method
    
    def _generate_ip(self) -> str:
        """Generate caller IP."""
        prefix = random.choice(self.CALLER_IPS)
        return f"{prefix}{random.randint(1, 254)}"
    
    def _generate_audit_log(self) -> Dict[str, Any]:
        """Generate GCP audit log record."""
        service, method = self._get_random_service_method()
        log_type = random.choices(
            [t for t, _ in self.LOG_TYPES],
            [w for _, w in self.LOG_TYPES]
        )[0]
        
        project = random.choice(self.PROJECTS)
        region = random.choice(self.REGIONS)
        principal = random.choice(self.PRINCIPALS)
        ip = self._generate_ip()
        
        # Generate timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        # Build authentication info
        auth_info = {
            "principalEmail": principal.split(":")[1],
            "principalSubject": f"user:{principal.split(':')[1]}" if principal.startswith("user:") else principal,
        }
        
        if principal.startswith("user:"):
            auth_info["principalEmail"] = principal.split(":")[1]
        
        # Request metadata
        request_metadata = {
            "callerIp": ip,
            "callerSuppliedUserAgent": random.choice(self.USER_AGENTS),
            "requestAttributes": {
                "time": timestamp,
                "auth": {}
            },
            "destinationAttributes": {}
        }
        
        # Status (mostly success)
        success = random.random() < 0.95
        status = {
            "code": 0 if success else random.choice([3, 5, 7, 16]),
            "message": "OK" if success else random.choice([
                "PERMISSION_DENIED",
                "RESOURCE_EXHAUSTED",
                "INVALID_ARGUMENT",
                "NOT_FOUND",
            ]),
        }
        
        # Resource info
        resource = {
            "type": self._get_resource_type(service),
            "labels": {
                "project_id": project,
                "zone": region,
            }
        }
        
        # Build protoPayload
        payload = {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "authenticationInfo": auth_info,
            "authorizationInfo": [{
                "permission": self._get_permission(method),
                "granted": success,
                "resourceAttributes": {}
            }],
            "methodName": method,
            "request": self._generate_request(method, project, region),
            "requestMetadata": request_metadata,
            "resourceLocation": {
                "currentLocations": [region]
            },
            "resourceName": self._generate_resource_name(service, project, region),
            "serviceName": service,
            "status": status,
        }
        
        # Build full log entry
        entry = {
            "protoPayload": payload,
            "insertId": str(uuid.uuid4()).replace("-", ""),
            "resource": resource,
            "timestamp": timestamp,
            "severity": "INFO" if success else "ERROR",
            "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2F{self._get_log_subtype(log_type)}",
            "operation": None,
            "receiveTimestamp": timestamp,
        }
        
        return entry, service, method, success, log_type
    
    def _get_resource_type(self, service: str) -> str:
        """Get resource type for service."""
        mapping = {
            "compute.googleapis.com": "gce_instance",
            "storage.googleapis.com": "gcs_bucket",
            "iam.googleapis.com": "service_account",
            "cloudresourcemanager.googleapis.com": "project",
            "logging.googleapis.com": "logging_log",
            "cloudfunctions.googleapis.com": "cloud_function",
            "bigquery.googleapis.com": "bigquery_dataset",
            "sqladmin.googleapis.com": "cloud_sql_database",
        }
        return mapping.get(service, "generic_task")
    
    def _get_permission(self, method: str) -> str:
        """Extract permission from method."""
        if "create" in method.lower() or "insert" in method.lower():
            return method.split(".")[-1].replace("Create", "create").replace("Insert", "create")
        elif "delete" in method.lower():
            return method.split(".")[-1].replace("Delete", "delete")
        elif "update" in method.lower() or "patch" in method.lower():
            return method.split(".")[-1].replace("Update", "update").replace("Patch", "update")
        return method.split(".")[-1].lower()
    
    def _generate_resource_name(self, service: str, project: str, region: str) -> str:
        """Generate resource name."""
        if service == "compute.googleapis.com":
            resource = random.choice(["instances", "disks", "firewalls", "networks"])
            return f"projects/{project}/zones/{region}/instances/{resource}-{random.randint(1000, 9999)}"
        elif service == "storage.googleapis.com":
            return f"projects/{project}/buckets/{project}-bucket-{random.randint(100, 999)}"
        elif service == "iam.googleapis.com":
            return f"projects/{project}/serviceAccounts/sa-{random.randint(1000, 9999)}@{project}.iam.gserviceaccount.com"
        elif service == "cloudresourcemanager.googleapis.com":
            return f"projects/{project}"
        elif service == "bigquery.googleapis.com":
            return f"projects/{project}/datasets/dataset_{random.randint(1, 100)}"
        elif service == "sqladmin.googleapis.com":
            return f"projects/{project}/instances/sql-{random.randint(1000, 9999)}"
        return f"projects/{project}/resources/{uuid.uuid4()}"
    
    def _generate_request(self, method: str, project: str, region: str) -> Dict[str, Any]:
        """Generate request parameters."""
        request = {}
        
        if "compute.instances" in method:
            if "insert" in method:
                request = {
                    "name": f"vm-{random.randint(1000, 9999)}",
                    "machineType": f"zones/{region}/machineTypes/{random.choice(['n1-standard-1', 'n1-standard-2', 'e2-medium'])}",
                    "disks": [{
                        "initializeParams": {
                            "diskSizeGb": str(random.choice([50, 100, 200])),
                            "sourceImage": "projects/debian-cloud/global/images/family/debian-11"
                        }
                    }],
                    "networkInterfaces": [{
                        "network": "global/networks/default"
                    }],
                }
            elif "setMetadata" in method:
                request = {
                    "items": [{"key": "startup-script", "value": "#!/bin/bash\necho hello"}]
                }
        
        elif "storage" in method:
            if "buckets.create" in method:
                request = {
                    "name": f"{project}-bucket-{random.randint(100, 999)}",
                    "location": region,
                    "storageClass": "STANDARD"
                }
            elif "objects" in method:
                request = {
                    "name": random.choice(["data.csv", "report.pdf", "backup.zip", "config.json"]),
                    "contentType": random.choice(["text/csv", "application/pdf", "application/zip", "application/json"])
                }
        
        elif "iam" in method and "ServiceAccount" in method:
            if "Create" in method:
                request = {
                    "accountId": f"sa-{random.randint(1000, 9999)}",
                    "serviceAccount": {
                        "displayName": f"Service Account {random.randint(1, 100)}"
                    }
                }
        
        elif "SetIamPolicy" in method:
            request = {
                "policy": {
                    "bindings": [{
                        "role": random.choice(["roles/editor", "roles/viewer", "roles/owner"]),
                        "members": [random.choice(self.PRINCIPALS)]
                    }]
                }
            }
        
        return request if request else {"@type": "type.googleapis.com/google.protobuf.Empty"}
    
    def _get_log_subtype(self, log_type: str) -> str:
        """Get log subtype."""
        mapping = {
            "ADMIN_READ": "activity",
            "ADMIN_WRITE": "activity",
            "DATA_READ": "data_access",
            "DATA_WRITE": "data_access",
            "POLICY_DENIED": "policy",
        }
        return mapping.get(log_type, "activity")
    
    def generate_event(self) -> LogEvent:
        """Generate GCP Audit log event."""
        entry, service, method, success, log_type = self._generate_audit_log()
        
        # Create message
        status_str = "SUCCESS" if success else "FAILED"
        resource = entry["protoPayload"]["resourceName"].split("/")[-1]
        message = f"GCP Audit: {method} on {resource} - {status_str}"
        
        # Convert to JSON
        raw_log = json.dumps(entry, indent=None)
        
        # Determine severity
        if not success:
            severity = EventSeverity.HIGH
        elif "SetIamPolicy" in method or "CreateServiceAccountKey" in method:
            severity = EventSeverity.MEDIUM
        else:
            severity = EventSeverity.LOW
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="gcp_audit",
            source_ip=entry["protoPayload"]["requestMetadata"]["callerIp"],
            source_host=f"{service}",
            message=message,
            raw_log=raw_log,
            fields={
                "serviceName": service,
                "methodName": method,
                "resourceName": entry["protoPayload"]["resourceName"],
                "principalEmail": entry["protoPayload"]["authenticationInfo"]["principalEmail"],
                "project_id": entry["resource"]["labels"]["project_id"],
                "zone": entry["resource"]["labels"]["zone"],
                "severity": entry["severity"],
                "log_type": log_type,
                "status": entry["protoPayload"]["status"],
            },
            tags=["gcp", "audit", service.replace(".googleapis.com", ""), log_type.lower()],
            severity=severity
        )


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("GCP Audit Generator Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    config = {"eps": 10}
    
    generator = GCPAuditGenerator(config, inventory)
    
    for i in range(5):
        event = generator.generate_event()
        print(f"\nAudit {i+1}:")
        print(f"  {event.message}")
        print(f"  Project: {event.fields['project_id']}, Zone: {event.fields['zone']}")
        print(f"  Severity: {event.severity.name}")
