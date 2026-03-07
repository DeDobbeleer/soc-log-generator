#!/usr/bin/env python3
"""
Azure Activity Logs Generator

Generates realistic Azure Activity Logs for:
- Resource operations (create, delete, update)
- Administrative operations
- Service health events
- Alert events
- Security events
- Policy events
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


class AzureActivityGenerator(BaseGenerator):
    """
    Generator for Azure Activity Logs.
    
    Simulates Azure Resource Manager operations and administrative events
    with realistic patterns across Azure services.
    """
    
    # Azure Resource Providers and operations
    RESOURCE_PROVIDERS = {
        "Microsoft.Compute": {
            "resources": ["virtualMachines", "disks", "snapshots", "images"],
            "operations": [
                ("write", "Create or update VM", 0.25),
                ("delete", "Delete VM", 0.1),
                ("action", "Start VM", 0.2),
                ("action", "Stop VM", 0.15),
                ("action", "Restart VM", 0.1),
                ("action", "Deallocate VM", 0.08),
                ("write", "Create disk", 0.07),
                ("delete", "Delete disk", 0.05),
            ]
        },
        "Microsoft.Storage": {
            "resources": ["storageAccounts", "blobServices", "fileServices"],
            "operations": [
                ("write", "Create storage account", 0.3),
                ("delete", "Delete storage account", 0.1),
                ("write", "Regenerate access keys", 0.15),
                ("action", "Create container", 0.2),
                ("write", "Update network rules", 0.15),
                ("delete", "Delete container", 0.1),
            ]
        },
        "Microsoft.Network": {
            "resources": ["virtualNetworks", "networkInterfaces", "networkSecurityGroups", "publicIPAddresses"],
            "operations": [
                ("write", "Create or update VNet", 0.2),
                ("write", "Create NSG", 0.15),
                ("write", "Create NSG rule", 0.2),
                ("delete", "Delete NSG rule", 0.1),
                ("write", "Associate NSG", 0.15),
                ("write", "Create public IP", 0.1),
                ("delete", "Delete public IP", 0.1),
            ]
        },
        "Microsoft.Sql": {
            "resources": ["servers", "databases", "elasticPools"],
            "operations": [
                ("write", "Create SQL server", 0.15),
                ("write", "Create database", 0.25),
                ("write", "Update firewall rules", 0.2),
                ("action", "Enable TDE", 0.15),
                ("delete", "Delete database", 0.15),
                ("write", "Scale DTU", 0.1),
            ]
        },
        "Microsoft.KeyVault": {
            "resources": ["vaults", "secrets", "keys"],
            "operations": [
                ("write", "Create vault", 0.15),
                ("write", "Set secret", 0.3),
                ("read", "Get secret", 0.25),
                ("delete", "Delete secret", 0.1),
                ("action", "Backup vault", 0.1),
                ("write", "Update access policy", 0.1),
            ]
        },
        "Microsoft.Authorization": {
            "resources": ["roleAssignments", "roleDefinitions", "locks"],
            "operations": [
                ("write", "Create role assignment", 0.3),
                ("delete", "Delete role assignment", 0.15),
                ("write", "Create deny assignment", 0.1),
                ("write", "Create management lock", 0.2),
                ("delete", "Delete management lock", 0.15),
                ("write", "Create policy assignment", 0.1),
            ]
        },
        "Microsoft.AAD": {
            "resources": ["domainservices", "users", "groups"],
            "operations": [
                ("write", "Add user to group", 0.25),
                ("write", "Create user", 0.2),
                ("delete", "Delete user", 0.1),
                ("write", "Update user", 0.2),
                ("write", "Reset password", 0.15),
                ("write", "Enable MFA", 0.1),
            ]
        },
        "Microsoft.Resources": {
            "resources": ["deployments", "resourceGroups", "subscriptions"],
            "operations": [
                ("write", "Create deployment", 0.3),
                ("action", "Validate deployment", 0.2),
                ("write", "Create resource group", 0.15),
                ("delete", "Delete resource group", 0.1),
                ("action", "Export template", 0.15),
                ("write", "Move resources", 0.1),
            ]
        },
    }
    
    # Azure Regions
    LOCATIONS = [
        "eastus", "eastus2", "westus", "westus2", "centralus",
        "northeurope", "westeurope", "uksouth", "ukwest",
        "southeastasia", "eastasia", "japaneast", "japanwest",
        "australiaeast", "brazilsouth", "southcentralus", "northcentralus"
    ]
    
    # Subscription IDs
    SUBSCRIPTIONS = [
        "12345678-1234-1234-1234-123456789012",
        "23456789-2345-2345-2345-234567890123",
        "34567890-3456-3456-3456-345678901234",
    ]
    
    # Tenant IDs
    TENANTS = [
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    ]
    
    # Caller identities
    CALLERS = [
        "user@contoso.com",
        "admin@contoso.com",
        "deployer@contoso.com",
        "system@microsoft.com",
        "automation@contoso.com"
    ]
    
    # Service principals
    SERVICE_PRINCIPALS = [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
    ]
    
    # Categories
    CATEGORIES = {
        "Administrative": 0.6,
        "ServiceHealth": 0.15,
        "ResourceHealth": 0.1,
        "Alert": 0.1,
        "Security": 0.05,
    }
    
    # Statuses
    STATUSES = [
        ("Accepted", 0.05),
        ("Succeeded", 0.85),
        ("Failed", 0.08),
        ("Started", 0.02),
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: Optional[AssetInventory] = None):
        """Initialize Azure Activity generator."""
        super().__init__(config)
        self.eps = config.get('eps', 100)
        self.inventory = inventory
    
    def _get_random_operation(self) -> tuple:
        """Get random resource provider and operation."""
        provider = random.choice(list(self.RESOURCE_PROVIDERS.keys()))
        provider_data = self.RESOURCE_PROVIDERS[provider]
        
        operations = provider_data["operations"]
        ops, descs, weights = zip(*operations)
        op_idx = random.choices(range(len(ops)), weights=weights)[0]
        
        return (
            provider,
            random.choice(provider_data["resources"]),
            ops[op_idx],
            descs[op_idx]
        )
    
    def _generate_activity_log(self) -> Dict[str, Any]:
        """Generate Azure Activity Log event."""
        provider, resource_type, operation, description = self._get_random_operation()
        category = random.choices(
            list(self.CATEGORIES.keys()),
            list(self.CATEGORIES.values())
        )[0]
        
        location = random.choice(self.LOCATIONS)
        subscription = random.choice(self.SUBSCRIPTIONS)
        resource_group = f"rg-{random.choice(['prod', 'dev', 'test', 'shared'])}-{random.randint(1, 99)}"
        resource_name = f"{resource_type.rstrip('s')}-{random.randint(1000, 9999)}"
        
        # Determine caller type
        if random.random() < 0.3:  # 30% service principal
            caller = random.choice(self.SERVICE_PRINCIPALS)
            caller_type = "ServicePrincipal"
        else:
            caller = random.choice(self.CALLERS)
            caller_type = "User"
        
        status, _ = random.choices(self.STATUSES, [w for _, w in self.STATUSES])[0]
        
        event = {
            "channels": "Operation",
            "correlationId": str(uuid.uuid4()),
            "description": description,
            "eventDataId": str(uuid.uuid4()),
            "eventName": {
                "value": f"{operation}/{resource_type}",
                "localizedValue": description
            },
            "eventSource": {
                "value": "ResourceManager",
                "localizedValue": "Resource Manager"
            },
            "httpRequest": {
                "clientRequestId": str(uuid.uuid4()),
                "clientIpAddress": self._generate_ip(),
                "method": "PUT" if operation == "write" else "DELETE" if operation == "delete" else "POST",
                "uri": f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/{provider}/{resource_type}/{resource_name}"
            },
            "id": f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Insights/activityLogs/{str(uuid.uuid4())}",
            "level": self._get_level(status),
            "resourceGroupName": resource_group,
            "resourceProviderName": {
                "value": provider,
                "localizedValue": provider
            },
            "resourceId": f"/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/{provider}/{resource_type}/{resource_name}",
            "resourceType": {
                "value": f"{provider}/{resource_type}",
                "localizedValue": f"{provider}/{resource_type}"
            },
            "operationId": str(uuid.uuid4()),
            "operationName": {
                "value": f"Microsoft.Resources/{operation}",
                "localizedValue": f"{operation} resource"
            },
            "properties": self._generate_properties(provider, operation, status),
            "status": {
                "value": status,
                "localizedValue": status
            },
            "subStatus": {
                "value": None,
                "localizedValue": None
            },
            "eventTimestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "submissionTimestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "subscriptionId": subscription,
            "tenantId": random.choice(self.TENANTS),
            "caller": caller,
            "category": {
                "value": category,
                "localizedValue": category
            }
        }
        
        # Add claims for user authentication
        if caller_type == "User":
            event["claims"] = {
                "aud": "https://management.core.windows.net/",
                "iss": f"https://sts.windows.net/{event['tenantId']}/",
                "iat": str(int(datetime.now(timezone.utc).timestamp())),
                "nbf": str(int(datetime.now(timezone.utc).timestamp())),
                "exp": str(int(datetime.now(timezone.utc).timestamp()) + 3600),
                "altsecid": "5::100320008B7F9F0E",
                "email": caller,
                "groups": "admin-group,developers",
                "ipaddr": event["httpRequest"]["clientIpAddress"],
                "name": caller.split("@")[0],
                "oid": str(uuid.uuid4()),
                "puid": "100320008B7F9F0E",
                "rh": "0.AAAA.",
                "tid": event["tenantId"],
                "unique_name": caller,
                "upn": caller,
                "uti": str(uuid.uuid4()).replace("-", ""),
                "ver": "1.0"
            }
        
        return event, category, status
    
    def _generate_ip(self) -> str:
        """Generate client IP."""
        return f"{random.randint(10, 172)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _get_level(self, status: str) -> str:
        """Get event level based on status."""
        if status == "Failed":
            return "Error"
        elif status == "Started":
            return "Informational"
        return "Informational"
    
    def _generate_properties(self, provider: str, operation: str, status: str) -> Dict[str, Any]:
        """Generate operation-specific properties."""
        props = {
            "statusCode": "OK" if status == "Succeeded" else "Accepted" if status == "Accepted" else "BadRequest" if status == "Failed" else "Created",
            "serviceRequestId": str(uuid.uuid4())
        }
        
        if provider == "Microsoft.Compute" and operation == "write":
            props["entity"] = "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}".format(
                random.choice(self.SUBSCRIPTIONS),
                "rg-prod-01",
                f"vm-{random.randint(1000, 9999)}"
            )
            props["eventCategory"] = "Administrative"
        
        elif provider == "Microsoft.Storage" and operation == "write":
            props["blobEndpoint"] = f"https://st{random.randint(10000,99999)}.blob.core.windows.net/"
            props["fileEndpoint"] = f"https://st{random.randint(10000,99999)}.file.core.windows.net/"
        
        elif provider == "Microsoft.Authorization":
            props["principalId"] = str(uuid.uuid4())
            props["roleDefinitionId"] = f"/subscriptions/{random.choice(self.SUBSCRIPTIONS)}/providers/Microsoft.Authorization/roleDefinitions/{uuid.uuid4()}"
        
        if status == "Failed":
            props["statusMessage"] = random.choice([
                "Conflict: Another operation is in progress",
                "BadRequest: Invalid parameter value",
                "Unauthorized: Insufficient permissions",
                "NotFound: Resource not found"
            ])
        
        return props
    
    def _get_severity(self, category: str, status: str) -> EventSeverity:
        """Determine severity based on category and status."""
        if status == "Failed":
            return EventSeverity.HIGH
        if category == "Security":
            return EventSeverity.HIGH
        if category in ("Alert", "ServiceHealth"):
            return EventSeverity.MEDIUM
        return EventSeverity.LOW
    
    def generate_event(self) -> LogEvent:
        """Generate Azure Activity Log event."""
        activity_data, category, status = self._generate_activity_log()
        
        # Extract key information
        resource_id = activity_data["resourceId"]
        caller = activity_data.get("caller", "unknown")
        operation = activity_data["operationName"]["value"]
        
        # Create message
        message = f"Azure {category}: {activity_data['description']} by {caller}"
        if status == "Failed":
            message += f" - FAILED"
        
        # Convert to JSON
        raw_log = json.dumps(activity_data, indent=None)
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="azure_activity",
            source_ip=activity_data["httpRequest"]["clientIpAddress"],
            source_host=f"management.azure.com",
            message=message,
            raw_log=raw_log,
            fields={
                "subscriptionId": activity_data["subscriptionId"],
                "tenantId": activity_data["tenantId"],
                "resourceGroup": activity_data["resourceGroupName"],
                "resourceProvider": activity_data["resourceProviderName"]["value"],
                "resourceType": activity_data["resourceType"]["value"],
                "resourceId": resource_id,
                "operation": operation,
                "category": category,
                "status": status,
                "caller": caller,
                "correlationId": activity_data["correlationId"],
                "level": activity_data["level"]
            },
            tags=["azure", "activity", category.lower(), activity_data["resourceProviderName"]["value"].lower().replace("microsoft.", "")],
            severity=self._get_severity(category, status)
        )


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("Azure Activity Generator Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    config = {"eps": 10}
    
    generator = AzureActivityGenerator(config, inventory)
    
    for i in range(5):
        event = generator.generate_event()
        print(f"\nEvent {i+1}:")
        print(f"  Source: {event.source_type}")
        print(f"  Message: {event.message}")
        print(f"  Severity: {event.severity.name}")
        print(f"  Tags: {event.tags}")
