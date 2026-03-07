#!/usr/bin/env python3
"""
Azure AD Sign-in Logs Generator

Generates realistic Azure AD sign-in logs including:
- Interactive sign-ins (web, mobile, desktop)
- Non-interactive sign-ins (service principals)
- Service principal sign-ins
- Managed identity sign-ins

Includes success, failure, and risk detection scenarios.
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


class AzureSignInGenerator(BaseGenerator):
    """
    Generator for Azure AD Sign-in Logs.
    
    Simulates various authentication scenarios including MFA,
    conditional access, risk detections, and failures.
    """
    
    # Sign-in types
    SIGNIN_TYPES = [
        ("interactiveUser", 0.60),
        ("nonInteractiveUser", 0.20),
        ("servicePrincipal", 0.15),
        ("managedIdentity", 0.05),
    ]
    
    # Applications
    APPS = {
        "Outlook": "00000002-0000-0ff1-ce00-000000000000",
        "Office 365": "00000003-0000-0ff1-ce00-000000000000",
        "Azure Portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
        "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "SharePoint": "00000003-0000-0ff1-ce00-000000000000",
        "Graph Explorer": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
        "PowerShell": "1950a258-227b-4e31-a9cf-717495945fc2",
        "Azure CLI": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    }
    
    # Resource IDs
    RESOURCES = [
        "00000003-0000-0000-c000-000000000000",  # Graph API
        "00000002-0000-0000-c000-000000000000",  # AAD Graph
        "https://management.core.windows.net/",
        "https://graph.microsoft.com",
        "https://outlook.office365.com",
    ]
    
    # Client apps
    CLIENT_APPS = [
        "Browser",
        "Mobile Apps and Desktop clients",
        "Exchange ActiveSync",
        "IMAP",
        "MAPI",
        "Other clients",
        "POP3",
        "SMTP",
    ]
    
    # Operating systems
    OS_LIST = [
        ("Windows 10", "10.0.19044"),
        ("Windows 11", "10.0.22000"),
        ("macOS", "13.5.1"),
        ("iOS", "16.6"),
        ("Android", "13.0"),
        ("Linux", "5.15.0"),
    ]
    
    # Browsers
    BROWSERS = [
        "Edge 117.0",
        "Chrome 118.0",
        "Safari 16.6",
        "Firefox 118.0",
        "Mobile Safari 16.6",
        "Samsung Browser 22.0",
    ]
    
    # Locations
    LOCATIONS = [
        {"city": "Brussels", "state": "Brussels", "country": "BE", "lat": 50.85, "lon": 4.35},
        {"city": "Paris", "state": "Île-de-France", "country": "FR", "lat": 48.85, "lon": 2.35},
        {"city": "London", "state": "England", "country": "GB", "lat": 51.50, "lon": -0.13},
        {"city": "Amsterdam", "state": "North Holland", "country": "NL", "lat": 52.37, "lon": 4.90},
        {"city": "Frankfurt", "state": "Hesse", "country": "DE", "lat": 50.11, "lon": 8.68},
        {"city": "New York", "state": "NY", "country": "US", "lat": 40.71, "lon": -74.00},
        {"city": "Singapore", "state": "Singapore", "country": "SG", "lat": 1.35, "lon": 103.82},
        {"city": "Tokyo", "state": "Tokyo", "country": "JP", "lat": 35.68, "lon": 139.76},
    ]
    
    # IP ranges by location type
    CORPORATE_IPS = ["203.0.113.", "198.51.100."]
    HOME_IPS = ["192.0.2.", "172.16.", "10.0."]
    MOBILE_IPS = ["100.64.", "198.18."]
    SUSPICIOUS_IPS = ["185.220.", "45.142.", "91.219."]
    
    # Users
    USERS = [
        "john.doe@contoso.com",
        "jane.smith@contoso.com",
        "admin@contoso.com",
        "developer@contoso.com",
        "analyst@contoso.com",
        "manager@contoso.com",
        "service.account@contoso.com",
        "external.user@partner.com",
    ]
    
    # Error codes
    ERRORS = [
        (None, "Success", 0.85),
        ("50126", "Error validating credentials due to invalid username or password", 0.08),
        ("50074", "Strong Authentication is required", 0.03),
        ("70044", "The session has expired or is invalid due to sign-in frequency checks", 0.02),
        ("50076", "Due to a configuration change made by the admin", 0.01),
        ("50133", "Session is invalid due to expiration or recent password change", 0.005),
        ("50105", "The signed in user is not assigned to a role for the application", 0.005),
    ]
    
    # Risk levels
    RISK_LEVELS = [
        ("none", 0.90),
        ("low", 0.05),
        ("medium", 0.03),
        ("high", 0.02),
    ]
    
    # Risk types
    RISK_TYPES = [
        "unfamiliarFeatures",
        "anonymizedIPAddress",
        "maliciousIPAddress",
        "unfamiliarSigningProperties",
        "riskyIPAddress",
        "suspiciousIPAddress",
        "leakedCredentials",
        "investigationThreatIntelligence",
        "generic",
    ]
    
    # Conditional access statuses
    CA_STATUSES = [
        ("success", 0.85),
        ("failure", 0.10),
        ("notApplied", 0.03),
        ("notEnabled", 0.02),
    ]
    
    # MFA methods
    MFA_METHODS = [
        "Password",
        "Mobile app notification",
        "Text message",
        "Phone call approval",
        "Authenticator app TOTP",
        "Windows Hello for Business",
        "FIDO2 security key",
        "Certificate",
    ]
    
    # Auth requirement
    AUTH_REQUIREMENTS = [
        ("singleFactorAuthentication", 0.70),
        ("multiFactorAuthentication", 0.25),
        ("none", 0.05),
    ]
    
    def __init__(self, config: Dict[str, Any], inventory: Optional[AssetInventory] = None):
        """Initialize Azure Sign-in generator."""
        super().__init__(config)
        self.eps = config.get('eps', 100)
        self.inventory = inventory
        self.tenant_id = str(uuid.uuid4())
    
    def _generate_ip(self, is_suspicious: bool = False) -> str:
        """Generate client IP."""
        if is_suspicious:
            prefix = random.choice(self.SUSPICIOUS_IPS)
        elif random.random() < 0.6:
            prefix = random.choice(self.CORPORATE_IPS)
        elif random.random() < 0.5:
            prefix = random.choice(self.HOME_IPS)
        else:
            prefix = random.choice(self.MOBILE_IPS)
        return f"{prefix}{random.randint(1, 254)}"
    
    def _generate_location(self, ip: str) -> Dict[str, Any]:
        """Generate location data."""
        # Occasionally (5%) generate mismatched location (travel scenario)
        if random.random() < 0.05:
            location = random.choice(self.LOCATIONS)
        else:
            location = random.choice(self.LOCATIONS[:4])  # Prefer European locations
        
        return {
            "city": location["city"],
            "state": location["state"],
            "countryOrRegion": location["country"],
            "geoCoordinates": {
                "latitude": location["lat"] + random.uniform(-0.1, 0.1),
                "longitude": location["lon"] + random.uniform(-0.1, 0.1),
            },
        }
    
    def _generate_device_info(self) -> Dict[str, Any]:
        """Generate device information."""
        os_name, os_version = random.choice(self.OS_LIST)
        
        return {
            "deviceId": str(uuid.uuid4()),
            "displayName": f"CORP-{random.randint(1000, 9999)}",
            "operatingSystem": os_name,
            "operatingSystemVersion": os_version,
            "isCompliant": random.choice([True, True, True, False]),
            "isManaged": random.choice([True, True, False]),
            "trustType": random.choice(["AzureAD", "Hybrid", "Workplace", ""]),
        }
    
    def _generate_signin_record(self) -> Dict[str, Any]:
        """Generate Azure AD sign-in record."""
        signin_type = random.choices(
            [t for t, _ in self.SIGNIN_TYPES],
            [w for _, w in self.SIGNIN_TYPES]
        )[0]
        
        user = random.choice(self.USERS)
        app_name = random.choice(list(self.APPS.keys()))
        app_id = self.APPS[app_name]
        
        # Determine risk
        risk_level, _ = random.choices(
            [r for r, _ in self.RISK_LEVELS],
            [w for _, w in self.RISK_LEVELS]
        )[0]
        
        is_suspicious = risk_level in ("medium", "high")
        ip = self._generate_ip(is_suspicious)
        location = self._generate_location(ip)
        
        # Determine error
        error_code, failure_reason, _ = random.choices(
            self.ERRORS,
            [w for _, _, w in self.ERRORS]
        )[0]
        
        # Success or failure
        success = error_code is None
        
        # Build authentication details
        auth_req = random.choices(
            [a for a, _ in self.AUTH_REQUIREMENTS],
            [w for _, w in self.AUTH_REQUIREMENTS]
        )[0]
        
        auth_details = []
        
        # Primary authentication (password)
        auth_details.append({
            "authenticationStepDateTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "authenticationStepMethodDetail": "Password",
            "authenticationStepResultDetail": "Successfully completed" if success else failure_reason,
            "succeeded": success,
        })
        
        # MFA if required and successful
        if auth_req == "multiFactorAuthentication" and success:
            mfa_method = random.choice(self.MFA_METHODS[1:])  # Skip "Password"
            auth_details.append({
                "authenticationStepDateTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authenticationStepMethodDetail": mfa_method,
                "authenticationStepResultDetail": "Successfully completed",
                "succeeded": True,
            })
        elif auth_req == "multiFactorAuthentication" and not success and error_code == "50074":
            auth_details.append({
                "authenticationStepDateTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authenticationStepMethodDetail": "Mobile app notification",
                "authenticationStepResultDetail": "User did not respond to mobile app notification",
                "succeeded": False,
            })
        
        # Generate correlation ID
        correlation_id = str(uuid.uuid4())
        
        # Create datetime
        created = datetime.now(timezone.utc)
        
        record = {
            "id": str(uuid.uuid4()),
            "createdDateTime": created.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "userDisplayName": user.split("@")[0].replace(".", " ").title(),
            "userPrincipalName": user,
            "userId": str(uuid.uuid4()),
            "appId": app_id,
            "appDisplayName": app_name,
            "ipAddress": ip,
            "ipAddressFromResourceProvider": None,
            "clientAppUsed": random.choice(self.CLIENT_APPS),
            "userAgent": f"Mozilla/5.0 ({random.choice(['Windows NT 10.0', 'Macintosh', 'iPhone', 'Android'])}) {random.choice(self.BROWSERS)}",
            "correlationId": correlation_id,
            "conditionalAccessStatus": random.choices(
                [s for s, _ in self.CA_STATUSES],
                [w for _, w in self.CA_STATUSES]
            )[0],
            "isInteractive": signin_type == "interactiveUser",
            "riskDetail": None,
            "riskLevelAggregated": risk_level,
            "riskLevelDuringSignIn": risk_level,
            "riskState": "atRisk" if risk_level in ("medium", "high") else "none",
            "riskEventTypes": [],
            "riskEventTypes_v2": [],
            "resourceDisplayName": app_name,
            "resourceId": app_id,
            "resourceTenantId": self.tenant_id,
            "homeTenantId": self.tenant_id,
            "tokenIssuerName": "",
            "tokenIssuerType": "AzureAD",
            "clientCredentialType": None,
            "processingTimeInMilliseconds": random.randint(50, 5000),
            "servicePrincipalId": None,
            "servicePrincipalName": None,
            "authenticationProcessingDetails": [],
            "authenticationDetails": auth_details,
            "authenticationRequirement": auth_req,
            "signInIdentifier": user,
            "signInIdentifierType": "userPrincipalName",
            "signInEventTypes": [signin_type],
            "servicePrincipalCredentialKeyId": None,
            "userType": "Member" if "@contoso.com" in user else "Guest",
            "flaggedForReview": False,
            "locale": "en-us",
            "location": location,
            "deviceDetail": self._generate_device_info(),
            "status": {
                "errorCode": error_code or 0,
                "failureReason": failure_reason if not success else None,
                "additionalDetails": None,
            },
            "mfaDetail": {
                "authMethod": auth_details[1]["authenticationStepMethodDetail"] if len(auth_details) > 1 and auth_req == "multiFactorAuthentication" else None,
                "authDetail": None,
            } if auth_req == "multiFactorAuthentication" else None,
        }
        
        # Add risk event types if risky
        if risk_level in ("medium", "high"):
            num_risks = random.randint(1, 2)
            record["riskEventTypes_v2"] = random.sample(self.RISK_TYPES, num_risks)
        
        return record, signin_type, success, risk_level
    
    def generate_event(self) -> LogEvent:
        """Generate Azure AD Sign-in event."""
        record, signin_type, success, risk_level = self._generate_signin_record()
        
        # Create message
        status_str = "SUCCESS" if success else "FAILED"
        risk_str = f" [{risk_level.upper()} RISK]" if risk_level != "none" else ""
        message = f"Azure AD Sign-in: {record['userPrincipalName']} to {record['appDisplayName']} - {status_str}{risk_str}"
        
        # Convert to JSON
        raw_log = json.dumps(record, indent=None, default=str)
        
        # Determine severity
        if not success:
            severity = EventSeverity.MEDIUM
        elif risk_level in ("medium", "high"):
            severity = EventSeverity.HIGH
        elif record["conditionalAccessStatus"] == "failure":
            severity = EventSeverity.MEDIUM
        else:
            severity = EventSeverity.LOW
        
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="azure_signin",
            source_ip=record["ipAddress"],
            source_host="login.microsoftonline.com",
            message=message,
            raw_log=raw_log,
            fields={
                "id": record["id"],
                "userPrincipalName": record["userPrincipalName"],
                "userId": record["userId"],
                "appId": record["appId"],
                "appDisplayName": record["appDisplayName"],
                "ipAddress": record["ipAddress"],
                "clientAppUsed": record["clientAppUsed"],
                "correlationId": record["correlationId"],
                "conditionalAccessStatus": record["conditionalAccessStatus"],
                "riskLevelAggregated": record["riskLevelAggregated"],
                "riskState": record["riskState"],
                "authenticationRequirement": record["authenticationRequirement"],
                "isInteractive": record["isInteractive"],
                "status": record["status"],
                "location": record["location"],
                "deviceDetail": record["deviceDetail"],
                "signInEventTypes": record["signInEventTypes"],
            },
            tags=["azure", "signin", signin_type, record["appDisplayName"].lower().replace(" ", "_")],
            severity=severity
        )


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("Azure AD Sign-in Generator Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    config = {"eps": 10}
    
    generator = AzureSignInGenerator(config, inventory)
    
    for i in range(5):
        event = generator.generate_event()
        print(f"\nSign-in {i+1}:")
        print(f"  {event.message}")
        print(f"  IP: {event.fields['ipAddress']}, Location: {event.fields['location']['countryOrRegion']}")
        print(f"  Severity: {event.severity.name}")
