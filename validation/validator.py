#!/usr/bin/env python3
"""
Log Validator

Validates generated logs against reference schemas and provides
quality metrics for field coverage, format compliance, and
distribution analysis.
"""

import json
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

from .schemas import SchemaRegistry, LogSchema, FieldSchema, FieldType


@dataclass
class FieldValidationResult:
    """Result of validating a single field."""
    field_name: str
    present: bool
    valid: bool
    error_message: Optional[str] = None
    field_type: Optional[FieldType] = None


@dataclass
class ValidationReport:
    """Complete validation report for a log event."""
    source_type: str
    valid: bool
    field_results: List[FieldValidationResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    field_coverage: float = 0.0
    required_coverage: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "source_type": self.source_type,
            "valid": self.valid,
            "field_coverage": round(self.field_coverage, 2),
            "required_coverage": round(self.required_coverage, 2),
            "errors": self.errors,
            "warnings": self.warnings,
            "fields": [
                {
                    "name": r.field_name,
                    "present": r.present,
                    "valid": r.valid,
                    "error": r.error_message
                }
                for r in self.field_results
            ]
        }


@dataclass
class BatchValidationReport:
    """Validation report for a batch of logs."""
    total_events: int = 0
    valid_events: int = 0
    invalid_events: int = 0
    source_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    field_coverage: Dict[str, Dict[str, float]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(float)))
    common_errors: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    severity_distribution: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    def add_report(self, report: ValidationReport) -> None:
        """Add a single event report to batch."""
        self.total_events += 1
        self.source_types[report.source_type] += 1
        
        if report.valid:
            self.valid_events += 1
        else:
            self.invalid_events += 1
            for error in report.errors:
                self.common_errors[error] += 1
        
        # Track field coverage by source type
        for field_result in report.field_results:
            if field_result.present:
                self.field_coverage[report.source_type][field_result.field_name] += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        # Calculate percentages
        coverage_pct = {}
        for source_type, fields in self.field_coverage.items():
            total = self.source_types[source_type]
            coverage_pct[source_type] = {
                field: round(count / total * 100, 1)
                for field, count in fields.items()
            }
        
        return {
            "total_events": self.total_events,
            "valid_events": self.valid_events,
            "invalid_events": self.invalid_events,
            "validity_rate": round(self.valid_events / self.total_events * 100, 2) if self.total_events > 0 else 0,
            "source_type_distribution": dict(self.source_types),
            "field_coverage": coverage_pct,
            "common_errors": dict(sorted(self.common_errors.items(), key=lambda x: x[1], reverse=True)[:10]),
            "severity_distribution": dict(self.severity_distribution),
        }


class LogValidator:
    """
    Validates log events against reference schemas.
    
    Usage:
        validator = LogValidator()
        report = validator.validate_event(log_event)
        
        # Batch validation
        batch_report = validator.validate_batch(log_events)
    """
    
    def __init__(self):
        """Initialize validator."""
        self.registry = SchemaRegistry()
    
    def validate_event(self, event: Any) -> ValidationReport:
        """
        Validate a single log event.
        
        Args:
            event: LogEvent object to validate
            
        Returns:
            ValidationReport with detailed results
        """
        source_type = getattr(event, 'source_type', 'unknown')
        schema = self.registry.get_schema(source_type)
        
        if not schema:
            return ValidationReport(
                source_type=source_type,
                valid=False,
                errors=[f"No schema found for source type: {source_type}"]
            )
        
        # Get event fields as dict
        event_dict = self._event_to_dict(event)
        
        # Validate each field
        field_results = []
        errors = []
        warnings = []
        
        required_present = 0
        required_total = 0
        total_present = 0
        
        for field_schema in schema.fields:
            value = event_dict.get(field_schema.name)
            present = value is not None
            valid = True
            error_msg = None
            
            if field_schema.required:
                required_total += 1
                if present:
                    required_present += 1
            
            if present:
                total_present += 1
                # Validate value
                valid, error_msg = self._validate_field_value(value, field_schema)
                if not valid:
                    errors.append(f"{field_schema.name}: {error_msg}")
            elif field_schema.required:
                valid = False
                error_msg = "Required field missing"
                errors.append(f"{field_schema.name}: {error_msg}")
            
            field_results.append(FieldValidationResult(
                field_name=field_schema.name,
                present=present,
                valid=valid,
                error_message=error_msg,
                field_type=field_schema.field_type
            ))
        
        # Calculate coverage
        total_fields = len(schema.fields)
        field_coverage = total_present / total_fields if total_fields > 0 else 0
        required_coverage = required_present / required_total if required_total > 0 else 0
        
        # Additional validations
        self._validate_additional_rules(event, event_dict, schema, errors, warnings)
        
        return ValidationReport(
            source_type=source_type,
            valid=len(errors) == 0,
            field_results=field_results,
            errors=errors,
            warnings=warnings,
            field_coverage=field_coverage,
            required_coverage=required_coverage
        )
    
    def validate_batch(self, events: List[Any]) -> BatchValidationReport:
        """
        Validate a batch of events.
        
        Args:
            events: List of LogEvent objects
            
        Returns:
            BatchValidationReport with aggregated results
        """
        batch_report = BatchValidationReport()
        
        for event in events:
            report = self.validate_event(event)
            batch_report.add_report(report)
        
        return batch_report
    
    def _event_to_dict(self, event: Any) -> Dict[str, Any]:
        """Convert event to dictionary."""
        if hasattr(event, '__dict__'):
            return event.__dict__
        elif isinstance(event, dict):
            return event
        else:
            return {}
    
    def _validate_field_value(self, value: Any, schema: FieldSchema) -> Tuple[bool, Optional[str]]:
        """
        Validate a field value against its schema.
        
        Returns:
            Tuple of (valid, error_message)
        """
        if value is None:
            return True, None  # None is valid for optional fields
        
        field_type = schema.field_type
        
        # Type validation
        if field_type == FieldType.STRING:
            if not isinstance(value, str):
                return False, f"Expected string, got {type(value).__name__}"
            
            # Pattern validation
            if schema.pattern and not re.match(schema.pattern, value):
                return False, f"Value does not match pattern: {schema.pattern}"
            
            # Length validation
            if schema.min_length and len(value) < schema.min_length:
                return False, f"String too short (min {schema.min_length})"
            if schema.max_length and len(value) > schema.max_length:
                return False, f"String too long (max {schema.max_length})"
            
            # Enum validation
            if schema.allowed_values and value not in schema.allowed_values:
                return False, f"Value not in allowed values: {schema.allowed_values}"
        
        elif field_type == FieldType.INTEGER:
            if not isinstance(value, int):
                return False, f"Expected integer, got {type(value).__name__}"
        
        elif field_type == FieldType.FLOAT:
            if not isinstance(value, (int, float)):
                return False, f"Expected number, got {type(value).__name__}"
        
        elif field_type == FieldType.BOOLEAN:
            if not isinstance(value, bool):
                return False, f"Expected boolean, got {type(value).__name__}"
        
        elif field_type == FieldType.DATETIME:
            if isinstance(value, datetime):
                return True, None
            if isinstance(value, str):
                # Try to parse ISO format
                try:
                    datetime.fromisoformat(value.replace('Z', '+00:00'))
                    return True, None
                except ValueError:
                    return False, "Invalid datetime format (expected ISO 8601)"
            return False, f"Expected datetime, got {type(value).__name__}"
        
        elif field_type == FieldType.IP:
            if not isinstance(value, str):
                return False, f"Expected IP string, got {type(value).__name__}"
            try:
                ipaddress.ip_address(value)
                return True, None
            except ValueError:
                # Could be a hostname, accept it
                return True, None
        
        elif field_type == FieldType.UUID:
            if not isinstance(value, str):
                return False, f"Expected UUID string, got {type(value).__name__}"
            uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            if not re.match(uuid_pattern, value.lower()):
                return False, "Invalid UUID format"
        
        elif field_type == FieldType.JSON:
            # Any dict or list is valid JSON structure
            if not isinstance(value, (dict, list)):
                return False, f"Expected JSON object, got {type(value).__name__}"
        
        return True, None
    
    def _validate_additional_rules(self, event: Any, event_dict: Dict[str, Any], 
                                   schema: LogSchema, errors: List[str], 
                                   warnings: List[str]) -> None:
        """Validate additional rules beyond field schemas."""
        
        # Check for raw_log presence
        if 'raw_log' in event_dict:
            raw_log = event_dict['raw_log']
            if not raw_log or (isinstance(raw_log, str) and len(raw_log.strip()) == 0):
                warnings.append("raw_log is empty")
        
        # Check timestamp validity
        if 'timestamp' in event_dict:
            ts = event_dict['timestamp']
            if isinstance(ts, datetime):
                now = datetime.now(ts.tzinfo) if ts.tzinfo else datetime.now()
                diff = (now - ts).total_seconds()
                if diff < 0:
                    warnings.append("timestamp is in the future")
                elif diff > 86400:  # More than 24 hours old
                    warnings.append("timestamp is more than 24 hours old")
        
        # Check message presence
        if 'message' in event_dict:
            msg = event_dict['message']
            if not msg or (isinstance(msg, str) and len(msg.strip()) == 0):
                warnings.append("message is empty")
            elif isinstance(msg, str) and len(msg) > 1000:
                warnings.append("message is very long (>1000 chars)")
        
        # Source-specific validations
        if schema.name == "aws_cloudtrail":
            self._validate_aws_cloudtrail(event_dict, errors, warnings)
        elif schema.name == "azure_signin":
            self._validate_azure_signin(event_dict, errors, warnings)
        elif schema.name == "gcp_audit":
            self._validate_gcp_audit(event_dict, errors, warnings)
    
    def _validate_aws_cloudtrail(self, event_dict: Dict[str, Any], 
                                  errors: List[str], warnings: List[str]) -> None:
        """AWS CloudTrail specific validations."""
        fields = event_dict.get('fields', {})
        
        # Check for suspicious activity
        event_name = fields.get('eventName', '')
        error_code = fields.get('errorCode')
        
        if event_name in ['StopLogging', 'DeleteTrail'] and not error_code:
            warnings.append("Critical CloudTrail action without error")
        
        if event_name in ['PutBucketPolicy', 'PutBucketAcl']:
            warnings.append("S3 bucket policy modification detected")
    
    def _validate_azure_signin(self, event_dict: Dict[str, Any],
                               errors: List[str], warnings: List[str]) -> None:
        """Azure AD Sign-in specific validations."""
        fields = event_dict.get('fields', {})
        
        risk_level = fields.get('riskLevelAggregated')
        status = fields.get('status', {})
        
        if risk_level in ['medium', 'high'] and status.get('errorCode') == 0:
            warnings.append(f"Sign-in with {risk_level} risk but successful")
    
    def _validate_gcp_audit(self, event_dict: Dict[str, Any],
                            errors: List[str], warnings: List[str]) -> None:
        """GCP Audit specific validations."""
        fields = event_dict.get('fields', {})
        
        status = fields.get('status', {})
        if status.get('code') != 0 and 'permission' not in str(status.get('message', '')).lower():
            warnings.append(f"GCP API error: {status.get('message')}")


# Standalone validation functions
def validate_sample(sample_size: int = 100, generator_name: str = 'aws') -> Dict[str, Any]:
    """
    Validate a sample of generated logs.
    
    Args:
        sample_size: Number of events to generate and validate
        generator_name: Generator to test
        
    Returns:
        Validation report dictionary
    """
    try:
        from ..core import AssetInventory
        from ..generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
        from ..generators.cloud.aws_vpcflow import AWSVPCFlowGenerator
        from ..generators.cloud.azure_activity import AzureActivityGenerator
        from ..generators.cloud.azure_signin import AzureSignInGenerator
        from ..generators.cloud.o365 import Office365Generator
        from ..generators.cloud.gcp_audit import GCPAuditGenerator
        from ..generators.endpoint.windows import WindowsEventGenerator
        from ..generators.endpoint.linux_generator import LinuxAuthGenerator
        from ..generators.network.firewall import FirewallGenerator
    except ImportError:
        from core import AssetInventory
        from generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
        from generators.cloud.aws_vpcflow import AWSVPCFlowGenerator
        from generators.cloud.azure_activity import AzureActivityGenerator
        from generators.cloud.azure_signin import AzureSignInGenerator
        from generators.cloud.o365 import Office365Generator
        from generators.cloud.gcp_audit import GCPAuditGenerator
        from generators.endpoint.windows import WindowsEventGenerator
        from generators.endpoint.linux_generator import LinuxAuthGenerator
        from generators.network.firewall import FirewallGenerator
    
    generators = {
        'aws': AWSCloudTrailGenerator,
        'aws-vpcflow': AWSVPCFlowGenerator,
        'azure': AzureActivityGenerator,
        'azure-signin': AzureSignInGenerator,
        'o365': Office365Generator,
        'gcp': GCPAuditGenerator,
        'windows': WindowsEventGenerator,
        'linux': LinuxAuthGenerator,
        'firewall': FirewallGenerator,
    }
    
    gen_class = generators.get(generator_name)
    if not gen_class:
        return {"error": f"Unknown generator: {generator_name}"}
    
    inventory = AssetInventory()
    generator = gen_class({'eps': 100}, inventory)
    
    # Generate events
    events = [generator.generate_event() for _ in range(sample_size)]
    
    # Validate
    validator = LogValidator()
    report = validator.validate_batch(events)
    
    return report.to_dict()


if __name__ == "__main__":
    import sys
    
    print("Log Validator - Quality Control System")
    print("=" * 60)
    
    # Validate each generator
    generators = ['aws', 'aws-vpcflow', 'azure', 'azure-signin', 'o365', 'gcp']
    
    for gen_name in generators:
        print(f"\n🔍 Validating {gen_name}...")
        try:
            result = validate_sample(100, gen_name)
            print(f"  Validity Rate: {result['validity_rate']}%")
            print(f"  Field Coverage: {list(result['field_coverage'].get(gen_name, {}).keys())[:5]}...")
            if result['common_errors']:
                print(f"  Common Errors: {list(result['common_errors'].keys())[:3]}")
        except Exception as e:
            print(f"  Error: {e}")
