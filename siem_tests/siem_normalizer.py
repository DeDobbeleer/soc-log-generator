#!/usr/bin/env python3
"""
SIEM Normalizer

Simulates how different SIEMs parse and normalize log events.
Validates field extraction, CEF/LEEF conversion, and parser compatibility.
"""

import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class SIEMType(Enum):
    """Supported SIEM types."""
    LOGPOINT = "logpoint"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    QRADAR = "qradar"
    SENTINEL = "sentinel"
    ARCSIGHT = "arcsight"
    SUMOLOGIC = "sumologic"


class NormalizationStatus(Enum):
    """Normalization result status."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass
class FieldExtraction:
    """Result of extracting a field."""
    source_field: str
    target_field: str
    value: Any
    extracted: bool
    transformed: bool = False
    error: Optional[str] = None


@dataclass
class NormalizationReport:
    """Report of SIEM normalization."""
    siem_type: SIEMType
    source_type: str
    status: NormalizationStatus
    original_event: Dict[str, Any]
    normalized_fields: Dict[str, Any] = field(default_factory=dict)
    extractions: List[FieldExtraction] = field(default_factory=list)
    missing_fields: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    extraction_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "siem_type": self.siem_type.value,
            "source_type": self.source_type,
            "status": self.status.value,
            "extraction_rate": round(self.extraction_rate, 2),
            "normalized_fields": self.normalized_fields,
            "missing_fields": self.missing_fields,
            "errors": self.errors,
            "warnings": self.warnings,
            "extractions": [
                {
                    "source": e.source_field,
                    "target": e.target_field,
                    "extracted": e.extracted,
                    "transformed": e.transformed,
                    "error": e.error
                }
                for e in self.extractions
            ]
        }


class SIEMNormalizer:
    """
    Normalizes log events for different SIEMs.
    
    Simulates parser behavior and validates field extraction.
    """
    
    # Common SIEM field mappings
    COMMON_FIELDS = {
        "timestamp": ["_time", "TimeGenerated", "@timestamp", "event_time", "ts"],
        "source_ip": ["src_ip", "sourceip", "src", "client_ip", "ip.src"],
        "dest_ip": ["dest_ip", "dst_ip", "destinationip", "dst", "ip.dst"],
        "user": ["user", "username", "UserName", "user_id", "user.name"],
        "action": ["action", "Action", "outcome", "activity", "event.action"],
        "severity": ["severity", "Severity", "level", "priority", "event.severity"],
        "message": ["message", "Message", "msg", "raw_message", "event.original"],
    }
    
    # SIEM-specific field mappings
    SIEM_MAPPINGS = {
        SIEMType.LOGPOINT: {
            "timestamp": "timestamp",
            "source_ip": "device_address",
            "dest_ip": "dst_ip",
            "user": "user",
            "action": "action",
            "severity": "severity",
            "message": "msg",
            "raw_log": "message",
        },
        SIEMType.SPLUNK: {
            "timestamp": "_time",
            "source_ip": "src_ip",
            "dest_ip": "dest_ip",
            "user": "user",
            "action": "action",
            "severity": "severity",
            "message": "_raw",
            "sourcetype": "sourcetype",
            "index": "index",
            "host": "host",
        },
        SIEMType.ELASTIC: {
            "timestamp": "@timestamp",
            "source_ip": "source.ip",
            "dest_ip": "destination.ip",
            "user": "user.name",
            "action": "event.action",
            "severity": "event.severity",
            "message": "message",
            "raw_log": "event.original",
        },
        SIEMType.QRADAR: {
            "timestamp": "starttime",
            "source_ip": "sourceip",
            "dest_ip": "destinationip",
            "user": "username",
            "action": "eventaction",
            "severity": "severity",
            "message": "payload",
            "qid": "qid",
            "logsource_id": "logsourceid",
        },
        SIEMType.ARCSIGHT: {
            "timestamp": "deviceReceiptTime",
            "source_ip": "src",
            "dest_ip": "dst",
            "user": "duser",
            "action": "act",
            "severity": "severity",
            "message": "msg",
            "device_vendor": "deviceVendor",
            "device_product": "deviceProduct",
        },
    }
    
    # CEF field mappings
    CEF_FIELDS = {
        "act": "action",
        "rt": "deviceReceiptTime",
        "src": "sourceAddress",
        "dst": "destinationAddress",
        "spt": "sourcePort",
        "dpt": "destinationPort",
        "duser": "destinationUserName",
        "suser": "sourceUserName",
        "msg": "message",
        "cn1": "customNumber1",
        "cs1": "customString1",
        "cs2": "customString2",
        "cs3": "customString3",
        "cs4": "customString4",
        "cs5": "customString5",
        "cs6": "customString6",
    }
    
    def __init__(self, siem_type: SIEMType = SIEMType.LOGPOINT):
        """
        Initialize normalizer for a specific SIEM.
        
        Args:
            siem_type: Target SIEM type
        """
        self.siem_type = siem_type
        self.mapping = self.SIEM_MAPPINGS.get(siem_type, {})
    
    def normalize(self, event: Any) -> NormalizationReport:
        """
        Normalize a log event for the target SIEM.
        
        Args:
            event: LogEvent object or dict
            
        Returns:
            NormalizationReport with extraction results
        """
        # Convert event to dict
        event_dict = self._event_to_dict(event)
        source_type = event_dict.get('source_type', 'unknown')
        
        report = NormalizationReport(
            siem_type=self.siem_type,
            source_type=source_type,
            status=NormalizationStatus.SUCCESS,
            original_event=event_dict
        )
        
        # Extract timestamp
        self._extract_timestamp(event_dict, report)
        
        # Extract standard fields
        for source_field, target_field in self.mapping.items():
            self._extract_field(event_dict, source_field, target_field, report)
        
        # SIEM-specific processing
        if self.siem_type == SIEMType.LOGPOINT:
            self._normalize_for_logpoint(event_dict, report)
        elif self.siem_type == SIEMType.SPLUNK:
            self._normalize_for_splunk(event_dict, report)
        elif self.siem_type == SIEMType.ELASTIC:
            self._normalize_for_elastic(event_dict, report)
        elif self.siem_type == SIEMType.QRADAR:
            self._normalize_for_qradar(event_dict, report)
        elif self.siem_type == SIEMType.ARCSIGHT:
            self._normalize_for_arcsight(event_dict, report)
        
        # Calculate extraction rate
        if report.extractions:
            extracted_count = sum(1 for e in report.extractions if e.extracted)
            report.extraction_rate = extracted_count / len(report.extractions)
        
        # Determine overall status
        if report.extraction_rate < 0.5:
            report.status = NormalizationStatus.FAILED
        elif report.extraction_rate < 0.8:
            report.status = NormalizationStatus.PARTIAL
        elif report.errors:
            report.status = NormalizationStatus.PARTIAL
        
        return report
    
    def to_cef(self, event: Any) -> str:
        """
        Convert event to CEF format.
        
        Args:
            event: LogEvent object
            
        Returns:
            CEF formatted string
        """
        event_dict = self._event_to_dict(event)
        
        # Build CEF header
        version = "CEF:0"
        vendor = event_dict.get('fields', {}).get('vendor', 'Unknown')
        product = event_dict.get('source_type', 'Unknown')
        
        # Get severity
        severity_map = {1: 0, 2: 4, 3: 6, 4: 10}  # Map EventSeverity to CEF (0-10)
        severity = event_dict.get('severity')
        if hasattr(severity, 'value'):
            cef_severity = severity_map.get(severity.value, 5)
        else:
            cef_severity = 5
        
        # Build extension
        extensions = []
        
        # Map common fields
        field_mapping = {
            'src': event_dict.get('source_ip'),
            'dst': event_dict.get('fields', {}).get('dest_ip'),
            'msg': event_dict.get('message'),
            'rt': event_dict.get('timestamp'),
        }
        
        for key, value in field_mapping.items():
            if value:
                # Escape special characters in CEF
                value_str = str(value).replace('\\', '\\\\').replace('=', '\\=').replace('|', '\\|')
                extensions.append(f"{key}={value_str}")
        
        # Add custom fields from fields dict
        fields = event_dict.get('fields', {})
        for i, (key, value) in enumerate(fields.items(), 1):
            if i <= 6 and key not in ['src_ip', 'dest_ip']:
                if isinstance(value, (str, int, float)):
                    value_str = str(value).replace('\\', '\\\\').replace('=', '\\=')
                    extensions.append(f"cs{i}={value_str}")
        
        extension_str = " ".join(extensions)
        
        return f"{version}|{vendor}|{product}|1.0|{event_dict.get('source_type')}|{event_dict.get('message', 'Event')[:50]}|{cef_severity}|{extension_str}"
    
    def to_leef(self, event: Any) -> str:
        """
        Convert event to LEEF format (QRadar).
        
        Args:
            event: LogEvent object
            
        Returns:
            LEEF formatted string
        """
        event_dict = self._event_to_dict(event)
        
        # LEEF header
        version = "LEEF:2.0"
        vendor = event_dict.get('fields', {}).get('vendor', 'Unknown')
        product = event_dict.get('source_type', 'Unknown')
        event_id = event_dict.get('fields', {}).get('eventName', 'Unknown')
        
        # Build attributes
        attrs = []
        
        # Standard LEEF fields
        if event_dict.get('source_ip'):
            attrs.append(f"src={event_dict['source_ip']}")
        
        fields = event_dict.get('fields', {})
        if fields.get('dest_ip'):
            attrs.append(f"dst={fields['dest_ip']}")
        
        if event_dict.get('timestamp'):
            ts = event_dict['timestamp']
            if hasattr(ts, 'isoformat'):
                ts = ts.isoformat()
            attrs.append(f"devTime={ts}")
        
        if event_dict.get('message'):
            msg = str(event_dict['message']).replace('\t', ' ').replace('\n', ' ')
            attrs.append(f"msg={msg}")
        
        # Add custom fields
        for key, value in fields.items():
            if isinstance(value, (str, int, float, bool)):
                value_str = str(value).replace('\t', ' ').replace('\n', ' ')
                attrs.append(f"{key}={value_str}")
        
        attr_str = "\t".join(attrs)
        
        return f"{version}\t{vendor}\t{product}\t{event_id}\t{attr_str}"
    
    def _event_to_dict(self, event: Any) -> Dict[str, Any]:
        """Convert event to dictionary."""
        if hasattr(event, '__dict__'):
            result = dict(event.__dict__)
            # Flatten fields
            if 'fields' in result and isinstance(result['fields'], dict):
                result.update(result.pop('fields'))
            # Convert enum
            if 'severity' in result and hasattr(result['severity'], 'name'):
                result['severity'] = result['severity'].name
            return result
        elif isinstance(event, dict):
            return event
        return {}
    
    def _extract_timestamp(self, event_dict: Dict[str, Any], report: NormalizationReport) -> None:
        """Extract and normalize timestamp."""
        timestamp = event_dict.get('timestamp')
        if timestamp:
            if isinstance(timestamp, datetime):
                # Convert to various SIEM formats
                if self.siem_type == SIEMType.SPLUNK:
                    report.normalized_fields['_time'] = timestamp.timestamp()
                elif self.siem_type == SIEMType.ELASTIC:
                    report.normalized_fields['@timestamp'] = timestamp.isoformat()
                elif self.siem_type == SIEMType.QRADAR:
                    report.normalized_fields['starttime'] = int(timestamp.timestamp() * 1000)
                else:
                    report.normalized_fields['timestamp'] = timestamp.isoformat()
                
                report.extractions.append(FieldExtraction(
                    source_field="timestamp",
                    target_field=self.mapping.get("timestamp", "timestamp"),
                    value=timestamp,
                    extracted=True,
                    transformed=True
                ))
            else:
                report.warnings.append(f"Timestamp not a datetime object: {type(timestamp)}")
        else:
            report.missing_fields.append("timestamp")
    
    def _extract_field(self, event_dict: Dict[str, Any], source_field: str, 
                       target_field: str, report: NormalizationReport) -> None:
        """Extract a single field."""
        if source_field == "timestamp":
            return  # Already handled
        
        value = event_dict.get(source_field)
        if value is not None:
            report.normalized_fields[target_field] = value
            report.extractions.append(FieldExtraction(
                source_field=source_field,
                target_field=target_field,
                value=value,
                extracted=True
            ))
        else:
            report.missing_fields.append(source_field)
    
    def _normalize_for_logpoint(self, event_dict: Dict[str, Any], report: NormalizationReport) -> None:
        """LogPoint-specific normalization."""
        # LogPoint uses specific device types
        source_type = event_dict.get('source_type', '')
        if 'windows' in source_type:
            report.normalized_fields['device_type'] = 'windows'
        elif 'linux' in source_type:
            report.normalized_fields['device_type'] = 'linux'
        elif 'firewall' in source_type:
            report.normalized_fields['device_type'] = 'firewall'
        elif 'aws' in source_type or 'azure' in source_type or 'gcp' in source_type:
            report.normalized_fields['device_type'] = 'cloud'
        
        # Extract IP-based geo location (simulated)
        src_ip = event_dict.get('source_ip')
        if src_ip:
            report.normalized_fields['src_country'] = self._get_geo_country(src_ip)
    
    def _normalize_for_splunk(self, event_dict: Dict[str, Any], report: NormalizationReport) -> None:
        """Splunk-specific normalization."""
        # Set sourcetype based on source_type
        source_type = event_dict.get('source_type', '')
        sourcetype_map = {
            'windows': 'xmlwineventlog',
            'linux': 'syslog',
            'aws_cloudtrail': 'aws:cloudtrail',
            'firewall': 'pan:traffic',
            'proxy': 'bluecoat:proxysg:access:syslog',
        }
        report.normalized_fields['sourcetype'] = sourcetype_map.get(source_type, source_type)
        report.normalized_fields['index'] = 'main'
    
    def _normalize_for_elastic(self, event_dict: Dict[str, Any], report: NormalizationReport) -> None:
        """Elasticsearch/ECS-specific normalization."""
        # Map to ECS fields
        if 'source_ip' in event_dict:
            report.normalized_fields['source'] = {'ip': event_dict['source_ip']}
        
        if 'source_host' in event_dict:
            report.normalized_fields['host'] = {'name': event_dict['source_host']}
        
        # ECS event fields
        report.normalized_fields['ecs'] = {'version': '8.11.0'}
        
        # Map severity to ECS
        severity = event_dict.get('severity')
        if severity:
            if isinstance(severity, str):
                sev_value = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}.get(severity, 1)
            else:
                sev_value = getattr(severity, 'value', 1)
            report.normalized_fields['event'] = {
                'severity': sev_value,
                'original': event_dict.get('raw_log', '')
            }
    
    def _normalize_for_qradar(self, event_dict: Dict[str, Any], report: NormalizationReport) -> None:
        """QRadar-specific normalization."""
        # QRadar uses QID (QRadar Identifier) for event categorization
        source_type = event_dict.get('source_type', '')
        qid_map = {
            'windows': 38750003,
            'linux': 38750001,
            'firewall': 16001,
            'aws_cloudtrail': 45200001,
        }
        report.normalized_fields['qid'] = qid_map.get(source_type, 0)
        report.normalized_fields['logsourceid'] = 1234
        
        # Convert severity to QRadar scale (0-10)
        severity = event_dict.get('severity')
        if severity:
            if hasattr(severity, 'value'):
                report.normalized_fields['severity'] = severity.value * 2  # Scale 1-4 to 2-8
            elif isinstance(severity, str):
                sev_map = {'LOW': 2, 'MEDIUM': 5, 'HIGH': 8, 'CRITICAL': 10}
                report.normalized_fields['severity'] = sev_map.get(severity, 5)
    
    def _normalize_for_arcsight(self, event_dict: Dict[str, Any], report: NormalizationReport) -> None:
        """ArcSight-specific normalization."""
        # ArcSight uses CEF extensively
        fields = event_dict.get('fields', {})
        
        # Device info
        if 'vendor' in fields:
            report.normalized_fields['deviceVendor'] = fields['vendor']
        else:
            report.normalized_fields['deviceVendor'] = 'Generic'
        
        report.normalized_fields['deviceProduct'] = event_dict.get('source_type', 'Unknown')
        report.normalized_fields['deviceVersion'] = '1.0'
        report.normalized_fields['deviceEventClassId'] = fields.get('eventName', 'Unknown')
    
    def _get_geo_country(self, ip: str) -> str:
        """Simulate geo IP lookup."""
        # Simplified simulation
        if ip.startswith(('10.', '192.168.', '172.16.')):
            return 'Private'
        elif ip.startswith('203.0.113.'):
            return 'BE'  # Belgium
        elif ip.startswith('198.51.100.'):
            return 'US'
        else:
            return 'Unknown'


# Test function
def test_normalization():
    """Test SIEM normalization."""
    from core import AssetInventory
    from generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
    
    print("SIEM Normalization Test")
    print("=" * 60)
    
    inventory = AssetInventory()
    generator = AWSCloudTrailGenerator({'eps': 10}, inventory)
    event = generator.generate_event()
    
    for siem_type in [SIEMType.LOGPOINT, SIEMType.SPLUNK, SIEMType.ELASTIC]:
        print(f"\n{siem_type.value.upper()}:")
        normalizer = SIEMNormalizer(siem_type)
        report = normalizer.normalize(event)
        
        print(f"  Status: {report.status.value}")
        print(f"  Extraction Rate: {report.extraction_rate:.1%}")
        print(f"  Fields: {len(report.normalized_fields)}")
        
        if siem_type == SIEMType.LOGPOINT:
            print(f"\n  CEF Output:\n    {normalizer.to_cef(event)[:100]}...")


if __name__ == "__main__":
    test_normalization()
