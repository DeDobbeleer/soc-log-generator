#!/usr/bin/env python3
"""
SIEM Parsers

Parser simulations for major SIEM platforms.
Tests field extraction and normalization rules.
"""

import re
import json
from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod


class BaseParser(ABC):
    """Base class for SIEM parsers."""
    
    def __init__(self, name: str):
        self.name = name
        self.extraction_rules: List[Dict[str, Any]] = []
    
    @abstractmethod
    def parse(self, raw_log: str) -> Dict[str, Any]:
        """Parse raw log string."""
        pass
    
    @abstractmethod
    def extract_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract fields from parsed event."""
        pass


class LogPointParser(BaseParser):
    """LogPoint parser simulation."""
    
    def __init__(self):
        super().__init__("LogPoint")
        self.extraction_rules = [
            {"pattern": r"timestamp=(\S+)", "field": "timestamp", "type": "datetime"},
            {"pattern": r"src_ip=(\S+)", "field": "device_address", "type": "ip"},
            {"pattern": r"user=(\S+)", "field": "user", "type": "string"},
            {"pattern": r"action=(\S+)", "field": "action", "type": "string"},
        ]
    
    def parse(self, raw_log: str) -> Dict[str, Any]:
        """Parse LogPoint formatted log."""
        result = {"raw": raw_log, "parsed": {}}
        
        for rule in self.extraction_rules:
            match = re.search(rule["pattern"], raw_log)
            if match:
                result["parsed"][rule["field"]] = match.group(1)
        
        return result
    
    def extract_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract fields for LogPoint."""
        extracted = {}
        
        # Map to LogPoint fields
        field_map = {
            "source_ip": "device_address",
            "user": "user",
            "action": "action",
            "timestamp": "timestamp",
            "message": "msg",
        }
        
        for src, dst in field_map.items():
            if src in event:
                extracted[dst] = event[src]
        
        return extracted


class SplunkParser(BaseParser):
    """Splunk parser simulation."""
    
    def __init__(self):
        super().__init__("Splunk")
        self.extraction_rules = [
            {"pattern": r"(\w+)=([^\s,]+)", "extract_all": True},
        ]
    
    def parse(self, raw_log: str) -> Dict[str, Any]:
        """Parse using Splunk's auto-extraction."""
        result = {"_raw": raw_log, "extracted": {}}
        
        # Auto-extract key=value pairs
        matches = re.findall(r"(\w+)=([^\s,]+)", raw_log)
        for key, value in matches:
            result["extracted"][key] = value
        
        return result
    
    def extract_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract fields for Splunk."""
        extracted = {
            "_time": event.get("timestamp"),
            "_raw": event.get("raw_log", ""),
            "sourcetype": event.get("source_type", ""),
            "host": event.get("source_host", ""),
        }
        
        # Add all fields from event.fields
        if "fields" in event:
            extracted.update(event["fields"])
        
        return extracted
    
    def to_splunk_search(self, event: Dict[str, Any]) -> str:
        """Generate Splunk search query for this event type."""
        source_type = event.get("source_type", "*")
        return f'sourcetype="{source_type}" | stats count by source_host'


class ELKParser(BaseParser):
    """Elasticsearch/ELK parser simulation."""
    
    def __init__(self):
        super().__init__("ELK")
    
    def parse(self, raw_log: str) -> Dict[str, Any]:
        """Parse JSON formatted log for ELK."""
        try:
            return json.loads(raw_log)
        except json.JSONDecodeError:
            return {"message": raw_log, "parse_error": True}
    
    def extract_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract ECS fields."""
        extracted = {
            "@timestamp": event.get("timestamp"),
            "message": event.get("message"),
            "event.original": event.get("raw_log"),
            "ecs.version": "8.11.0",
        }
        
        # ECS source fields
        if "source_ip" in event:
            extracted["source.ip"] = event["source_ip"]
        if "source_host" in event:
            extracted["host.name"] = event["source_host"]
        
        # ECS event fields
        if "severity" in event:
            sev = event["severity"]
            if hasattr(sev, "value"):
                extracted["event.severity"] = sev.value
            else:
                extracted["event.severity"] = sev
        
        return extracted
    
    def get_index_mapping(self) -> Dict[str, Any]:
        """Get Elasticsearch index mapping."""
        return {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "message": {"type": "text"},
                    "source.ip": {"type": "ip"},
                    "event.severity": {"type": "integer"},
                }
            }
        }


class QRadarParser(BaseParser):
    """QRadar parser simulation."""
    
    def __init__(self):
        super().__init__("QRadar")
        self.qid_map = {
            "windows": 38750003,
            "linux": 38750001,
            "firewall": 16001,
            "aws_cloudtrail": 45200001,
        }
    
    def parse(self, raw_log: str) -> Dict[str, Any]:
        """Parse LEEF formatted log."""
        result = {"payload": raw_log, "attrs": {}}
        
        # Parse LEEF attributes
        if "\t" in raw_log:
            parts = raw_log.split("\t")
            for part in parts[4:]:  # Skip LEEF header
                if "=" in part:
                    key, value = part.split("=", 1)
                    result["attrs"][key] = value
        
        return result
    
    def extract_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract fields for QRadar."""
        source_type = event.get("source_type", "")
        
        extracted = {
            "starttime": event.get("timestamp"),
            "payload": event.get("raw_log", ""),
            "sourceip": event.get("source_ip"),
            "username": event.get("fields", {}).get("user"),
            "logsourceid": 1234,
            "qid": self.qid_map.get(source_type, 0),
        }
        
        return extracted
    
    def get_qid(self, source_type: str) -> int:
        """Get QRadar QID for source type."""
        return self.qid_map.get(source_type, 0)


# Parser factory
def get_parser(siem_name: str) -> BaseParser:
    """
    Get parser for SIEM.
    
    Args:
        siem_name: Name of SIEM (logpoint, splunk, elk, qradar)
        
    Returns:
        Parser instance
    """
    parsers = {
        "logpoint": LogPointParser,
        "splunk": SplunkParser,
        "elk": ELKParser,
        "qradar": QRadarParser,
    }
    
    parser_class = parsers.get(siem_name.lower(), SplunkParser)
    return parser_class()
