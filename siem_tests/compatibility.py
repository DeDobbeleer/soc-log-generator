#!/usr/bin/env python3
"""
SIEM Compatibility Matrix

Tracks compatibility of generators with different SIEMs.
"""

from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class CompatibilityEntry:
    """Compatibility entry for a generator/SIEM pair."""
    generator: str
    siem: str
    supported: bool
    cef_supported: bool
    json_supported: bool
    syslog_supported: bool
    notes: str = ""


class SIEMCompatibilityMatrix:
    """
    Matrix of generator compatibility with SIEMs.
    
    Usage:
        matrix = SIEMCompatibilityMatrix()
        compat = matrix.get_compatibility("aws_cloudtrail", "splunk")
        print(compat.supported)  # True
    """
    
    # Compatibility data
    _matrix: Dict[str, Dict[str, CompatibilityEntry]] = {
        "aws_cloudtrail": {
            "splunk": CompatibilityEntry("aws_cloudtrail", "splunk", True, True, True, False, "Use aws:cloudtrail sourcetype"),
            "elk": CompatibilityEntry("aws_cloudtrail", "elk", True, True, True, False, "Use Filebeat AWS module"),
            "logpoint": CompatibilityEntry("aws_cloudtrail", "logpoint", True, True, True, False, "Collect via S3"),
            "qradar": CompatibilityEntry("aws_cloudtrail", "qradar", True, True, True, False, "Use AWS DSM"),
            "arcsight": CompatibilityEntry("aws_cloudtrail", "arcsight", True, True, True, False, "Use AWS FlexConnector"),
        },
        "azure_activity": {
            "splunk": CompatibilityEntry("azure_activity", "splunk", True, False, True, False, "Use Splunk Add-on for Azure"),
            "elk": CompatibilityEntry("azure_activity", "elk", True, False, True, False, "Use Azure Monitor integration"),
            "logpoint": CompatibilityEntry("azure_activity", "logpoint", True, False, True, False, "Use Azure collector"),
            "sentinel": CompatibilityEntry("azure_activity", "sentinel", True, False, True, False, "Native integration"),
        },
        "windows": {
            "splunk": CompatibilityEntry("windows", "splunk", True, True, True, False, "Use Universal Forwarder"),
            "elk": CompatibilityEntry("windows", "elk", True, False, True, False, "Use Winlogbeat"),
            "logpoint": CompatibilityEntry("windows", "logpoint", True, True, True, False, "Use WEC"),
            "qradar": CompatibilityEntry("windows", "qradar", True, True, True, False, "Use WinCollect"),
        },
        "linux": {
            "splunk": CompatibilityEntry("linux", "splunk", True, False, False, True, "Use Universal Forwarder"),
            "elk": CompatibilityEntry("linux", "elk", True, False, True, True, "Use Filebeat"),
            "logpoint": CompatibilityEntry("linux", "logpoint", True, False, False, True, "Syslog collection"),
        },
        "firewall": {
            "splunk": CompatibilityEntry("firewall", "splunk", True, True, True, False, "Use TA-paloalto"),
            "elk": CompatibilityEntry("firewall", "elk", True, True, True, False, "Use Filebeat"),
            "logpoint": CompatibilityEntry("firewall", "logpoint", True, True, True, False, "Syslog/CEF"),
            "qradar": CompatibilityEntry("firewall", "qradar", True, True, True, False, "Use Palo Alto DSM"),
        },
    }
    
    @classmethod
    def get_compatibility(cls, generator: str, siem: str) -> CompatibilityEntry:
        """
        Get compatibility for generator/SIEM pair.
        
        Args:
            generator: Generator type
            siem: SIEM name
            
        Returns:
            CompatibilityEntry
        """
        gen_lower = generator.lower()
        siem_lower = siem.lower()
        
        if gen_lower in cls._matrix and siem_lower in cls._matrix[gen_lower]:
            return cls._matrix[gen_lower][siem_lower]
        
        # Default: assume basic syslog support
        return CompatibilityEntry(
            generator=generator,
            siem=siem,
            supported=True,
            cef_supported=True,
            json_supported=True,
            syslog_supported=True,
            notes="Generic support via syslog"
        )
    
    @classmethod
    def get_supported_siems(cls, generator: str) -> List[str]:
        """Get list of SIEMs supporting this generator."""
        gen_lower = generator.lower()
        if gen_lower in cls._matrix:
            return [siem for siem, entry in cls._matrix[gen_lower].items() if entry.supported]
        return ["splunk", "elk", "logpoint", "qradar"]  # Default list
    
    @classmethod
    def get_recommended_format(cls, generator: str, siem: str) -> str:
        """Get recommended format for generator/SIEM pair."""
        entry = cls.get_compatibility(generator, siem)
        
        if entry.json_supported and siem in ["splunk", "elk", "sentinel"]:
            return "json"
        elif entry.cef_supported:
            return "cef"
        elif entry.syslog_supported:
            return "syslog"
        else:
            return "raw"
    
    @classmethod
    def print_matrix(cls):
        """Print compatibility matrix."""
        print("\nSIEM COMPATIBILITY MATRIX")
        print("=" * 80)
        
        all_siems = ["splunk", "elk", "logpoint", "qradar", "sentinel", "arcsight"]
        
        # Header
        print(f"{'Generator':<20}", end="")
        for siem in all_siems:
            print(f"{siem:<12}", end="")
        print()
        print("-" * 80)
        
        # Rows
        for generator in cls._matrix:
            print(f"{generator:<20}", end="")
            for siem in all_siems:
                entry = cls.get_compatibility(generator, siem)
                symbol = "✅" if entry.supported else "❌"
                print(f"{symbol:<12}", end="")
            print()
        
        print("=" * 80)


if __name__ == "__main__":
    SIEMCompatibilityMatrix.print_matrix()
