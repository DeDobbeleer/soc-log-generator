#!/usr/bin/env python3
"""
Version Manager - Track and manage log format versions

This module provides version detection, management, and migration capabilities
for log formats that evolve over time.

Usage:
    from validation.version_manager import VersionManager, VersionInfo
    
    vm = VersionManager()
    
    # Register a new version
    vm.register_version("windows", "2.1.0", {
        "released": "2024-03-01",
        "changes": ["Added EventID 4662"],
        "breaking": False
    })
    
    # Detect version from sample
    detected = vm.detect_version(sample_log, "windows")
    print(f"Detected version: {detected.version}")
    
    # Get current version
    current = vm.get_current_version("windows")
    
    # List available versions
    versions = vm.list_versions("windows")

Author: SOC Log Generator Research Team
Version: 1.0.0
"""

import json
import re
import yaml
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import defaultdict


class VersionChangeType(Enum):
    """Types of changes in a version."""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    DEPRECATED = "deprecated"


@dataclass
class VersionChange:
    """Represents a single change in a version."""
    type: VersionChangeType
    description: str
    field: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "description": self.description,
            "field": self.field,
            "details": self.details
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'VersionChange':
        return cls(
            type=VersionChangeType(data.get("type", "modified")),
            description=data["description"],
            field=data.get("field"),
            details=data.get("details", {})
        )


@dataclass
class VersionInfo:
    """Complete information about a format version."""
    version: str
    source_type: str
    released: str  # YYYY-MM-DD
    changes: List[Union[str, VersionChange]] = field(default_factory=list)
    breaking: bool = False
    supported: bool = True
    deprecated: Optional[str] = None  # YYYY-MM-DD if deprecated
    superseded_by: Optional[str] = None
    min_platform_version: Optional[str] = None
    max_platform_version: Optional[str] = None
    documentation_url: Optional[str] = None
    migration_guide: Optional[str] = None
    
    # Field-level changes
    added_fields: List[str] = field(default_factory=list)
    removed_fields: List[str] = field(default_factory=list)
    modified_fields: Dict[str, Dict] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "version": self.version,
            "source_type": self.source_type,
            "released": self.released,
            "changes": [
                c.to_dict() if isinstance(c, VersionChange) else c 
                for c in self.changes
            ],
            "breaking": self.breaking,
            "supported": self.supported,
            "deprecated": self.deprecated,
            "superseded_by": self.superseded_by,
            "min_platform_version": self.min_platform_version,
            "max_platform_version": self.max_platform_version,
            "documentation_url": self.documentation_url,
            "migration_guide": self.migration_guide,
            "added_fields": self.added_fields,
            "removed_fields": self.removed_fields,
            "modified_fields": self.modified_fields
        }
        return {k: v for k, v in result.items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: Dict, source_type: str) -> 'VersionInfo':
        """Create from dictionary."""
        changes = []
        for c in data.get("changes", []):
            if isinstance(c, dict):
                changes.append(VersionChange.from_dict(c))
            else:
                changes.append(c)
        
        return cls(
            version=data["version"],
            source_type=source_type,
            released=data["released"],
            changes=changes,
            breaking=data.get("breaking", False),
            supported=data.get("supported", True),
            deprecated=data.get("deprecated"),
            superseded_by=data.get("superseded_by"),
            min_platform_version=data.get("min_platform_version"),
            max_platform_version=data.get("max_platform_version"),
            documentation_url=data.get("documentation_url"),
            migration_guide=data.get("migration_guide"),
            added_fields=data.get("added_fields", []),
            removed_fields=data.get("removed_fields", []),
            modified_fields=data.get("modified_fields", {})
        )


@dataclass
class VersionDetectionResult:
    """Result of version detection."""
    source_type: str
    version: str
    confidence: float  # 0.0 - 1.0
    method: str  # How version was detected
    indicators: List[str] = field(default_factory=list)
    possible_versions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "version": self.version,
            "confidence": self.confidence,
            "method": self.method,
            "indicators": self.indicators,
            "possible_versions": self.possible_versions
        }


class VersionManager:
    """
    Manage log format versions across all sources.
    
    This class provides:
    - Version registration and tracking
    - Version detection from samples
    - Version comparison and migration
    - Version selection for generation
    
    Example:
        vm = VersionManager()
        
        # Check current version
        current = vm.get_current_version("windows")
        print(f"Current: {current.version}")
        
        # Detect version from sample
        sample = {"EventID": 4624, "LogonType": 11, ...}
        result = vm.detect_version(sample, "windows")
        print(f"Detected: {result.version} (confidence: {result.confidence})")
    """
    
    DEFAULT_REGISTRY_PATH = Path(__file__).parent / "version_registry.yaml"
    
    def __init__(self, registry_path: Optional[Union[str, Path]] = None):
        """
        Initialize VersionManager.
        
        Args:
            registry_path: Path to version registry file (YAML)
        """
        self.registry_path = Path(registry_path) if registry_path else self.DEFAULT_REGISTRY_PATH
        self._registry: Dict[str, Dict[str, VersionInfo]] = defaultdict(dict)
        self._current_versions: Dict[str, str] = {}
        self._load_registry()
    
    def _load_registry(self) -> None:
        """Load version registry from file."""
        if not self.registry_path.exists():
            # Create default registry
            self._create_default_registry()
            return
        
        try:
            with open(self.registry_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            for source_type, source_data in data.get("sources", {}).items():
                self._current_versions[source_type] = source_data.get("current_version", "")
                
                for version_str, version_data in source_data.get("versions", {}).items():
                    version_info = VersionInfo.from_dict(version_data, source_type)
                    version_info.version = version_str
                    self._registry[source_type][version_str] = version_info
                    
        except Exception as e:
            print(f"Warning: Failed to load version registry: {e}")
            self._create_default_registry()
    
    def _create_default_registry(self) -> None:
        """Create default registry with known versions."""
        default_versions = {
            "windows": {
                "current_version": "2.1.0",
                "versions": {
                    "2.1.0": {
                        "released": "2024-03-01",
                        "changes": [
                            "Added EventID 4662 (Object Access) detailed fields",
                            "Added LogonType 11 (CachedInteractive)",
                            "Updated SubjectUserSid for virtual accounts"
                        ],
                        "breaking": False,
                        "supported": True,
                        "min_platform_version": "Windows Server 2016",
                        "max_platform_version": "Windows Server 2022",
                        "added_fields": ["VirtualAccount", "VirtualAccountSid"],
                        "documentation_url": "https://docs.microsoft.com/..."
                    },
                    "2.0.0": {
                        "released": "2023-06-15",
                        "changes": [
                            "Restructured SubjectUserSid format",
                            "Added Azure AD joined device support"
                        ],
                        "breaking": True,
                        "supported": True,
                        "superseded_by": "2.1.0",
                        "migration_guide": "https://docs.microsoft.com/..."
                    },
                    "1.9.0": {
                        "released": "2023-01-10",
                        "changes": ["Initial comprehensive coverage"],
                        "breaking": False,
                        "supported": False,
                        "deprecated": "2023-12-31"
                    }
                }
            },
            "aws": {
                "current_version": "1.08",
                "versions": {
                    "1.08": {
                        "released": "2021-11-04",
                        "changes": ["Added sessionIssuer field", "Enhanced VPC endpoint context"],
                        "breaking": False,
                        "supported": True,
                        "documentation_url": "https://docs.aws.amazon.com/..."
                    },
                    "1.07": {
                        "released": "2020-11-10",
                        "changes": ["Added eventCategory field"],
                        "breaking": False,
                        "supported": True,
                        "superseded_by": "1.08"
                    }
                }
            },
            "azure": {
                "current_version": "2021-09-01",
                "versions": {
                    "2021-09-01": {
                        "released": "2021-09-01",
                        "changes": ["Current stable schema"],
                        "breaking": False,
                        "supported": True
                    }
                }
            },
            "linux": {
                "current_version": "1.0.0",
                "versions": {
                    "1.0.0": {
                        "released": "2024-01-01",
                        "changes": ["Initial standardized format"],
                        "breaking": False,
                        "supported": True
                    }
                }
            }
        }
        
        for source_type, source_data in default_versions.items():
            self._current_versions[source_type] = source_data["current_version"]
            for version_str, version_data in source_data["versions"].items():
                version_info = VersionInfo.from_dict(version_data, source_type)
                version_info.version = version_str
                self._registry[source_type][version_str] = version_info
        
        self.save_registry()
    
    def save_registry(self) -> None:
        """Save registry to file."""
        data = {
            "sources": {},
            "last_updated": datetime.utcnow().isoformat()
        }
        
        for source_type, versions in self._registry.items():
            data["sources"][source_type] = {
                "current_version": self._current_versions.get(source_type, ""),
                "versions": {
                    v.version: v.to_dict() for v in versions.values()
                }
            }
        
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.registry_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=True)
    
    def register_version(self, source_type: str, version: str, 
                         info: Union[VersionInfo, Dict]) -> None:
        """
        Register a new version for a source type.
        
        Args:
            source_type: Source type identifier
            version: Version string (e.g., "2.1.0")
            info: VersionInfo or dict with version details
        """
        if isinstance(info, dict):
            info = VersionInfo.from_dict(info, source_type)
            info.version = version
        
        self._registry[source_type][version] = info
        
        # Update current version if this is newer
        if version not in self._registry[source_type] or info.breaking is False:
            current = self._current_versions.get(source_type, "")
            if self._compare_versions(version, current) > 0:
                self._current_versions[source_type] = version
        
        self.save_registry()
    
    def get_version(self, source_type: str, version: str) -> Optional[VersionInfo]:
        """
        Get version information.
        
        Args:
            source_type: Source type
            version: Version string
            
        Returns:
            VersionInfo or None if not found
        """
        return self._registry.get(source_type, {}).get(version)
    
    def get_current_version(self, source_type: str) -> Optional[VersionInfo]:
        """
        Get current (latest supported) version.
        
        Args:
            source_type: Source type
            
        Returns:
            VersionInfo or None
        """
        current = self._current_versions.get(source_type)
        if current:
            return self.get_version(source_type, current)
        return None
    
    def list_versions(self, source_type: str, include_deprecated: bool = False) -> List[VersionInfo]:
        """
        List all versions for a source type.
        
        Args:
            source_type: Source type
            include_deprecated: Whether to include deprecated versions
            
        Returns:
            List of VersionInfo objects
        """
        versions = []
        for v in self._registry.get(source_type, {}).values():
            if include_deprecated or v.supported:
                versions.append(v)
        
        # Sort by version
        return sorted(versions, key=lambda x: x.version, reverse=True)
    
    def detect_version(self, sample: Dict[str, Any], source_type: str) -> VersionDetectionResult:
        """
        Detect format version from a sample log entry.
        
        Args:
            sample: Sample log entry
            source_type: Source type
            
        Returns:
            VersionDetectionResult with detected version and confidence
        """
        indicators = []
        possible = []
        
        # Get all versions for this source
        versions = self.list_versions(source_type, include_deprecated=True)
        
        if not versions:
            return VersionDetectionResult(
                source_type=source_type,
                version="unknown",
                confidence=0.0,
                method="no_versions",
                indicators=["No versions registered for this source type"]
            )
        
        # Check for explicit version fields
        version_field = self._extract_version_field(sample, source_type)
        if version_field:
            indicators.append(f"Explicit version field: {version_field}")
            for v in versions:
                if v.version in version_field or version_field in v.version:
                    possible.append(v.version)
        
        # Check for field presence indicators
        field_indicators = self._check_field_indicators(sample, source_type)
        indicators.extend(field_indicators)
        
        # Check for version-specific patterns
        pattern_indicators = self._check_pattern_indicators(sample, source_type)
        indicators.extend(pattern_indicators)
        
        # Determine most likely version
        if possible:
            detected = possible[0]
            confidence = 0.9 if len(possible) == 1 else 0.7
            method = "explicit_version"
        elif field_indicators:
            # Infer from fields
            detected = self._infer_version_from_fields(sample, source_type, versions)
            confidence = 0.7
            method = "field_analysis"
            possible = [detected] if detected else [v.version for v in versions[:3]]
        else:
            # Default to current version
            current = self.get_current_version(source_type)
            detected = current.version if current else versions[0].version
            confidence = 0.5
            method = "default"
            possible = [v.version for v in versions[:3]]
        
        return VersionDetectionResult(
            source_type=source_type,
            version=detected,
            confidence=confidence,
            method=method,
            indicators=indicators,
            possible_versions=possible
        )
    
    def _extract_version_field(self, sample: Dict, source_type: str) -> Optional[str]:
        """Try to extract explicit version from sample."""
        version_fields = {
            "aws": ["eventVersion"],
            "azure": ["apiVersion", "version"],
            "gcp": ["apiVersion"],
            "windows": ["Version", "EventVersion"],
            "linux": ["version"],
            "sysmon": ["Version"]
        }
        
        fields = version_fields.get(source_type, ["version", "apiVersion"])
        
        for field in fields:
            if field in sample:
                return str(sample[field])
            # Check nested
            for key, value in sample.items():
                if isinstance(value, dict) and field in value:
                    return str(value[field])
        
        return None
    
    def _check_field_indicators(self, sample: Dict, source_type: str) -> List[str]:
        """Check for version-specific field indicators."""
        indicators = []
        
        # Windows-specific checks
        if source_type == "windows":
            if "VirtualAccount" in str(sample):
                indicators.append("Has VirtualAccount field (v2.1+)")
            if sample.get("LogonType") == 11:
                indicators.append("LogonType 11 present (v2.1+)")
            if "SubjectUserSid" in sample and sample.get("EventID") in [4624, 4625]:
                indicators.append("Standard security event fields")
        
        # AWS-specific checks
        if source_type == "aws":
            if "sessionIssuer" in str(sample):
                indicators.append("Has sessionIssuer (v1.08+)")
            if "eventCategory" in sample:
                indicators.append("Has eventCategory (v1.07+)")
        
        # Azure-specific checks
        if source_type == "azure":
            if "resourceProvider" in sample and "category" in sample:
                indicators.append("Modern Activity Log structure")
        
        return indicators
    
    def _check_pattern_indicators(self, sample: Dict, source_type: str) -> List[str]:
        """Check for version-specific pattern indicators."""
        indicators = []
        sample_str = str(sample)
        
        if source_type == "windows":
            # Check SID format
            sid_pattern = r'S-1-5-21-\d+-\d+-\d+-\d+'
            if re.search(sid_pattern, sample_str):
                indicators.append("Modern SID format detected")
        
        return indicators
    
    def _infer_version_from_fields(self, sample: Dict, source_type: str, 
                                    versions: List[VersionInfo]) -> Optional[str]:
        """Infer version based on field presence."""
        sample_fields = self._get_all_fields(sample)
        
        best_match = None
        best_score = 0
        
        for version in versions:
            score = 0
            # Check added fields
            for field in version.added_fields:
                if field in sample_fields:
                    score += 1
            # Check removed fields (negative)
            for field in version.removed_fields:
                if field in sample_fields:
                    score -= 1
            
            if score > best_score:
                best_score = score
                best_match = version.version
        
        return best_match
    
    def _get_all_fields(self, sample: Dict, prefix: str = "") -> Set[str]:
        """Get all field names from nested sample."""
        fields = set()
        
        for key, value in sample.items():
            full_key = f"{prefix}.{key}" if prefix else key
            fields.add(full_key)
            
            if isinstance(value, dict):
                fields.update(self._get_all_fields(value, full_key))
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                fields.update(self._get_all_fields(value[0], full_key))
        
        return fields
    
    def compare_versions(self, source_type: str, version1: str, 
                         version2: str) -> Dict[str, Any]:
        """
        Compare two versions and return differences.
        
        Args:
            source_type: Source type
            version1: First version
            version2: Second version
            
        Returns:
            Dictionary with comparison results
        """
        v1 = self.get_version(source_type, version1)
        v2 = self.get_version(source_type, version2)
        
        if not v1 or not v2:
            return {"error": "One or both versions not found"}
        
        return {
            "version1": version1,
            "version2": version2,
            "breaking_changes": v2.breaking if self._compare_versions(version2, version1) > 0 else v1.breaking,
            "added_in_v2": list(set(v2.added_fields) - set(v1.added_fields)),
            "removed_in_v2": list(set(v1.added_fields) - set(v2.added_fields)),
            "fields_only_in_v1": list(set(v1.added_fields) - set(v2.added_fields)),
            "fields_only_in_v2": list(set(v2.added_fields) - set(v1.added_fields)),
            "migration_required": v2.breaking if self._compare_versions(version2, version1) > 0 else False
        }
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
        if not v2:
            return 1
        
        # Parse version components
        def parse(v):
            # Handle different formats: "2.1.0", "1.08", "2021-09-01"
            parts = re.split(r'[.-]', v)
            result = []
            for p in parts:
                try:
                    result.append(int(p))
                except ValueError:
                    result.append(p)
            return result
        
        p1, p2 = parse(v1), parse(v2)
        
        for i in range(max(len(p1), len(p2))):
            a = p1[i] if i < len(p1) else 0
            b = p2[i] if i < len(p2) else 0
            
            if isinstance(a, int) and isinstance(b, int):
                if a > b:
                    return 1
                elif a < b:
                    return -1
            else:
                sa, sb = str(a), str(b)
                if sa > sb:
                    return 1
                elif sa < sb:
                    return -1
        
        return 0
    
    def get_migration_path(self, source_type: str, from_version: str, 
                           to_version: str) -> List[Dict]:
        """
        Get migration steps between versions.
        
        Args:
            source_type: Source type
            from_version: Starting version
            to_version: Target version
            
        Returns:
            List of migration steps
        """
        steps = []
        
        # Get all versions between from and to
        all_versions = self.list_versions(source_type, include_deprecated=True)
        
        # Filter versions between from and to
        between = []
        found_from = False
        for v in all_versions:
            if v.version == from_version:
                found_from = True
                continue
            if v.version == to_version:
                break
            if found_from:
                between.append(v)
        
        # Build migration steps
        for v in between:
            steps.append({
                "version": v.version,
                "changes": [c if isinstance(c, str) else c.description for c in v.changes],
                "breaking": v.breaking,
                "migration_guide": v.migration_guide
            })
        
        return steps


def main():
    """CLI for Version Manager."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage log format versions")
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # List versions
    list_cmd = subparsers.add_parser("list", help="List versions for a source")
    list_cmd.add_argument("--source", required=True, help="Source type")
    list_cmd.add_argument("--all", action="store_true", help="Include deprecated")
    
    # Detect version
    detect_cmd = subparsers.add_parser("detect", help="Detect version from sample")
    detect_cmd.add_argument("--sample", required=True, help="Sample JSON file")
    detect_cmd.add_argument("--source", required=True, help="Source type")
    
    # Compare versions
    compare_cmd = subparsers.add_parser("compare", help="Compare two versions")
    compare_cmd.add_argument("--source", required=True, help="Source type")
    compare_cmd.add_argument("--v1", required=True, help="First version")
    compare_cmd.add_argument("--v2", required=True, help="Second version")
    
    # Register version
    register_cmd = subparsers.add_parser("register", help="Register new version")
    register_cmd.add_argument("--source", required=True, help="Source type")
    register_cmd.add_argument("--version", required=True, help="Version string")
    register_cmd.add_argument("--released", required=True, help="Release date (YYYY-MM-DD)")
    register_cmd.add_argument("--breaking", action="store_true", help="Is breaking change")
    
    args = parser.parse_args()
    
    vm = VersionManager()
    
    if args.command == "list":
        versions = vm.list_versions(args.source, include_deprecated=args.all)
        print(f"\nVersions for {args.source}:")
        print("-" * 60)
        for v in versions:
            status = "✅" if v.supported else "⛔"
            current = " [CURRENT]" if vm._current_versions.get(args.source) == v.version else ""
            print(f"{status} {v.version}{current}")
            print(f"   Released: {v.released}")
            print(f"   Breaking: {v.breaking}")
            if v.deprecated:
                print(f"   Deprecated: {v.deprecated}")
            print()
    
    elif args.command == "detect":
        with open(args.sample, 'r') as f:
            sample = json.load(f)
        
        result = vm.detect_version(sample, args.source)
        print(json.dumps(result.to_dict(), indent=2))
    
    elif args.command == "compare":
        comparison = vm.compare_versions(args.source, args.v1, args.v2)
        print(json.dumps(comparison, indent=2))
    
    elif args.command == "register":
        vm.register_version(
            args.source,
            args.version,
            {
                "released": args.released,
                "breaking": args.breaking,
                "changes": ["New version registered via CLI"]
            }
        )
        print(f"Registered {args.source} version {args.version}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
