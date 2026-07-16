#!/usr/bin/env python3
"""
Sample Collector - Collect and anonymize real log samples

This module provides tools for:
- Collecting log samples from various sources
- Anonymizing sensitive data (PII, IPs, hostnames)
- Validating sample quality
- Organizing samples by source type

Usage:
    from validation.sample_collector import SampleCollector
    
    collector = SampleCollector()
    
    # Collect from file
    collector.collect_from_file(
        "/var/log/auth.log",
        source_type="linux",
        output_dir="samples/linux/"
    )
    
    # Anonymize existing samples
    collector.anonymize_samples(
        "samples/raw/",
        "samples/anonymized/",
        rules={"ip": "10.0.0.x", "hostname": "host-{n}"}
    )

Author: SOC Log Generator Research Team
Version: 1.0.0
"""

import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Union
import random


@dataclass
class AnonymizationRule:
    """Rule for anonymizing a specific field or pattern."""
    name: str
    pattern: Union[str, Pattern]
    replacement: Union[str, Callable[[str], str]]
    description: str = ""
    
    def apply(self, value: str) -> str:
        """Apply anonymization rule to value."""
        if callable(self.replacement):
            return self.replacement(value)
        return self.replacement


@dataclass
class CollectionResult:
    """Result of sample collection."""
    source_type: str
    files_collected: int
    events_collected: int
    events_anonymized: int
    output_dir: Path
    timestamp: datetime = field(default_factory=datetime.utcnow)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "files_collected": self.files_collected,
            "events_collected": self.events_collected,
            "events_anonymized": self.events_anonymized,
            "output_dir": str(self.output_dir),
            "timestamp": self.timestamp.isoformat(),
            "errors": self.errors
        }


class SampleCollector:
    """
    Collect and anonymize real log samples for validation.
    
    This class provides comprehensive tools for:
    - Collecting samples from files, directories, or SIEM exports
    - Anonymizing sensitive information
    - Validating sample quality
    - Organizing samples by source type
    
    Example:
        collector = SampleCollector()
        
        # Basic collection with auto-anonymization
        result = collector.collect_from_file(
            "/var/log/syslog",
            source_type="linux",
            output_dir="samples/linux/"
        )
        
        # Advanced anonymization
        rules = {
            "ip": "10.0.0.{n}",
            "domain": "example.com",
            "username": "user-{hash}"
        }
        collector.anonymize_samples("raw/", "clean/", rules)
    """
    
    # Default anonymization rules
    DEFAULT_RULES = {
        "ipv4": AnonymizationRule(
            name="ipv4",
            pattern=re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b'),
            replacement=lambda m: f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
            description="Replace IPv4 addresses with RFC1918 addresses"
        ),
        "ipv6": AnonymizationRule(
            name="ipv6",
            pattern=re.compile(r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
            replacement=lambda m: f"2001:db8::{random.randint(1, 65535)}",
            description="Replace IPv6 addresses with documentation addresses"
        ),
        "email": AnonymizationRule(
            name="email",
            pattern=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            replacement=lambda m: f"user{hash(m.group()) % 1000}@example.com",
            description="Replace email addresses"
        ),
        "hostname_windows": AnonymizationRule(
            name="hostname_windows",
            pattern=re.compile(r'\b[A-Z]{2,3}-WIN-[A-Z]{2,3}-\d{3,4}\b', re.I),
            replacement=lambda m: f"WK-WIN-{random.randint(1000, 9999):04d}",
            description="Replace Windows hostnames"
        ),
        "hostname_linux": AnonymizationRule(
            name="hostname_linux",
            pattern=re.compile(r'\b(srv|web|db|app|mail)-[a-z0-9]+\.[a-z0-9.-]+\b', re.I),
            replacement=lambda m: f"srv-{random.randint(100, 999):03d}.example.com",
            description="Replace Linux hostnames"
        ),
        "username": AnonymizationRule(
            name="username",
            pattern=re.compile(r'"user(name)?"\s*[=:]\s*"([^"]+)"', re.I),
            replacement=lambda m: f'"username":"user{hash(m.group(2)) % 1000}"',
            description="Replace usernames in JSON/key-value pairs"
        ),
        "sid": AnonymizationRule(
            name="sid",
            pattern=re.compile(r'S-1-5-21-\d+-\d+-\d+-\d+'),
            replacement=lambda m: f"S-1-5-21-{random.randint(1000000000, 9999999999)}-"
                                  f"{random.randint(1000000000, 9999999999)}-"
                                  f"{random.randint(1000000000, 9999999999)}-"
                                  f"{random.randint(1000, 9999)}",
            description="Replace Windows SIDs"
        ),
        "aws_account": AnonymizationRule(
            name="aws_account",
            pattern=re.compile(r'\b\d{12}\b'),
            replacement=lambda m: f"{random.randint(100000000000, 999999999999)}",
            description="Replace AWS account IDs"
        ),
        "arn": AnonymizationRule(
            name="arn",
            pattern=re.compile(r'arn:aws:[a-z]+:[a-z0-9-]*:\d{12}:[^\s"]+'),
            replacement=lambda m: "arn:aws:iam::123456789012:user/anonymized",
            description="Replace AWS ARNs"
        ),
        "domain": AnonymizationRule(
            name="domain",
            pattern=re.compile(r'\b[a-zA-Z0-9.-]+\.(com|net|org|io|co\.\w{2}|\w{2})\b'),
            replacement=lambda m: "example.com" if random.random() > 0.5 else "internal.local",
            description="Replace domain names"
        )
    }
    
    def __init__(self, custom_rules: Optional[Dict[str, AnonymizationRule]] = None):
        """
        Initialize SampleCollector.
        
        Args:
            custom_rules: Optional custom anonymization rules
        """
        self.rules = {**self.DEFAULT_RULES}
        if custom_rules:
            self.rules.update(custom_rules)
        
        # Tracking for consistent anonymization
        self._ip_mapping: Dict[str, str] = {}
        self._hostname_mapping: Dict[str, str] = {}
        self._username_mapping: Dict[str, str] = {}
        self._counter = 0
    
    def collect_from_file(self, filepath: Union[str, Path], 
                          source_type: str,
                          output_dir: Union[str, Path],
                          format_type: Optional[str] = None,
                          anonymize: bool = True,
                          max_samples: int = 1000) -> CollectionResult:
        """
        Collect samples from a single file.
        
        Args:
            filepath: Path to log file
            source_type: Type of log source
            output_dir: Directory to write samples
            format_type: Format type (json, jsonl, syslog, csv)
            anonymize: Whether to anonymize samples
            max_samples: Maximum samples to collect
            
        Returns:
            CollectionResult with details
        """
        filepath = Path(filepath)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        result = CollectionResult(
            source_type=source_type,
            files_collected=1,
            output_dir=output_dir
        )
        
        # Auto-detect format if not specified
        if format_type is None:
            format_type = self._detect_format(filepath)
        
        try:
            # Read and parse samples
            samples = self._parse_file(filepath, format_type, max_samples)
            result.events_collected = len(samples)
            
            # Anonymize if requested
            if anonymize:
                samples = [self.anonymize_sample(s, source_type) for s in samples]
                result.events_anonymized = len(samples)
            
            # Write to output
            output_file = output_dir / f"{filepath.stem}_samples.jsonl"
            self._write_samples(samples, output_file)
            
        except Exception as e:
            result.errors.append(str(e))
        
        return result
    
    def collect_from_directory(self, directory: Union[str, Path],
                               source_type: str,
                               output_dir: Union[str, Path],
                               pattern: str = "*.log",
                               anonymize: bool = True,
                               max_samples: int = 1000) -> CollectionResult:
        """
        Collect samples from all matching files in a directory.
        
        Args:
            directory: Source directory
            source_type: Type of log source
            output_dir: Directory to write samples
            pattern: File glob pattern
            anonymize: Whether to anonymize samples
            max_samples: Maximum samples per file
            
        Returns:
            CollectionResult with details
        """
        directory = Path(directory)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        result = CollectionResult(
            source_type=source_type,
            output_dir=output_dir
        )
        
        files = list(directory.glob(pattern))
        result.files_collected = len(files)
        
        for filepath in files:
            try:
                file_result = self.collect_from_file(
                    filepath, source_type, output_dir,
                    anonymize=anonymize, max_samples=max_samples
                )
                result.events_collected += file_result.events_collected
                result.events_anonymized += file_result.events_anonymized
                result.errors.extend(file_result.errors)
            except Exception as e:
                result.errors.append(f"{filepath}: {e}")
        
        return result
    
    def _detect_format(self, filepath: Path) -> str:
        """Auto-detect file format."""
        suffix = filepath.suffix.lower()
        
        if suffix == '.json':
            return 'json'
        elif suffix == '.jsonl':
            return 'jsonl'
        elif suffix in ['.csv', '.tsv']:
            return 'csv'
        elif suffix in ['.log', '.txt', '']:
            # Check content
            with open(filepath, 'r') as f:
                first_line = f.readline()
                try:
                    json.loads(first_line)
                    return 'jsonl'
                except:
                    return 'syslog'
        
        return 'syslog'
    
    def _parse_file(self, filepath: Path, format_type: str, 
                    max_samples: int) -> List[Dict]:
        """Parse file and extract samples."""
        samples = []
        
        if format_type == 'json':
            with open(filepath, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    samples = data[:max_samples]
                else:
                    samples = [data]
        
        elif format_type == 'jsonl':
            with open(filepath, 'r') as f:
                for line in f:
                    if len(samples) >= max_samples:
                        break
                    try:
                        samples.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        elif format_type == 'syslog':
            # Parse syslog-style logs
            with open(filepath, 'r') as f:
                for line in f:
                    if len(samples) >= max_samples:
                        break
                    parsed = self._parse_syslog_line(line)
                    if parsed:
                        samples.append(parsed)
        
        elif format_type == 'csv':
            import csv
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if len(samples) >= max_samples:
                        break
                    samples.append(dict(row))
        
        return samples
    
    def _parse_syslog_line(self, line: str) -> Optional[Dict]:
        """Parse a syslog line into structured format."""
        # Basic syslog parsing
        pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$'
        match = re.match(pattern, line)
        
        if match:
            return {
                "timestamp": match.group(1),
                "hostname": match.group(2),
                "message": match.group(3),
                "raw": line.strip()
            }
        
        # Try RFC 5424 format
        rfc5424_pattern = r'^<(\d+)>\d+\s+(\S+)\s+(\S+)\s+(.*)$'
        match = re.match(rfc5424_pattern, line)
        
        if match:
            return {
                "priority": match.group(1),
                "timestamp": match.group(2),
                "hostname": match.group(3),
                "message": match.group(4),
                "raw": line.strip()
            }
        
        return None
    
    def anonymize_sample(self, sample: Dict[str, Any], 
                         source_type: str) -> Dict[str, Any]:
        """
        Anonymize a single sample.
        
        Args:
            sample: Sample to anonymize
            source_type: Type of log source
            
        Returns:
            Anonymized sample
        """
        # Convert to string for regex operations
        sample_str = json.dumps(sample) if isinstance(sample, dict) else str(sample)
        
        # Apply rules
        for rule_name, rule in self.rules.items():
            if isinstance(rule.pattern, str):
                sample_str = sample_str.replace(rule.pattern, rule.replacement)
            else:
                # Regex pattern
                def replace_match(match):
                    if callable(rule.replacement):
                        return rule.replacement(match)
                    return rule.replacement
                
                sample_str = rule.pattern.sub(replace_match, sample_str)
        
        # Additional source-specific anonymization
        sample_str = self._source_specific_anonymization(sample_str, source_type)
        
        # Try to parse back to dict
        try:
            return json.loads(sample_str)
        except json.JSONDecodeError:
            # Return as raw message
            return {"message": sample_str, "anonymized": True}
    
    def _source_specific_anonymization(self, text: str, source_type: str) -> str:
        """Apply source-specific anonymization rules."""
        if source_type == "windows":
            # Anonymize Windows-specific fields
            text = re.sub(r'"TargetUserName"\s*:\s*"([^"]+)"', 
                         lambda m: f'"TargetUserName":"user{hash(m.group(1)) % 1000}"', 
                         text)
            text = re.sub(r'"SubjectUserName"\s*:\s*"([^"]+)"', 
                         lambda m: f'"SubjectUserName":"user{hash(m.group(1)) % 1000}"', 
                         text)
            text = re.sub(r'"Computer"\s*:\s*"([^"]+)"', 
                         lambda m: f'"Computer":"WK-WIN-{random.randint(1000, 9999):04d}"', 
                         text)
        
        elif source_type == "aws":
            # Anonymize AWS-specific fields
            text = re.sub(r'"userName"\s*:\s*"([^"]+)"', 
                         lambda m: f'"userName":"user{hash(m.group(1)) % 1000}"', 
                         text)
            text = re.sub(r'"principalId"\s*:\s*"([^"]+)"', 
                         lambda m: f'"principalId":"AID{hash(m.group(1)) % 100000000000:012d}"', 
                         text)
        
        elif source_type == "azure":
            # Anonymize Azure-specific fields
            text = re.sub(r'"caller"\s*:\s*"([^"]+)"', 
                         lambda m: f'"caller":"user{hash(m.group(1)) % 1000}@example.com"', 
                         text)
            text = re.sub(r'"subscriptionId"\s*:\s*"([^"]+)"', 
                         lambda m: f'"subscriptionId":"{uuid.uuid4()}"', 
                         text)
        
        return text
    
    def anonymize_samples(self, input_dir: Union[str, Path],
                          output_dir: Union[str, Path],
                          custom_rules: Optional[Dict[str, str]] = None) -> int:
        """
        Anonymize all samples in a directory.
        
        Args:
            input_dir: Input directory with raw samples
            output_dir: Output directory for anonymized samples
            custom_rules: Optional custom replacement rules
            
        Returns:
            Number of files processed
        """
        input_dir = Path(input_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        count = 0
        
        for file_path in input_dir.glob("**/*.json*"):
            try:
                # Determine source type from path
                source_type = self._infer_source_type(file_path)
                
                # Load samples
                if file_path.suffix == '.jsonl':
                    with open(file_path, 'r') as f:
                        samples = [json.loads(line) for line in f if line.strip()]
                else:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        samples = data if isinstance(data, list) else [data]
                
                # Anonymize
                anonymized = [self.anonymize_sample(s, source_type) for s in samples]
                
                # Write output
                rel_path = file_path.relative_to(input_dir)
                output_file = output_dir / rel_path
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                self._write_samples(anonymized, output_file)
                count += 1
                
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
        
        return count
    
    def _infer_source_type(self, filepath: Path) -> str:
        """Infer source type from file path."""
        path_str = str(filepath).lower()
        
        if 'windows' in path_str or 'sysmon' in path_str:
            return 'windows'
        elif 'linux' in path_str or 'auth' in path_str:
            return 'linux'
        elif 'aws' in path_str or 'cloudtrail' in path_str:
            return 'aws'
        elif 'azure' in path_str:
            return 'azure'
        elif 'gcp' in path_str or 'google' in path_str:
            return 'gcp'
        elif 'firewall' in path_str or 'palo' in path_str:
            return 'firewall'
        elif 'proxy' in path_str:
            return 'proxy'
        elif 'dns' in path_str:
            return 'dns'
        elif 'ids' in path_str or 'suricata' in path_str:
            return 'ids'
        else:
            return 'unknown'
    
    def _write_samples(self, samples: List[Dict], filepath: Path) -> None:
        """Write samples to file."""
        filepath = Path(filepath)
        
        if filepath.suffix == '.jsonl':
            with open(filepath, 'w') as f:
                for sample in samples:
                    f.write(json.dumps(sample) + '\n')
        else:
            with open(filepath, 'w') as f:
                json.dump(samples, f, indent=2)
    
    def validate_samples(self, sample_dir: Union[str, Path], 
                         source_type: str) -> Dict[str, Any]:
        """
        Validate sample quality.
        
        Args:
            sample_dir: Directory with samples
            source_type: Expected source type
            
        Returns:
            Validation report
        """
        sample_dir = Path(sample_dir)
        
        report = {
            "total_files": 0,
            "total_samples": 0,
            "valid_samples": 0,
            "invalid_samples": 0,
            "pii_detected": [],
            "field_coverage": {},
            "issues": []
        }
        
        for file_path in sample_dir.glob("**/*.json*"):
            report["total_files"] += 1
            
            try:
                if file_path.suffix == '.jsonl':
                    with open(file_path, 'r') as f:
                        samples = [json.loads(line) for line in f if line.strip()]
                else:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        samples = data if isinstance(data, list) else [data]
                
                for sample in samples:
                    report["total_samples"] += 1
                    
                    # Check for PII
                    pii = self._detect_pii(sample)
                    if pii:
                        report["pii_detected"].extend(pii)
                    else:
                        report["valid_samples"] += 1
                    
                    # Check field coverage
                    self._update_field_coverage(report["field_coverage"], sample)
                    
            except Exception as e:
                report["issues"].append(f"{file_path}: {e}")
                report["invalid_samples"] += 1
        
        report["pii_detected"] = list(set(report["pii_detected"]))
        return report
    
    def _detect_pii(self, sample: Dict) -> List[str]:
        """Detect potential PII in sample."""
        pii = []
        sample_str = json.dumps(sample)
        
        # Check for real IPs (not RFC1918 or documentation)
        ip_pattern = r'\b(?!(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.|::1|2001:db8::))[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
        if re.search(ip_pattern, sample_str):
            pii.append("public_ip")
        
        # Check for real domains (not example.com, internal.local, etc.)
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.(com|net|org|io|co\.\w{2}|\w{2})\b'
        domains = re.findall(domain_pattern, sample_str)
        if any(d not in ['example.com', 'internal.local', 'corp.local', 'test.com'] for d in domains):
            pii.append("domain")
        
        # Check for email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.search(email_pattern, sample_str):
            emails = re.findall(email_pattern, sample_str)
            if any('example.com' not in e and 'internal.local' not in e for e in emails):
                pii.append("email")
        
        # Check for AWS account IDs (12 digits)
        aws_pattern = r'\b\d{12}\b'
        if re.search(aws_pattern, sample_str) and '123456789012' not in sample_str:
            pii.append("aws_account")
        
        return pii
    
    def _update_field_coverage(self, coverage: Dict, sample: Dict, prefix: str = "") -> None:
        """Update field coverage statistics."""
        for key, value in sample.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if full_key not in coverage:
                coverage[full_key] = {"count": 0, "types": set()}
            
            coverage[full_key]["count"] += 1
            coverage[full_key]["types"].add(type(value).__name__)
            
            if isinstance(value, dict):
                self._update_field_coverage(coverage, value, full_key)


def main():
    """CLI for Sample Collector."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Collect and anonymize log samples"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # Collect command
    collect_cmd = subparsers.add_parser("collect", help="Collect samples")
    collect_cmd.add_argument("--input", required=True, help="Input file or directory")
    collect_cmd.add_argument("--source", required=True, help="Source type")
    collect_cmd.add_argument("--output", required=True, help="Output directory")
    collect_cmd.add_argument("--format", help="Format type (auto-detected if not specified)")
    collect_cmd.add_argument("--no-anonymize", action="store_true", help="Skip anonymization")
    collect_cmd.add_argument("--max-samples", type=int, default=1000, help="Max samples per file")
    
    # Anonymize command
    anon_cmd = subparsers.add_parser("anonymize", help="Anonymize existing samples")
    anon_cmd.add_argument("--input", required=True, help="Input directory")
    anon_cmd.add_argument("--output", required=True, help="Output directory")
    
    # Validate command
    validate_cmd = subparsers.add_parser("validate", help="Validate samples")
    validate_cmd.add_argument("--input", required=True, help="Input directory")
    validate_cmd.add_argument("--source", required=True, help="Expected source type")
    
    args = parser.parse_args()
    
    collector = SampleCollector()
    
    if args.command == "collect":
        input_path = Path(args.input)
        
        if input_path.is_dir():
            result = collector.collect_from_directory(
                input_path, args.source, args.output,
                format_type=args.format,
                anonymize=not args.no_anonymize,
                max_samples=args.max_samples
            )
        else:
            result = collector.collect_from_file(
                input_path, args.source, args.output,
                format_type=args.format,
                anonymize=not args.no_anonymize,
                max_samples=args.max_samples
            )
        
        print(json.dumps(result.to_dict(), indent=2))
    
    elif args.command == "anonymize":
        count = collector.anonymize_samples(args.input, args.output)
        print(f"Processed {count} files")
    
    elif args.command == "validate":
        report = collector.validate_samples(args.input, args.source)
        print(json.dumps(report, indent=2, default=str))
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
