#!/usr/bin/env python3
"""
Reality Checker - Compare generated logs against real-world samples

This module provides comprehensive comparison between generated logs and
real-world samples to measure accuracy and identify gaps.

Usage:
    from validation.reality_checker import RealityChecker
    
    checker = RealityChecker()
    checker.load_real_samples("samples/windows_real.json", "windows")
    checker.load_generated_samples(generated_events, "windows")
    
    report = checker.compare("windows")
    print(report.to_dict())

Author: SOC Log Generator Research Team
Version: 1.0.0
"""

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import math


@dataclass
class FieldStats:
    """Statistics for a single field."""
    name: str
    present_count: int = 0
    total_count: int = 0
    value_types: Counter = field(default_factory=Counter)
    value_patterns: Counter = field(default_factory=Counter)
    unique_values: Set = field(default_factory=set)
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    numeric_min: Optional[float] = None
    numeric_max: Optional[float] = None
    
    @property
    def coverage(self) -> float:
        """Percentage of events where field is present."""
        if self.total_count == 0:
            return 0.0
        return (self.present_count / self.total_count) * 100
    
    @property
    def cardinality(self) -> int:
        """Number of unique values."""
        return len(self.unique_values)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "coverage": self.coverage,
            "present_count": self.present_count,
            "total_count": self.total_count,
            "cardinality": self.cardinality,
            "value_types": dict(self.value_types),
            "min_length": self.min_length,
            "max_length": self.max_length,
            "numeric_range": {
                "min": self.numeric_min,
                "max": self.numeric_max
            } if self.numeric_min is not None else None
        }


@dataclass
class ComparisonReport:
    """Complete comparison report between real and generated samples."""
    
    source_type: str
    real_sample_count: int
    generated_sample_count: int
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Field analysis
    real_fields: Dict[str, FieldStats] = field(default_factory=dict)
    generated_fields: Dict[str, FieldStats] = field(default_factory=dict)
    
    # Similarity metrics
    field_coverage: float = 0.0  # % of real fields present in generated
    field_extra: float = 0.0  # % of generated fields not in real
    pattern_accuracy: float = 0.0  # % of patterns matching
    type_accuracy: float = 0.0  # % of type matches
    distribution_similarity: float = 0.0  # KL divergence based
    
    # Detailed findings
    missing_fields: List[str] = field(default_factory=list)
    extra_fields: List[str] = field(default_factory=list)
    mismatched_patterns: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "source_type": self.source_type,
            "timestamp": self.timestamp.isoformat(),
            "sample_counts": {
                "real": self.real_sample_count,
                "generated": self.generated_sample_count
            },
            "metrics": {
                "field_coverage": round(self.field_coverage, 2),
                "field_extra": round(self.field_extra, 2),
                "pattern_accuracy": round(self.pattern_accuracy, 2),
                "type_accuracy": round(self.type_accuracy, 2),
                "distribution_similarity": round(self.distribution_similarity, 2),
                "overall_score": round(self.overall_score, 2)
            },
            "field_analysis": {
                "real": {k: v.to_dict() for k, v in self.real_fields.items()},
                "generated": {k: v.to_dict() for k, v in self.generated_fields.items()}
            },
            "findings": {
                "missing_fields": self.missing_fields,
                "extra_fields": self.extra_fields,
                "mismatched_patterns": self.mismatched_patterns
            },
            "recommendations": self.recommendations
        }
    
    @property
    def overall_score(self) -> float:
        """Calculate overall accuracy score (0-100)."""
        weights = {
            "field_coverage": 0.30,
            "pattern_accuracy": 0.25,
            "type_accuracy": 0.20,
            "distribution_similarity": 0.25
        }
        
        score = (
            self.field_coverage * weights["field_coverage"] +
            self.pattern_accuracy * weights["pattern_accuracy"] +
            self.type_accuracy * weights["type_accuracy"] +
            self.distribution_similarity * weights["distribution_similarity"]
        )
        return min(100.0, max(0.0, score))
    
    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            f"# Reality Check Report: {self.source_type}",
            f"**Generated**: {self.timestamp.isoformat()}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Real Samples | {self.real_sample_count} |",
            f"| Generated Samples | {self.generated_sample_count} |",
            f"| **Overall Score** | **{self.overall_score:.1f}%** |",
            f"| Field Coverage | {self.field_coverage:.1f}% |",
            f"| Pattern Accuracy | {self.pattern_accuracy:.1f}% |",
            f"| Type Accuracy | {self.type_accuracy:.1f}% |",
            f"| Distribution Similarity | {self.distribution_similarity:.1f}% |",
            "",
            "## Field Analysis",
            "",
            "### Missing Fields (in real, not in generated)",
            ""
        ]
        
        if self.missing_fields:
            for field in self.missing_fields[:10]:
                lines.append(f"- `{field}`")
            if len(self.missing_fields) > 10:
                lines.append(f"- ... and {len(self.missing_fields) - 10} more")
        else:
            lines.append("None - all fields covered!")
        
        lines.extend([
            "",
            "### Extra Fields (in generated, not in real)",
            ""
        ])
        
        if self.extra_fields:
            for field in self.extra_fields[:10]:
                lines.append(f"- `{field}`")
            if len(self.extra_fields) > 10:
                lines.append(f"- ... and {len(self.extra_fields) - 10} more")
        else:
            lines.append("None")
        
        lines.extend([
            "",
            "## Recommendations",
            ""
        ])
        
        for rec in self.recommendations:
            lines.append(f"- {rec}")
        
        return "\n".join(lines)


class RealityChecker:
    """
    Compare generated logs against real-world samples.
    
    This class provides comprehensive comparison capabilities to ensure
    generated logs match real-world formats as closely as possible.
    
    Example:
        checker = RealityChecker()
        
        # Load samples
        checker.load_real_samples("path/to/real.json", "windows")
        checker.load_generated_samples(generated_events, "windows")
        
        # Run comparison
        report = checker.compare("windows")
        
        # Export results
        print(report.to_markdown())
    """
    
    def __init__(self):
        """Initialize RealityChecker."""
        self.real_samples: Dict[str, List[Dict]] = {}
        self.generated_samples: Dict[str, List[Dict]] = {}
        self._compiled_patterns: Dict[str, re.Pattern] = {}
    
    def load_real_samples(self, filepath: Union[str, Path], source_type: str) -> int:
        """
        Load real log samples from file.
        
        Supports JSON, JSONL, and directory of files.
        
        Args:
            filepath: Path to sample file or directory
            source_type: Type of log source (e.g., 'windows', 'aws')
            
        Returns:
            Number of samples loaded
        """
        filepath = Path(filepath)
        samples = []
        
        if filepath.is_dir():
            # Load all JSON files in directory
            for file in filepath.glob("**/*.json"):
                samples.extend(self._load_json_file(file))
            for file in filepath.glob("**/*.jsonl"):
                samples.extend(self._load_jsonl_file(file))
        elif filepath.suffix == '.jsonl':
            samples = self._load_jsonl_file(filepath)
        else:
            samples = self._load_json_file(filepath)
        
        self.real_samples[source_type] = samples
        return len(samples)
    
    def load_generated_samples(self, events: List[Any], source_type: str) -> int:
        """
        Load generated events for comparison.
        
        Args:
            events: List of LogEvent objects or dictionaries
            source_type: Type of log source
            
        Returns:
            Number of samples loaded
        """
        samples = []
        for event in events:
            if hasattr(event, 'to_dict'):
                samples.append(event.to_dict())
            elif hasattr(event, '__dict__'):
                samples.append(event.__dict__)
            elif isinstance(event, dict):
                samples.append(event)
            else:
                raise ValueError(f"Cannot convert event to dict: {type(event)}")
        
        self.generated_samples[source_type] = samples
        return len(samples)
    
    def _load_json_file(self, filepath: Path) -> List[Dict]:
        """Load samples from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                return [data]
            else:
                return []
    
    def _load_jsonl_file(self, filepath: Path) -> List[Dict]:
        """Load samples from JSONL file."""
        samples = []
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        samples.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return samples
    
    def compare(self, source_type: str) -> ComparisonReport:
        """
        Run comprehensive comparison for a source type.
        
        Args:
            source_type: Type of log source to compare
            
        Returns:
            ComparisonReport with detailed findings
        """
        if source_type not in self.real_samples:
            raise ValueError(f"No real samples loaded for {source_type}")
        if source_type not in self.generated_samples:
            raise ValueError(f"No generated samples loaded for {source_type}")
        
        real = self.real_samples[source_type]
        generated = self.generated_samples[source_type]
        
        report = ComparisonReport(
            source_type=source_type,
            real_sample_count=len(real),
            generated_sample_count=len(generated)
        )
        
        # Analyze fields in both datasets
        report.real_fields = self._analyze_fields(real)
        report.generated_fields = self._analyze_fields(generated)
        
        # Calculate metrics
        report.field_coverage = self._calculate_field_coverage(
            report.real_fields, report.generated_fields
        )
        report.field_extra = self._calculate_field_extra(
            report.real_fields, report.generated_fields
        )
        report.pattern_accuracy = self._calculate_pattern_accuracy(
            real, generated, report.real_fields
        )
        report.type_accuracy = self._calculate_type_accuracy(
            report.real_fields, report.generated_fields
        )
        report.distribution_similarity = self._calculate_distribution_similarity(
            real, generated, report.real_fields
        )
        
        # Identify specific gaps
        report.missing_fields = self._find_missing_fields(
            report.real_fields, report.generated_fields
        )
        report.extra_fields = self._find_extra_fields(
            report.real_fields, report.generated_fields
        )
        report.mismatched_patterns = self._find_mismatched_patterns(
            real, generated, report.real_fields
        )
        
        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)
        
        return report
    
    def _analyze_fields(self, samples: List[Dict]) -> Dict[str, FieldStats]:
        """Analyze field statistics from samples."""
        stats: Dict[str, FieldStats] = {}
        
        for sample in samples:
            self._analyze_sample_fields(sample, stats, "")
        
        return stats
    
    def _analyze_sample_fields(self, sample: Any, stats: Dict[str, FieldStats], 
                                prefix: str, count: int = 1) -> None:
        """Recursively analyze fields in a sample."""
        if not isinstance(sample, dict):
            return
        
        for key, value in sample.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if full_key not in stats:
                stats[full_key] = FieldStats(name=full_key)
            
            stat = stats[full_key]
            stat.total_count = count
            
            if value is not None:
                stat.present_count += 1
                
                # Track value type
                value_type = type(value).__name__
                stat.value_types[value_type] += 1
                
                # Track patterns for strings
                if isinstance(value, str):
                    pattern = self._get_pattern(value)
                    stat.value_patterns[pattern] += 1
                    stat.unique_values.add(value[:100])  # Limit size
                    
                    length = len(value)
                    if stat.min_length is None or length < stat.min_length:
                        stat.min_length = length
                    if stat.max_length is None or length > stat.max_length:
                        stat.max_length = length
                
                # Track numeric ranges
                elif isinstance(value, (int, float)):
                    stat.unique_values.add(str(value))
                    if stat.numeric_min is None or value < stat.numeric_min:
                        stat.numeric_min = value
                    if stat.numeric_max is None or value > stat.numeric_max:
                        stat.numeric_max = value
                
                # Recurse into nested objects
                elif isinstance(value, dict):
                    self._analyze_sample_fields(value, stats, full_key, count)
                
                # Analyze arrays of objects
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    for item in value:
                        self._analyze_sample_fields(item, stats, full_key, count)
    
    def _get_pattern(self, value: str) -> str:
        """Identify pattern type for a string value."""
        # IP address
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
            return "IP_ADDRESS"
        
        # UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return "UUID"
        
        # Timestamp ISO
        if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', value):
            return "TIMESTAMP_ISO"
        
        # Email
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
            return "EMAIL"
        
        # Hex
        if re.match(r'^0x[0-9a-f]+$', value, re.I):
            return "HEX"
        
        # SID (Windows)
        if re.match(r'^S-1-\d+-\d+', value):
            return "WINDOWS_SID"
        
        # ARN (AWS)
        if re.match(r'^arn:', value):
            return "AWS_ARN"
        
        # Path
        if '/' in value or '\\' in value:
            return "FILE_PATH"
        
        # Domain
        if '.' in value and not ' ' in value:
            return "DOMAIN_OR_HOST"
        
        return "STRING"
    
    def _calculate_field_coverage(self, real_fields: Dict[str, FieldStats],
                                   gen_fields: Dict[str, FieldStats]) -> float:
        """Calculate percentage of real fields present in generated."""
        if not real_fields:
            return 0.0
        
        real_names = set(real_fields.keys())
        gen_names = set(gen_fields.keys())
        
        covered = len(real_names & gen_names)
        return (covered / len(real_names)) * 100
    
    def _calculate_field_extra(self, real_fields: Dict[str, FieldStats],
                               gen_fields: Dict[str, FieldStats]) -> float:
        """Calculate percentage of generated fields not in real."""
        if not gen_fields:
            return 0.0
        
        real_names = set(real_fields.keys())
        gen_names = set(gen_fields.keys())
        
        extra = len(gen_names - real_names)
        return (extra / len(gen_names)) * 100
    
    def _calculate_pattern_accuracy(self, real_samples: List[Dict],
                                    gen_samples: List[Dict],
                                    real_fields: Dict[str, FieldStats]) -> float:
        """Calculate pattern matching accuracy."""
        scores = []
        
        for field_name, real_stat in real_fields.items():
            if real_stat.present_count == 0:
                continue
            
            # Get dominant pattern from real samples
            if real_stat.value_patterns:
                expected_pattern = real_stat.value_patterns.most_common(1)[0][0]
                
                # Check generated samples for this field
                match_count = 0
                total_count = 0
                
                for sample in gen_samples:
                    value = self._get_nested_value(sample, field_name)
                    if value is not None and isinstance(value, str):
                        total_count += 1
                        actual_pattern = self._get_pattern(value)
                        if actual_pattern == expected_pattern:
                            match_count += 1
                
                if total_count > 0:
                    scores.append((match_count / total_count) * 100)
        
        return sum(scores) / len(scores) if scores else 0.0
    
    def _calculate_type_accuracy(self, real_fields: Dict[str, FieldStats],
                                  gen_fields: Dict[str, FieldStats]) -> float:
        """Calculate type matching accuracy."""
        scores = []
        
        for field_name, real_stat in real_fields.items():
            if field_name not in gen_fields:
                continue
            
            gen_stat = gen_fields[field_name]
            
            # Get dominant type from real samples
            if real_stat.value_types:
                expected_type = real_stat.value_types.most_common(1)[0][0]
                
                if gen_stat.value_types:
                    actual_type = gen_stat.value_types.most_common(1)[0][0]
                    scores.append(100.0 if actual_type == expected_type else 0.0)
        
        return sum(scores) / len(scores) if scores else 0.0
    
    def _calculate_distribution_similarity(self, real_samples: List[Dict],
                                           gen_samples: List[Dict],
                                           real_fields: Dict[str, FieldStats]) -> float:
        """Calculate distribution similarity using simplified KL divergence."""
        # This is a simplified version - full implementation would use proper KL divergence
        similarities = []
        
        for field_name, real_stat in real_fields.items():
            if real_stat.cardinality == 0:
                continue
            
            # Compare cardinality ratios
            if field_name in self.generated_samples:
                gen_cardinality = len(set(
                    str(self._get_nested_value(s, field_name)) 
                    for s in gen_samples
                    if self._get_nested_value(s, field_name) is not None
                ))
                
                real_cardinality = real_stat.cardinality
                ratio = min(gen_cardinality, real_cardinality) / max(gen_cardinality, real_cardinality)
                similarities.append(ratio * 100)
        
        return sum(similarities) / len(similarities) if similarities else 0.0
    
    def _get_nested_value(self, sample: Dict, field_path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        parts = field_path.split('.')
        value = sample
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        
        return value
    
    def _find_missing_fields(self, real_fields: Dict[str, FieldStats],
                             gen_fields: Dict[str, FieldStats]) -> List[str]:
        """Find fields present in real but not in generated."""
        real_names = set(real_fields.keys())
        gen_names = set(gen_fields.keys())
        return sorted(real_names - gen_names)
    
    def _find_extra_fields(self, real_fields: Dict[str, FieldStats],
                           gen_fields: Dict[str, FieldStats]) -> List[str]:
        """Find fields present in generated but not in real."""
        real_names = set(real_fields.keys())
        gen_names = set(gen_fields.keys())
        return sorted(gen_names - real_names)
    
    def _find_mismatched_patterns(self, real_samples: List[Dict],
                                  gen_samples: List[Dict],
                                  real_fields: Dict[str, FieldStats]) -> List[Dict]:
        """Find fields with pattern mismatches."""
        mismatches = []
        
        for field_name, real_stat in real_fields.items():
            if not real_stat.value_patterns:
                continue
            
            expected_pattern = real_stat.value_patterns.most_common(1)[0][0]
            
            # Sample some generated values
            actual_patterns = Counter()
            for sample in gen_samples[:100]:  # Sample first 100
                value = self._get_nested_value(sample, field_name)
                if value is not None and isinstance(value, str):
                    actual_patterns[self._get_pattern(value)] += 1
            
            if actual_patterns and actual_patterns.most_common(1)[0][0] != expected_pattern:
                mismatches.append({
                    "field": field_name,
                    "expected_pattern": expected_pattern,
                    "actual_pattern": actual_patterns.most_common(1)[0][0]
                })
        
        return mismatches
    
    def _generate_recommendations(self, report: ComparisonReport) -> List[str]:
        """Generate improvement recommendations based on findings."""
        recommendations = []
        
        # Coverage recommendations
        if report.field_coverage < 90:
            recommendations.append(
                f"Add missing fields to improve coverage from {report.field_coverage:.1f}% to 90%+"
            )
            if report.missing_fields:
                recommendations.append(
                    f"Priority fields to add: {', '.join(report.missing_fields[:5])}"
                )
        
        # Pattern recommendations
        if report.pattern_accuracy < 95:
            recommendations.append(
                f"Review field patterns - accuracy is {report.pattern_accuracy:.1f}% (target: 95%)"
            )
        
        # Type recommendations
        if report.type_accuracy < 90:
            recommendations.append(
                f"Fix field type mismatches - accuracy is {report.type_accuracy:.1f}%"
            )
        
        # Extra fields
        if report.extra_fields:
            recommendations.append(
                f"Review {len(report.extra_fields)} extra fields that may not be needed"
            )
        
        if not recommendations:
            recommendations.append("No critical issues found - maintain current accuracy")
        
        return recommendations


def main():
    """CLI for Reality Checker."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Compare generated logs against real samples"
    )
    parser.add_argument(
        "--real",
        required=True,
        help="Path to real samples (file or directory)"
    )
    parser.add_argument(
        "--generated",
        required=True,
        help="Path to generated samples (file or directory)"
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Source type (e.g., windows, aws, linux)"
    )
    parser.add_argument(
        "--output",
        help="Output file for report (JSON or MD)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format"
    )
    
    args = parser.parse_args()
    
    # Run comparison
    checker = RealityChecker()
    
    print(f"Loading real samples from {args.real}...")
    real_count = checker.load_real_samples(args.real, args.source)
    print(f"  Loaded {real_count} samples")
    
    print(f"Loading generated samples from {args.generated}...")
    gen_count = checker.load_real_samples(args.generated, args.source)
    print(f"  Loaded {gen_count} samples")
    
    print("Running comparison...")
    report = checker.compare(args.source)
    
    # Output results
    if args.output:
        if args.format == "json":
            with open(args.output, 'w') as f:
                json.dump(report.to_dict(), f, indent=2)
        else:
            with open(args.output, 'w') as f:
                f.write(report.to_markdown())
        print(f"Report saved to {args.output}")
    else:
        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.to_markdown())
    
    # Summary
    print(f"\n{'='*50}")
    print(f"Overall Accuracy Score: {report.overall_score:.1f}%")
    print(f"Status: {'✅ PASS' if report.overall_score >= 80 else '⚠️ NEEDS IMPROVEMENT'}")


if __name__ == "__main__":
    main()
