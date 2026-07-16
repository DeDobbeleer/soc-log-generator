#!/usr/bin/env python3
"""
Validation Package - Reality checking and validation for SOC Log Generator

This package provides comprehensive validation capabilities:

- **SchemaRegistry**: Define and store reference schemas
- **LogValidator**: Validate generated logs against schemas
- **RealityChecker**: Compare generated logs with real-world samples
- **VersionManager**: Manage log format versions
- **SampleCollector**: Collect and anonymize real samples
- **ReportGenerator**: Generate accuracy reports

Example:
    from validation import RealityChecker, VersionManager, ReportGenerator
    
    # Compare with reality
    checker = RealityChecker()
    checker.load_real_samples("samples/real/", "windows")
    checker.load_generated_samples(generated_events, "windows")
    report = checker.compare("windows")
    
    # Manage versions
    vm = VersionManager()
    current = vm.get_current_version("windows")
    
    # Generate report
    generator = ReportGenerator()
    full_report = generator.generate_full_report()

Author: SOC Log Generator Research Team
Version: 1.0.0
"""

from validation.schemas import SchemaRegistry, LogSchema, FieldSchema, FieldType
from validation.reality_checker import RealityChecker, ComparisonReport, FieldStats
from validation.version_manager import VersionManager, VersionInfo, VersionDetectionResult
from validation.sample_collector import SampleCollector, CollectionResult
from validation.report_generator import ReportGenerator, AccuracyMetrics

__all__ = [
    # Schemas
    'SchemaRegistry',
    'LogSchema',
    'FieldSchema',
    'FieldType',
    
    # Reality checking
    'RealityChecker',
    'ComparisonReport',
    'FieldStats',
    
    # Version management
    'VersionManager',
    'VersionInfo',
    'VersionDetectionResult',
    
    # Sample collection
    'SampleCollector',
    'CollectionResult',
    
    # Reporting
    'ReportGenerator',
    'AccuracyMetrics',
]

__version__ = "1.0.0"
