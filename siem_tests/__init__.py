"""
SIEM Integration Tests

Tests for SIEM compatibility and log normalization:
- LogPoint parser compatibility
- Splunk field extraction
- ELK/Elasticsearch mapping
- QRadar DSM compatibility
- Microsoft Sentinel parsers
"""

from .siem_normalizer import SIEMNormalizer, NormalizationReport, SIEMType, NormalizationStatus
from .parsers import LogPointParser, SplunkParser, ELKParser, QRadarParser, BaseParser
from .compatibility import SIEMCompatibilityMatrix, CompatibilityEntry

__all__ = [
    'SIEMNormalizer',
    'NormalizationReport',
    'SIEMType',
    'NormalizationStatus',
    'LogPointParser',
    'SplunkParser',
    'ELKParser',
    'QRadarParser',
    'BaseParser',
    'SIEMCompatibilityMatrix',
    'CompatibilityEntry'
]
