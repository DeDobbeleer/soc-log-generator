"""
SOC Log Generator

A professional, modular log generator for SOC (Security Operations Center)
and MSSP (Managed Security Service Provider) environments.

Features:
- Multi-source log generation (Endpoint, Network, Cloud, Security)
- Realistic temporal patterns and attack scenarios
- AI-powered log learning and parser generation
- SIEM validation and stress testing
- Industry-specific sources (Healthcare, Finance, OT/ICS)

Example:
    >>> from soc_log_generator import AssetInventory, FileOutput
    >>> inventory = AssetInventory()
    >>> output = FileOutput("/var/log/soc/logs.json")
"""

__version__ = "1.0.0-alpha"
__author__ = "SOC Log Generator Team"
__license__ = "MIT"

# Import core components for easy access
from .core import (
    AssetInventory,
    EventSeverity,
    FileOutput,
    LogEvent,
    MultiOutput,
    OutputHandler,
    RateLimiter,
    SyslogOutput,
    TimeProfile,
)

__all__ = [
    "AssetInventory",
    "EventSeverity",
    "FileOutput",
    "LogEvent",
    "MultiOutput",
    "OutputHandler",
    "RateLimiter",
    "SyslogOutput",
    "TimeProfile",
    "__version__",
]
