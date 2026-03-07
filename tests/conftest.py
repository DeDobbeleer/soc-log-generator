#!/usr/bin/env python3
"""
Pytest configuration and fixtures.
"""

import pytest
from soc_log_generator.core import AssetInventory


@pytest.fixture
def asset_inventory():
    """Provide a default asset inventory for tests."""
    return AssetInventory()


@pytest.fixture
def sample_event_data():
    """Provide sample event data for tests."""
    return {
        "timestamp": "2024-03-07T12:00:00+00:00",
        "source_type": "test",
        "source_ip": "10.0.0.1",
        "source_host": "TEST-01",
        "message": "Test event",
        "raw_log": "TEST: test message",
        "fields": {"key": "value", "count": 42},
        "tags": ["test", "demo"],
        "severity": "LOW"
    }
