#!/usr/bin/env python3
"""
Integration tests for Phase 1 generators.

Tests all endpoint generators working together.
"""

import pytest
import sys
sys.path.insert(0, '.')

from core import AssetInventory
from generators.endpoint.windows import WindowsEventGenerator
from generators.endpoint.linux_generator import LinuxAuthGenerator
from generators.endpoint.linux_sysmon import LinuxSysmonGenerator


class TestPhase1Generators:
    """Test suite for Phase 1 endpoint generators."""
    
    @pytest.fixture
    def inventory(self):
        """Provide asset inventory."""
        return AssetInventory()
    
    def test_windows_generator(self, inventory):
        """Test Windows Event Log generator produces valid events."""
        gen = WindowsEventGenerator({'eps': 100}, inventory)
        
        events = []
        for _ in range(10):
            event = gen.generate_event()
            events.append(event)
            
            # Validate event structure
            assert event.source_type == "windows"
            assert event.source_host.startswith("WK-") or event.source_host.startswith("SRV-")
            assert "EventID" in event.fields
            assert event.fields["EventID"] in gen.SECURITY_EVENTS or event.fields["EventID"] in gen.SYSTEM_EVENTS
            assert event.message
            assert event.raw_log  # Should have XML
        
        # Should have variety of event IDs
        event_ids = [e.fields["EventID"] for e in events]
        assert len(set(event_ids)) > 1, "Should generate different event types"
    
    def test_linux_auth_generator(self, inventory):
        """Test Linux auth generator produces valid events."""
        gen = LinuxAuthGenerator({'eps': 100}, inventory)
        
        events = []
        for _ in range(10):
            event = gen.generate_event()
            events.append(event)
            
            # Validate event structure
            assert event.source_type == "linux"
            assert event.source_ip.startswith("10.0.")
            assert event.message
            assert event.raw_log  # Should have syslog format
        
        # Should have different severity levels
        severities = [e.severity.name for e in events]
        assert len(set(severities)) > 0
    
    def test_linux_sysmon_generator(self, inventory):
        """Test Linux Sysmon generator produces valid events."""
        gen = LinuxSysmonGenerator({'eps': 100}, inventory)
        
        events = []
        for _ in range(10):
            event = gen.generate_event()
            events.append(event)
            
            # Validate event structure
            assert event.source_type == "linux_sysmon"
            assert "EventId" in event.fields
            assert event.fields["EventId"] in [1, 3, 5, 9, 11, 16, 23]
            assert event.message
            assert event.raw_log  # Should have JSON format
    
    def test_event_correlation_windows(self, inventory):
        """Test that Windows events correlate properly."""
        gen = WindowsEventGenerator({'eps': 100}, inventory)
        
        # Generate logon event
        logon_event = None
        for _ in range(50):  # Try multiple times
            event = gen.generate_event()
            if event.fields.get("EventID") == 4624:
                logon_event = event
                break
        
        if logon_event:
            # Should have logon ID
            assert "TargetLogonId" in logon_event.fields
            assert logon_event.fields["TargetLogonId"].startswith("0x")
    
    def test_all_generators_integration(self, inventory):
        """Test all generators working together."""
        generators = [
            WindowsEventGenerator({'eps': 100, 'weight': 1.0}, inventory),
            LinuxAuthGenerator({'eps': 100, 'weight': 0.5}, inventory),
            LinuxSysmonGenerator({'eps': 100, 'weight': 0.3}, inventory),
        ]
        
        all_events = []
        for gen in generators:
            for _ in range(5):
                all_events.append(gen.generate_event())
        
        # Should have events from all generators
        source_types = set(e.source_type for e in all_events)
        assert "windows" in source_types
        assert "linux" in source_types
        assert "linux_sysmon" in source_types
        
        # Total events
        assert len(all_events) == 15


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
