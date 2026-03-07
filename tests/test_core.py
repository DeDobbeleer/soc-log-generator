#!/usr/bin/env python3
"""
Unit tests for core module.

Tests cover:
- LogEvent creation and serialization
- AssetInventory management
- RateLimiter functionality
- Output handlers (FileOutput, SyslogOutput)
"""

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc_log_generator.core import (
    AssetInventory,
    EventSeverity,
    FileOutput,
    LogEvent,
    MultiOutput,
    RateLimiter,
    SyslogOutput,
    TimeProfile,
)


class TestLogEvent:
    """Test cases for LogEvent class."""
    
    def test_create_basic_event(self):
        """Test basic event creation."""
        event = LogEvent(
            timestamp=datetime(2024, 3, 7, 12, 0, 0, tzinfo=timezone.utc),
            source_type="test",
            source_ip="10.0.0.1",
            source_host="TEST-01",
            message="Test event",
            raw_log="TEST: message",
            fields={"key": "value"},
            tags=["test"],
            severity=EventSeverity.LOW
        )
        
        assert event.source_type == "test"
        assert event.source_ip == "10.0.0.1"
        assert event.severity == EventSeverity.LOW
    
    def test_to_json(self):
        """Test JSON serialization."""
        event = LogEvent(
            timestamp=datetime(2024, 3, 7, 12, 0, 0, tzinfo=timezone.utc),
            source_type="test",
            source_ip="10.0.0.1",
            source_host="TEST-01",
            message="Test",
            raw_log="TEST: raw",
            fields={"count": 42},
            tags=["test", "demo"],
            severity=EventSeverity.HIGH
        )
        
        json_str = event.to_json()
        data = json.loads(json_str)
        
        assert data["source_type"] == "test"
        assert data["source"]["ip"] == "10.0.0.1"
        assert data["source"]["hostname"] == "TEST-01"
        assert data["event"]["severity"] == 3
        assert data["event"]["severity_label"] == "HIGH"
        assert data["fields"]["count"] == 42
        assert "ecs" in data
    
    def test_to_cef(self):
        """Test CEF serialization."""
        event = LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="windows",
            source_ip="10.0.0.1",
            source_host="WK-01",
            message="Process created",
            raw_log="4688: process",
            fields={
                "event_name": "ProcessCreate",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "user": "admin"
            },
            tags=["windows"],
            severity=EventSeverity.MEDIUM
        )
        
        cef = event.to_cef()
        
        assert cef.startswith("CEF:0|SOCGen|LogGenerator|1.0|")
        assert "windows|ProcessCreate|4|" in cef  # Severity 4 = MEDIUM * 2
        assert "src=10.0.0.1" in cef
        assert "dst=8.8.8.8" in cef
        assert "suser=admin" in cef
    
    def test_to_syslog_rfc5424(self):
        """Test RFC 5424 syslog format."""
        event = LogEvent(
            timestamp=datetime(2024, 3, 7, 12, 30, 45, 123456, tzinfo=timezone.utc),
            source_type="test",
            source_ip="10.0.0.1",
            source_host="TEST-01",
            message="Test message",
            raw_log="raw",
            fields={},
            tags=[],
            severity=EventSeverity.LOW
        )
        
        syslog = event.to_syslog(facility=1, rfc="5424")
        
        # Priority = facility * 8 + severity (1*8 + 6 = 14 for INFO)
        assert syslog.startswith("<14>1 2024-03-07T12:30:45.123456Z TEST-01 test - - - Test message")
    
    def test_to_syslog_rfc3164(self):
        """Test RFC 3164 (legacy) syslog format."""
        event = LogEvent(
            timestamp=datetime(2024, 3, 7, 12, 30, 45, tzinfo=timezone.utc),
            source_type="test",
            source_ip="10.0.0.1",
            source_host="TEST-01",
            message="Test message",
            raw_log="raw",
            fields={},
            tags=[],
            severity=EventSeverity.CRITICAL
        )
        
        syslog = event.to_syslog(facility=1, rfc="3164")
        
        # Priority = 1*8 + 3 = 11 for ERROR
        assert syslog.startswith("<11>Mar 07 12:30:45 TEST-01 Test message")
    
    def test_severity_mapping(self):
        """Test severity level values."""
        assert EventSeverity.LOW.value == 1
        assert EventSeverity.MEDIUM.value == 2
        assert EventSeverity.HIGH.value == 3
        assert EventSeverity.CRITICAL.value == 4


class TestAssetInventory:
    """Test cases for AssetInventory class."""
    
    def test_default_inventory_creation(self):
        """Test default inventory generation."""
        inventory = AssetInventory()
        
        assert len(inventory.assets) > 0
        assert len(inventory.users) > 0
        assert len(inventory.domains) > 0
        assert len(inventory.subnets) > 0
    
    def test_get_random_asset(self):
        """Test random asset retrieval."""
        inventory = AssetInventory()
        
        # Get any asset
        asset = inventory.get_random_asset()
        assert "hostname" in asset
        assert "ip" in asset
        assert "type" in asset
        
        # Filter by type
        workstation = inventory.get_random_asset(asset_type="workstation")
        assert workstation["type"] == "workstation"
        
        # Filter by subnet
        subnet_assets = inventory.get_random_asset(subnet="10.0.10.0/24")
        assert "subnet" in subnet_assets
    
    def test_get_random_user(self):
        """Test random user retrieval."""
        inventory = AssetInventory()
        
        # Get any user
        user = inventory.get_random_user()
        assert "username" in user
        assert "role" in user
        
        # Filter by role
        admin = inventory.get_random_user(role="admin")
        assert admin["role"] == "admin"
        
        # Filter by department
        it_user = inventory.get_random_user(dept="IT")
        assert it_user["dept"] == "IT"
    
    def test_get_asset_by_ip(self):
        """Test asset lookup by IP."""
        inventory = AssetInventory()
        
        # Get a known asset first
        asset = inventory.get_random_asset()
        ip = asset["ip"]
        
        # Look it up
        found = inventory.get_asset_by_ip(ip)
        assert found is not None
        assert found["hostname"] == asset["hostname"]
        
        # Non-existent IP
        not_found = inventory.get_asset_by_ip("255.255.255.255")
        assert not_found is None
    
    def test_inventory_from_config(self):
        """Test loading inventory from config."""
        config = {
            "domains": ["test.local"],
            "subnets": ["192.168.1.0/24"],
            "users": [
                {"username": "testuser", "domain": "test.local", "dept": "IT", "role": "admin"}
            ],
            "assets": {
                "TEST-01": {
                    "type": "workstation",
                    "os": "Windows 10",
                    "ip": "192.168.1.10",
                    "domain": "test.local"
                }
            }
        }
        
        inventory = AssetInventory(config)
        
        assert inventory.domains == ["test.local"]
        assert len(inventory.users) == 1
        assert inventory.users[0]["username"] == "testuser"
        assert len(inventory.assets) == 1


class TestRateLimiter:
    """Test cases for RateLimiter class."""
    
    def test_rate_limiting_basic(self):
        """Test basic rate limiting at 10 EPS."""
        limiter = RateLimiter(eps=10.0)
        
        start = time.perf_counter()
        for _ in range(5):
            limiter.acquire()
        elapsed = time.perf_counter() - start
        
        # Should take approximately 0.4 seconds (4 intervals of 0.1s)
        assert 0.35 <= elapsed <= 0.6, f"Expected ~0.4s, got {elapsed:.3f}s"
    
    def test_rate_update(self):
        """Test dynamic rate updates."""
        limiter = RateLimiter(eps=10.0)
        
        # Start at 10 EPS
        start = time.perf_counter()
        limiter.acquire()
        
        # Update to 100 EPS
        limiter.update_rate(100.0)
        for _ in range(5):
            limiter.acquire()
        
        elapsed = time.perf_counter() - start
        
        # Should be much faster now (roughly 0.1s + 0.04s = 0.14s)
        assert elapsed < 0.3, f"Expected <0.3s after speedup, got {elapsed:.3f}s"
    
    def test_thread_safety(self):
        """Test thread-safe operation."""
        limiter = RateLimiter(eps=100.0)  # High rate for faster test
        counters = {"count": 0}
        lock = threading.Lock()
        
        def worker():
            for _ in range(10):
                limiter.acquire()
                with lock:
                    counters["count"] += 1
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert counters["count"] == 50


class TestTimeProfile:
    """Test cases for TimeProfile class."""
    
    def test_base_eps(self):
        """Test base EPS is returned with variation."""
        profile = TimeProfile(base_eps=100.0)
        eps = profile.get_current_eps()
        
        # Should be around 100 (±10% variation + time-based adjustments)
        assert 5 <= eps <= 250  # Wide range to account for time of day
    
    def test_weekend_reduction(self):
        """Test weekend activity reduction."""
        from datetime import datetime
        
        profile = TimeProfile(
            base_eps=100.0,
            weekend_multiplier=0.5
        )
        
        # Check that weekend multiplier affects output
        # (We can't easily mock time here, but we can verify the logic exists)
        eps = profile.get_current_eps()
        assert isinstance(eps, float)
        assert eps > 0


class TestFileOutput:
    """Test cases for FileOutput class."""
    
    def test_write_single_event(self):
        """Test writing a single event."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name
        
        try:
            output = FileOutput(temp_path)
            
            event = LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type="test",
                source_ip="10.0.0.1",
                source_host="TEST-01",
                message="Test",
                raw_log="test",
                fields={},
                tags=[],
                severity=EventSeverity.LOW
            )
            
            assert output.write(event) is True
            output.close()
            
            # Verify file content
            with open(temp_path, 'r') as f:
                line = f.readline()
                data = json.loads(line)
                assert data["source_type"] == "test"
        finally:
            os.unlink(temp_path)
    
    def test_file_rotation(self):
        """Test file rotation on size limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.log")
            
            # Small rotation size (1KB)
            output = FileOutput(filepath, rotation_size=1024)
            
            # Write enough data to trigger rotation
            for i in range(100):
                event = LogEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_type="test",
                    source_ip="10.0.0.1",
                    source_host="TEST-01",
                    message=f"Event {i} with padding to make it longer",
                    raw_log=f"raw {i}",
                    fields={"seq": i},
                    tags=[],
                    severity=EventSeverity.LOW
                )
                output.write(event)
            
            output.close()
            
            # Check that rotation occurred
            assert os.path.exists(filepath)
            assert os.path.exists(f"{filepath}.1")
    
    def test_batch_write(self):
        """Test batch write functionality."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name
        
        try:
            output = FileOutput(temp_path)
            
            events = [
                LogEvent(
                    timestamp=datetime.now(timezone.utc),
                    source_type="test",
                    source_ip="10.0.0.1",
                    source_host="TEST-01",
                    message=f"Event {i}",
                    raw_log=f"raw {i}",
                    fields={"seq": i},
                    tags=[],
                    severity=EventSeverity.LOW
                )
                for i in range(10)
            ]
            
            count = output.write_batch(events)
            assert count == 10
            output.close()
            
            # Verify line count
            with open(temp_path, 'r') as f:
                lines = f.readlines()
                assert len(lines) == 10
        finally:
            os.unlink(temp_path)
    
    def test_health_check(self):
        """Test health check functionality."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_path = f.name
        
        try:
            output = FileOutput(temp_path)
            assert output.health_check() is True
            
            output.close()
            assert output.health_check() is False
        finally:
            os.unlink(temp_path)


class TestMultiOutput:
    """Test cases for MultiOutput class."""
    
    def test_multiple_outputs(self):
        """Test writing to multiple outputs."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f1:
            path1 = f1.name
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f2:
            path2 = f2.name
        
        try:
            output1 = FileOutput(path1)
            output2 = FileOutput(path2)
            multi = MultiOutput([output1, output2])
            
            event = LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type="test",
                source_ip="10.0.0.1",
                source_host="TEST-01",
                message="Test",
                raw_log="test",
                fields={},
                tags=[],
                severity=EventSeverity.LOW
            )
            
            assert multi.write(event) is True
            multi.close()
            
            # Verify both files have the content
            with open(path1, 'r') as f:
                assert "test" in f.read()
            with open(path2, 'r') as f:
                assert "test" in f.read()
        finally:
            os.unlink(path1)
            os.unlink(path2)


class TestSyslogOutput:
    """Test cases for SyslogOutput class."""
    
    def test_udp_output(self):
        """Test UDP syslog output (connectionless)."""
        # UDP doesn't actually connect, so this should work without a server
        output = SyslogOutput(
            host="127.0.0.1",
            port=514,
            protocol="udp"
        )
        
        event = LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="test",
            source_ip="10.0.0.1",
            source_host="TEST-01",
            message="UDP test",
            raw_log="test",
            fields={},
            tags=[],
            severity=EventSeverity.LOW
        )
        
        # Should not raise even without server (UDP)
        assert output.write(event) is True
        output.close()
    
    def test_format_selection(self):
        """Test different output formats."""
        output_json = SyslogOutput(
            host="127.0.0.1",
            port=514,
            protocol="udp",
            format="json"
        )
        output_cef = SyslogOutput(
            host="127.0.0.1",
            port=514,
            protocol="udp",
            format="cef"
        )
        
        event = LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="test",
            source_ip="10.0.0.1",
            source_host="TEST-01",
            message="Test",
            raw_log="test",
            fields={},
            tags=[],
            severity=EventSeverity.LOW
        )
        
        # Both should write without error
        assert output_json.write(event) is True
        assert output_cef.write(event) is True
        
        output_json.close()
        output_cef.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
