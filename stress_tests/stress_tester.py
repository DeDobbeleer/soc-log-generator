#!/usr/bin/env python3
"""
Stress Tester

Framework for stress testing log generation under various conditions:
- Burst testing: Sudden spikes in load
- Sustained testing: Constant high load over time
- Spike testing: Rapid up/down variations
- Ramp testing: Gradual increase/decrease
"""

import time
import threading
import statistics
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import gc


class TestType(Enum):
    """Types of stress tests."""
    BURST = "burst"
    SUSTAINED = "sustained"
    SPIKE = "spike"
    RAMP = "ramp"
    ENDURANCE = "endurance"


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class SampleMetrics:
    """Metrics at a single point in time."""
    timestamp: float
    target_eps: float
    actual_eps: float
    events_generated: int
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None
    latency_ms: Optional[float] = None
    queue_size: Optional[int] = None
    errors: int = 0


@dataclass
class StressTestReport:
    """Complete stress test report."""
    test_type: TestType
    status: TestStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    total_events: int = 0
    target_eps: float = 0.0
    avg_eps: float = 0.0
    max_eps: float = 0.0
    min_eps: float = 0.0
    eps_variance: float = 0.0
    samples: List[SampleMetrics] = field(default_factory=list)
    error_count: int = 0
    error_rate: float = 0.0
    latency_avg_ms: float = 0.0
    latency_max_ms: float = 0.0
    latency_p99_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_type": self.test_type.value,
            "status": self.status.value,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_events": self.total_events,
            "target_eps": round(self.target_eps, 2),
            "avg_eps": round(self.avg_eps, 2),
            "max_eps": round(self.max_eps, 2),
            "min_eps": round(self.min_eps, 2),
            "eps_variance": round(self.eps_variance, 2),
            "error_count": self.error_count,
            "error_rate": round(self.error_rate, 4),
            "latency_avg_ms": round(self.latency_avg_ms, 2),
            "latency_max_ms": round(self.latency_max_ms, 2),
            "latency_p99_ms": round(self.latency_p99_ms, 2),
        }
    
    def print_summary(self) -> None:
        """Print formatted summary."""
        print("\n" + "=" * 60)
        print(f"STRESS TEST REPORT: {self.test_type.value.upper()}")
        print("=" * 60)
        print(f"Status: {self.status.value}")
        print(f"Duration: {self.duration_seconds:.1f}s")
        print(f"Total Events: {self.total_events:,}")
        print(f"\nEPS Performance:")
        print(f"  Target: {self.target_eps:,.1f}")
        print(f"  Average: {self.avg_eps:,.1f}")
        print(f"  Min/Max: {self.min_eps:,.1f} / {self.max_eps:,.1f}")
        print(f"  Variance: {self.eps_variance:.2f}")
        print(f"  Accuracy: {(self.avg_eps/self.target_eps*100):.1f}%")
        print(f"\nLatency:")
        print(f"  Average: {self.latency_avg_ms:.2f}ms")
        print(f"  P99: {self.latency_p99_ms:.2f}ms")
        print(f"  Max: {self.latency_max_ms:.2f}ms")
        print(f"\nReliability:")
        print(f"  Errors: {self.error_count}")
        print(f"  Error Rate: {self.error_rate*100:.4f}%")
        print("=" * 60)


class StressTester:
    """
    Stress testing framework for log generators.
    
    Usage:
        tester = StressTester(generator)
        report = tester.run_burst_test(target_eps=10000, duration=60)
        report.print_summary()
    """
    
    def __init__(self, generator: Any, output_handler: Optional[Any] = None):
        """
        Initialize stress tester.
        
        Args:
            generator: Log generator instance
            output_handler: Optional output handler for testing
        """
        self.generator = generator
        self.output_handler = output_handler
        self._stop_event = threading.Event()
        self._current_report: Optional[StressTestReport] = None
    
    def run_burst_test(self, target_eps: float, duration: float, 
                       burst_multiplier: float = 3.0) -> StressTestReport:
        """
        Run burst test: sudden spike then return to baseline.
        
        Pattern:
        - Baseline: 20% of target
        - Burst: 300% of target (3x)
        - Recovery: return to baseline
        
        Args:
            target_eps: Target events per second
            duration: Test duration in seconds
            burst_multiplier: How many times target to burst
            
        Returns:
            StressTestReport
        """
        report = StressTestReport(
            test_type=TestType.BURST,
            status=TestStatus.RUNNING,
            target_eps=target_eps
        )
        self._current_report = report
        report.start_time = datetime.now(timezone.utc)
        
        baseline_eps = target_eps * 0.2
        burst_eps = target_eps * burst_multiplier
        
        phase_duration = duration / 3
        
        try:
            # Phase 1: Baseline
            self._run_phase(report, baseline_eps, phase_duration, "baseline")
            
            # Phase 2: Burst
            self._run_phase(report, burst_eps, phase_duration, "burst")
            
            # Phase 3: Recovery
            self._run_phase(report, baseline_eps, phase_duration, "recovery")
            
            report.status = TestStatus.COMPLETED
            
        except Exception as e:
            report.status = TestStatus.FAILED
            print(f"Test failed: {e}")
        
        finally:
            report.end_time = datetime.now(timezone.utc)
            self._finalize_report(report)
        
        return report
    
    def run_sustained_test(self, target_eps: float, duration: float) -> StressTestReport:
        """
        Run sustained test: constant load over extended period.
        
        Args:
            target_eps: Target events per second
            duration: Test duration in seconds
            
        Returns:
            StressTestReport
        """
        report = StressTestReport(
            test_type=TestType.SUSTAINED,
            status=TestStatus.RUNNING,
            target_eps=target_eps
        )
        self._current_report = report
        report.start_time = datetime.now(timezone.utc)
        
        try:
            self._run_phase(report, target_eps, duration, "sustained")
            report.status = TestStatus.COMPLETED
            
        except Exception as e:
            report.status = TestStatus.FAILED
            print(f"Test failed: {e}")
        
        finally:
            report.end_time = datetime.now(timezone.utc)
            self._finalize_report(report)
        
        return report
    
    def run_spike_test(self, target_eps: float, duration: float,
                       spike_count: int = 5) -> StressTestReport:
        """
        Run spike test: multiple rapid up/down variations.
        
        Args:
            target_eps: Target events per second
            duration: Test duration in seconds
            spike_count: Number of spikes
            
        Returns:
            StressTestReport
        """
        report = StressTestReport(
            test_type=TestType.SPIKE,
            status=TestStatus.RUNNING,
            target_eps=target_eps
        )
        self._current_report = report
        report.start_time = datetime.now(timezone.utc)
        
        phase_duration = duration / (spike_count * 2 + 1)
        baseline_eps = target_eps * 0.1
        spike_eps = target_eps * 2
        
        try:
            # Start with baseline
            self._run_phase(report, baseline_eps, phase_duration, "baseline")
            
            # Alternate spikes
            for i in range(spike_count):
                self._run_phase(report, spike_eps, phase_duration, f"spike_{i+1}_up")
                self._run_phase(report, baseline_eps, phase_duration, f"spike_{i+1}_down")
            
            report.status = TestStatus.COMPLETED
            
        except Exception as e:
            report.status = TestStatus.FAILED
            print(f"Test failed: {e}")
        
        finally:
            report.end_time = datetime.now(timezone.utc)
            self._finalize_report(report)
        
        return report
    
    def run_ramp_test(self, start_eps: float, end_eps: float, 
                      duration: float) -> StressTestReport:
        """
        Run ramp test: gradual increase or decrease.
        
        Args:
            start_eps: Starting EPS
            end_eps: Ending EPS
            duration: Test duration in seconds
            
        Returns:
            StressTestReport
        """
        report = StressTestReport(
            test_type=TestType.RAMP,
            status=TestStatus.RUNNING,
            target_eps=(start_eps + end_eps) / 2
        )
        self._current_report = report
        report.start_time = datetime.now(timezone.utc)
        
        sample_interval = 1.0  # 1 second samples
        steps = int(duration / sample_interval)
        eps_step = (end_eps - start_eps) / steps if steps > 0 else 0
        
        try:
            for i in range(steps):
                current_eps = start_eps + (eps_step * i)
                self._run_phase(report, current_eps, sample_interval, f"ramp_{i}")
                
                if self._stop_event.is_set():
                    break
            
            report.status = TestStatus.COMPLETED
            
        except Exception as e:
            report.status = TestStatus.FAILED
            print(f"Test failed: {e}")
        
        finally:
            report.end_time = datetime.now(timezone.utc)
            self._finalize_report(report)
        
        return report
    
    def run_endurance_test(self, target_eps: float, duration: float) -> StressTestReport:
        """
        Run endurance test: long-duration sustained load.
        
        Args:
            target_eps: Target events per second
            duration: Test duration in seconds (typically 3600+ for 1h+)
            
        Returns:
            StressTestReport
        """
        report = StressTestReport(
            test_type=TestType.ENDURANCE,
            status=TestStatus.RUNNING,
            target_eps=target_eps
        )
        self._current_report = report
        report.start_time = datetime.now(timezone.utc)
        
        try:
            # Run with longer sample intervals for endurance
            sample_interval = 10.0  # 10 second samples
            elapsed = 0.0
            
            while elapsed < duration:
                remaining = min(sample_interval, duration - elapsed)
                self._run_phase(report, target_eps, remaining, f"endurance_{elapsed:.0f}s")
                elapsed += remaining
                
                if self._stop_event.is_set():
                    break
            
            report.status = TestStatus.COMPLETED
            
        except Exception as e:
            report.status = TestStatus.FAILED
            print(f"Test failed: {e}")
        
        finally:
            report.end_time = datetime.now(timezone.utc)
            self._finalize_report(report)
        
        return report
    
    def stop(self) -> None:
        """Stop current test."""
        self._stop_event.set()
        if self._current_report:
            self._current_report.status = TestStatus.ABORTED
    
    def _run_phase(self, report: StressTestReport, target_eps: float, 
                   duration: float, phase_name: str) -> None:
        """Run a single phase of the test."""
        interval = 1.0  # Sample every second
        elapsed = 0.0
        
        while elapsed < duration:
            if self._stop_event.is_set():
                break
            
            start_time = time.perf_counter()
            
            # Generate events for this interval
            events_this_interval = int(target_eps * interval)
            actual_events = 0
            errors = 0
            latencies = []
            
            for _ in range(events_this_interval):
                try:
                    gen_start = time.perf_counter()
                    event = self.generator.generate_event()
                    latency = (time.perf_counter() - gen_start) * 1000
                    latencies.append(latency)
                    
                    if self.output_handler:
                        self.output_handler.write(event)
                    
                    actual_events += 1
                    report.total_events += 1
                    
                except Exception:
                    errors += 1
                    report.error_count += 1
            
            # Calculate actual EPS
            actual_duration = time.perf_counter() - start_time
            actual_eps = actual_events / actual_duration if actual_duration > 0 else 0
            
            # Record sample
            sample = SampleMetrics(
                timestamp=time.time(),
                target_eps=target_eps,
                actual_eps=actual_eps,
                events_generated=actual_events,
                errors=errors,
                latency_ms=statistics.mean(latencies) if latencies else None
            )
            report.samples.append(sample)
            
            elapsed += interval
    
    def _finalize_report(self, report: StressTestReport) -> None:
        """Finalize report with calculated metrics."""
        if not report.samples:
            return
        
        # Calculate duration
        if report.start_time and report.end_time:
            report.duration_seconds = (report.end_time - report.start_time).total_seconds()
        
        # EPS statistics
        eps_values = [s.actual_eps for s in report.samples]
        report.avg_eps = statistics.mean(eps_values)
        report.max_eps = max(eps_values)
        report.min_eps = min(eps_values)
        
        if len(eps_values) > 1:
            report.eps_variance = statistics.variance(eps_values)
        
        # Error rate
        total_attempts = sum(s.events_generated + s.errors for s in report.samples)
        if total_attempts > 0:
            report.error_rate = report.error_count / total_attempts
        
        # Latency statistics
        latencies = [s.latency_ms for s in report.samples if s.latency_ms is not None]
        if latencies:
            report.latency_avg_ms = statistics.mean(latencies)
            report.latency_max_ms = max(latencies)
            sorted_latencies = sorted(latencies)
            p99_idx = int(len(sorted_latencies) * 0.99)
            report.latency_p99_ms = sorted_latencies[min(p99_idx, len(sorted_latencies)-1)]


# Convenience function for quick tests
def quick_stress_test(generator: Any, target_eps: float = 1000, 
                      duration: float = 10.0) -> StressTestReport:
    """
    Run a quick sustained stress test.
    
    Args:
        generator: Log generator
        target_eps: Target EPS
        duration: Duration in seconds
        
    Returns:
        StressTestReport
    """
    tester = StressTester(generator)
    report = tester.run_sustained_test(target_eps, duration)
    report.print_summary()
    return report


if __name__ == "__main__":
    # Test with demo generator
    from core import AssetInventory
    from generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
    
    print("Stress Test Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    generator = AWSCloudTrailGenerator({'eps': 100}, inventory)
    
    # Quick test
    quick_stress_test(generator, target_eps=100, duration=5.0)
