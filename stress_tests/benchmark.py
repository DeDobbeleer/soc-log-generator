#!/usr/bin/env python3
"""
Benchmark Runner

Comprehensive benchmarking for log generators:
- Single vs multi-threaded performance
- Memory usage tracking
- Output handler comparison
- Format conversion overhead
"""

import time
import threading
import statistics
import psutil
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    generator_name: str
    test_name: str
    total_events: int
    duration_seconds: float
    avg_eps: float
    max_eps: float
    min_eps: float
    median_latency_ms: float
    memory_start_mb: float
    memory_end_mb: float
    memory_peak_mb: float
    cpu_avg_percent: float
    threads: int = 1
    batch_size: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "generator": self.generator_name,
            "test": self.test_name,
            "events": self.total_events,
            "duration": round(self.duration_seconds, 2),
            "avg_eps": round(self.avg_eps, 2),
            "max_eps": round(self.max_eps, 2),
            "min_eps": round(self.min_eps, 2),
            "latency_median_ms": round(self.median_latency_ms, 3),
            "memory_delta_mb": round(self.memory_end_mb - self.memory_start_mb, 2),
            "memory_peak_mb": round(self.memory_peak_mb, 2),
            "cpu_avg": round(self.cpu_avg_percent, 1),
            "threads": self.threads,
        }
    
    def print_summary(self):
        """Print formatted summary."""
        print(f"\n📊 Benchmark: {self.generator_name} - {self.test_name}")
        print("-" * 50)
        print(f"Events: {self.total_events:,} in {self.duration_seconds:.2f}s")
        print(f"EPS: avg={self.avg_eps:,.0f}, max={self.max_eps:,.0f}, min={self.min_eps:,.0f}")
        print(f"Latency: median={self.median_latency_ms:.3f}ms")
        print(f"Memory: {self.memory_start_mb:.1f}MB → {self.memory_end_mb:.1f}MB (peak: {self.memory_peak_mb:.1f}MB)")
        print(f"CPU: {self.cpu_avg_percent:.1f}% avg")
        if self.threads > 1:
            print(f"Threads: {self.threads}")


class BenchmarkRunner:
    """
    Comprehensive benchmark runner for log generators.
    
    Usage:
        runner = BenchmarkRunner()
        result = runner.benchmark_generator(generator, event_count=10000)
        result.print_summary()
    """
    
    def __init__(self):
        """Initialize benchmark runner."""
        self.process = psutil.Process(os.getpid())
        self.results: List[BenchmarkResult] = []
    
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        return self.process.memory_info().rss / 1024 / 1024
    
    def get_cpu_percent(self) -> float:
        """Get current CPU percent."""
        return self.process.cpu_percent()
    
    def benchmark_generator(self, generator: Any, event_count: int = 10000,
                           test_name: str = "single_thread") -> BenchmarkResult:
        """
        Benchmark a single generator.
        
        Args:
            generator: Log generator to benchmark
            event_count: Number of events to generate
            test_name: Name of the test
            
        Returns:
            BenchmarkResult
        """
        memory_start = self.get_memory_usage()
        memory_peak = memory_start
        cpu_readings = []
        latencies = []
        
        start_time = time.perf_counter()
        
        for i in range(event_count):
            gen_start = time.perf_counter()
            event = generator.generate_event()
            latency = (time.perf_counter() - gen_start) * 1000
            latencies.append(latency)
            
            # Sample memory and CPU every 100 events
            if i % 100 == 0:
                current_mem = self.get_memory_usage()
                memory_peak = max(memory_peak, current_mem)
                cpu_readings.append(self.get_cpu_percent())
        
        end_time = time.perf_counter()
        duration = end_time - start_time
        
        memory_end = self.get_memory_usage()
        
        # Calculate EPS samples (per second)
        eps_samples = []
        sample_window = 1000  # events per sample window
        window_time = 0
        window_start = start_time
        
        for i in range(event_count):
            if i > 0 and i % sample_window == 0:
                window_end = start_time + (duration * i / event_count)
                window_duration = window_end - window_start
                if window_duration > 0:
                    eps_samples.append(sample_window / window_duration)
                window_start = window_end
        
        result = BenchmarkResult(
            generator_name=generator.__class__.__name__,
            test_name=test_name,
            total_events=event_count,
            duration_seconds=duration,
            avg_eps=event_count / duration if duration > 0 else 0,
            max_eps=max(eps_samples) if eps_samples else 0,
            min_eps=min(eps_samples) if eps_samples else 0,
            median_latency_ms=statistics.median(latencies) if latencies else 0,
            memory_start_mb=memory_start,
            memory_end_mb=memory_end,
            memory_peak_mb=memory_peak,
            cpu_avg_percent=statistics.mean(cpu_readings) if cpu_readings else 0,
        )
        
        self.results.append(result)
        return result
    
    def benchmark_multi_threaded(self, generator: Any, event_count: int = 10000,
                                 num_threads: int = 4) -> BenchmarkResult:
        """
        Benchmark with multiple threads.
        
        Args:
            generator: Log generator
            event_count: Total events to generate
            num_threads: Number of threads
            
        Returns:
            BenchmarkResult
        """
        memory_start = self.get_memory_usage()
        memory_peak = memory_start
        
        events_per_thread = event_count // num_threads
        results = []
        
        def worker(thread_id: int) -> Tuple[int, float, List[float]]:
            """Worker thread."""
            latencies = []
            thread_start = time.perf_counter()
            
            for _ in range(events_per_thread):
                gen_start = time.perf_counter()
                event = generator.generate_event()
                latency = (time.perf_counter() - gen_start) * 1000
                latencies.append(latency)
            
            thread_duration = time.perf_counter() - thread_start
            return events_per_thread, thread_duration, latencies
        
        overall_start = time.perf_counter()
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            
            for future in as_completed(futures):
                count, duration, latencies = future.result()
                results.append((count, duration, latencies))
                
                # Check memory
                current_mem = self.get_memory_usage()
                memory_peak = max(memory_peak, current_mem)
        
        overall_duration = time.perf_counter() - overall_start
        memory_end = self.get_memory_usage()
        
        # Aggregate results
        total_events = sum(r[0] for r in results)
        all_latencies = [lat for _, _, lats in results for lat in lats]
        
        # Calculate per-thread EPS
        eps_values = [r[0] / r[1] if r[1] > 0 else 0 for r in results]
        
        result = BenchmarkResult(
            generator_name=generator.__class__.__name__,
            test_name="multi_thread",
            total_events=total_events,
            duration_seconds=overall_duration,
            avg_eps=total_events / overall_duration if overall_duration > 0 else 0,
            max_eps=sum(eps_values),  # Theoretical max with perfect parallelization
            min_eps=min(eps_values),
            median_latency_ms=statistics.median(all_latencies) if all_latencies else 0,
            memory_start_mb=memory_start,
            memory_end_mb=memory_end,
            memory_peak_mb=memory_peak,
            cpu_avg_percent=0,  # Hard to measure with threads
            threads=num_threads,
        )
        
        self.results.append(result)
        return result
    
    def benchmark_all_generators(self, inventory: Any, 
                                  event_count: int = 5000) -> List[BenchmarkResult]:
        """
        Benchmark all available generators.
        
        Args:
            inventory: AssetInventory instance
            event_count: Events per generator
            
        Returns:
            List of BenchmarkResults
        """
        from generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
        from generators.cloud.azure_activity import AzureActivityGenerator
        from generators.cloud.o365 import Office365Generator
        from generators.cloud.gcp_audit import GCPAuditGenerator
        from generators.endpoint.windows import WindowsEventGenerator
        from generators.endpoint.linux_generator import LinuxAuthGenerator
        from generators.network.firewall import FirewallGenerator
        
        generators = [
            ("Windows", WindowsEventGenerator),
            ("Linux", LinuxAuthGenerator),
            ("Firewall", FirewallGenerator),
            ("AWS CloudTrail", AWSCloudTrailGenerator),
            ("Azure Activity", AzureActivityGenerator),
            ("Office 365", Office365Generator),
            ("GCP Audit", GCPAuditGenerator),
        ]
        
        print("\n🏆 BENCHMARKING ALL GENERATORS")
        print("=" * 60)
        
        results = []
        for name, gen_class in generators:
            print(f"\n📍 Testing {name}...")
            try:
                generator = gen_class({'eps': 100}, inventory)
                result = self.benchmark_generator(generator, event_count, f"{name}_single")
                result.print_summary()
                results.append(result)
            except Exception as e:
                print(f"  ❌ Error: {e}")
        
        return results
    
    def print_comparison(self, results: List[BenchmarkResult] = None):
        """Print comparison table of results."""
        if results is None:
            results = self.results
        
        if not results:
            print("No results to display")
            return
        
        print("\n" + "=" * 80)
        print("BENCHMARK COMPARISON")
        print("=" * 80)
        print(f"{'Generator':<25} {'Events':<10} {'Avg EPS':<12} {'Latency':<12} {'Memory':<12}")
        print("-" * 80)
        
        for r in sorted(results, key=lambda x: x.avg_eps, reverse=True):
            print(f"{r.generator_name:<25} {r.total_events:<10,} {r.avg_eps:<12,.0f} "
                  f"{r.median_latency_ms:<12.3f} {r.memory_peak_mb:<12.1f}")
        
        print("=" * 80)


# Quick benchmark function
def quick_benchmark(generator: Any, event_count: int = 10000) -> BenchmarkResult:
    """
    Quick benchmark a generator.
    
    Args:
        generator: Log generator
        event_count: Number of events
        
    Returns:
        BenchmarkResult
    """
    runner = BenchmarkRunner()
    result = runner.benchmark_generator(generator, event_count)
    result.print_summary()
    return result


if __name__ == "__main__":
    from core import AssetInventory
    from generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
    
    print("Benchmark Demo")
    print("=" * 60)
    
    inventory = AssetInventory()
    generator = AWSCloudTrailGenerator({'eps': 100}, inventory)
    
    # Quick benchmark
    quick_benchmark(generator, event_count=5000)
