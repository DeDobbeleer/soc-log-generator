#!/usr/bin/env python3
"""
Complete Test Suite

Comprehensive testing for soc-log-generator:
1. Validation Tests - Ensure logs match schemas
2. SIEM Normalization Tests - Verify SIEM compatibility
3. Stress Tests - Performance under load
4. Benchmark Tests - EPS and latency metrics
"""

import sys
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

# Import core components
from core import AssetInventory
from validation import LogValidator, SchemaRegistry
from siem_tests import SIEMNormalizer, SIEMType
from stress_tests import StressTester
from stress_tests.benchmark import BenchmarkRunner, quick_benchmark

# Import all generators
from generators.endpoint.windows import WindowsEventGenerator
from generators.endpoint.linux_generator import LinuxAuthGenerator
from generators.network.firewall import FirewallGenerator
from generators.network.proxy import ProxyGenerator
from generators.network.dns import DNSGenerator
from generators.network.ids import IDSensorGenerator
from generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
from generators.cloud.aws_vpcflow import AWSVPCFlowGenerator
from generators.cloud.azure_activity import AzureActivityGenerator
from generators.cloud.azure_signin import AzureSignInGenerator
from generators.cloud.o365 import Office365Generator
from generators.cloud.gcp_audit import GCPAuditGenerator


class TestSuite:
    """
    Complete test suite for log generators.
    
    Usage:
        suite = TestSuite()
        results = suite.run_all_tests()
        suite.print_report(results)
    """
    
    def __init__(self):
        """Initialize test suite."""
        self.inventory = AssetInventory()
        self.validator = LogValidator()
        self.generators = self._get_all_generators()
        self.results: Dict[str, Any] = {}
    
    def _get_all_generators(self) -> List[tuple]:
        """Get all generator classes with names."""
        return [
            ("Windows Event", WindowsEventGenerator),
            ("Linux Auth", LinuxAuthGenerator),
            ("Firewall", FirewallGenerator),
            ("Proxy", ProxyGenerator),
            ("DNS", DNSGenerator),
            ("IDS/IPS", IDSensorGenerator),
            ("AWS CloudTrail", AWSCloudTrailGenerator),
            ("AWS VPC Flow", AWSVPCFlowGenerator),
            ("Azure Activity", AzureActivityGenerator),
            ("Azure Sign-in", AzureSignInGenerator),
            ("Office 365", Office365Generator),
            ("GCP Audit", GCPAuditGenerator),
        ]
    
    def run_validation_tests(self, sample_size: int = 100) -> Dict[str, Any]:
        """
        Run validation tests on all generators.
        
        Returns:
            Test results dictionary
        """
        print("\n" + "=" * 70)
        print("🔍 PHASE 1: VALIDATION TESTS")
        print("=" * 70)
        
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_type": "validation",
            "generators_tested": 0,
            "generators_passed": 0,
            "details": []
        }
        
        for name, gen_class in self.generators:
            try:
                generator = gen_class({'eps': 100}, self.inventory)
                
                # Generate and validate sample
                events = [generator.generate_event() for _ in range(sample_size)]
                batch_report = self.validator.validate_batch(events)
                stats = batch_report.to_dict()
                
                passed = stats['validity_rate'] >= 80  # 80% threshold
                
                result = {
                    "generator": name,
                    "source_type": events[0].source_type if events else "unknown",
                    "validity_rate": stats['validity_rate'],
                    "field_coverage": stats.get('field_coverage', {}),
                    "passed": passed,
                    "errors": list(stats.get('common_errors', {}).keys())[:3]
                }
                
                results["details"].append(result)
                results["generators_tested"] += 1
                if passed:
                    results["generators_passed"] += 1
                
                status = "✅" if passed else "❌"
                print(f"{status} {name:<25} Validity: {stats['validity_rate']:.1f}%")
                
            except Exception as e:
                print(f"❌ {name:<25} ERROR: {str(e)[:40]}")
                results["details"].append({
                    "generator": name,
                    "passed": False,
                    "error": str(e)
                })
        
        results["pass_rate"] = (results["generators_passed"] / results["generators_tested"] * 100) if results["generators_tested"] > 0 else 0
        
        self.results["validation"] = results
        return results
    
    def run_siem_tests(self, sample_size: int = 50) -> Dict[str, Any]:
        """
        Run SIEM normalization tests.
        
        Returns:
            Test results dictionary
        """
        print("\n" + "=" * 70)
        print("🔍 PHASE 2: SIEM NORMALIZATION TESTS")
        print("=" * 70)
        
        siems = [SIEMType.LOGPOINT, SIEMType.SPLUNK, SIEMType.ELASTIC, SIEMType.QRADAR]
        
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_type": "siem_normalization",
            "siems_tested": len(siems),
            "generators_tested": 0,
            "details": []
        }
        
        # Test with AWS CloudTrail (complex JSON)
        generator = AWSCloudTrailGenerator({'eps': 100}, self.inventory)
        
        for siem_type in siems:
            print(f"\n📍 Testing {siem_type.value.upper()}:")
            normalizer = SIEMNormalizer(siem_type)
            
            siem_results = {
                "siem": siem_type.value,
                "samples": 0,
                "avg_extraction_rate": 0,
                "format_outputs": {}
            }
            
            extraction_rates = []
            
            for _ in range(sample_size):
                event = generator.generate_event()
                report = normalizer.normalize(event)
                extraction_rates.append(report.extraction_rate)
                
                # Test format conversion on first sample
                if siem_results["samples"] == 0:
                    try:
                        cef = normalizer.to_cef(event)
                        siem_results["format_outputs"]["cef_preview"] = cef[:100] + "..."
                    except:
                        pass
                
                siem_results["samples"] += 1
            
            siem_results["avg_extraction_rate"] = sum(extraction_rates) / len(extraction_rates)
            
            print(f"  ✅ Avg Extraction Rate: {siem_results['avg_extraction_rate']:.1%}")
            if "cef_preview" in siem_results["format_outputs"]:
                print(f"  📝 CEF: {siem_results['format_outputs']['cef_preview']}")
            
            results["details"].append(siem_results)
        
        results["generators_tested"] = 1
        self.results["siem"] = results
        return results
    
    def run_stress_tests(self, duration: float = 10.0) -> Dict[str, Any]:
        """
        Run stress tests.
        
        Returns:
            Test results dictionary
        """
        print("\n" + "=" * 70)
        print("🔍 PHASE 3: STRESS TESTS")
        print("=" * 70)
        
        generator = AWSCloudTrailGenerator({'eps': 1000}, self.inventory)
        tester = StressTester(generator)
        
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_type": "stress",
            "tests": []
        }
        
        # Test 1: Sustained load
        print("\n📍 Test 1: Sustained Load (100 EPS, 5s)")
        report1 = tester.run_sustained_test(target_eps=100, duration=min(duration/2, 5.0))
        results["tests"].append({
            "name": "sustained_100eps",
            "avg_eps": report1.avg_eps,
            "accuracy": report1.avg_eps / 100 * 100,
            "latency_avg_ms": report1.latency_avg_ms,
            "passed": report1.avg_eps >= 90  # Within 10% of target
        })
        print(f"  ✅ Avg EPS: {report1.avg_eps:.1f} (Accuracy: {report1.avg_eps/100*100:.1f}%)")
        
        # Test 2: Burst
        print("\n📍 Test 2: Burst Test (baseline→300→baseline)")
        report2 = tester.run_burst_test(target_eps=100, duration=min(duration, 6.0))
        results["tests"].append({
            "name": "burst",
            "max_eps": report2.max_eps,
            "min_eps": report2.min_eps,
            "variance": report2.eps_variance,
            "passed": report2.max_eps >= 250  # Should reach ~300
        })
        print(f"  ✅ Max EPS: {report2.max_eps:.1f}, Min: {report2.min_eps:.1f}")
        
        self.results["stress"] = results
        return results
    
    def run_benchmarks(self, event_count: int = 5000) -> Dict[str, Any]:
        """
        Run benchmark tests.
        
        Returns:
            Test results dictionary
        """
        print("\n" + "=" * 70)
        print("🔍 PHASE 4: BENCHMARKS")
        print("=" * 70)
        
        runner = BenchmarkRunner()
        
        # Benchmark key generators
        generators_to_test = [
            ("Windows", WindowsEventGenerator),
            ("AWS CloudTrail", AWSCloudTrailGenerator),
            ("Azure Activity", AzureActivityGenerator),
        ]
        
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_type": "benchmark",
            "event_count": event_count,
            "results": []
        }
        
        for name, gen_class in generators_to_test:
            try:
                generator = gen_class({'eps': 100}, self.inventory)
                result = runner.benchmark_generator(generator, event_count, name)
                
                results["results"].append({
                    "generator": name,
                    "avg_eps": result.avg_eps,
                    "latency_median_ms": result.median_latency_ms,
                    "memory_peak_mb": result.memory_peak_mb,
                    "passed": result.avg_eps > 100  # Should achieve >100 EPS
                })
                
                print(f"\n  ✅ {name}:")
                print(f"     Avg EPS: {result.avg_eps:,.0f}")
                print(f"     Latency: {result.median_latency_ms:.3f}ms")
                print(f"     Memory: {result.memory_peak_mb:.1f}MB")
                
            except Exception as e:
                print(f"\n  ❌ {name}: {e}")
        
        self.results["benchmark"] = results
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all test phases.
        
        Returns:
            Complete test results
        """
        print("\n" + "🧪" * 35)
        print("🧪 COMPLETE TEST SUITE - soc-log-generator 🧪")
        print("🧪" * 35)
        
        start_time = datetime.now(timezone.utc)
        
        # Run all phases
        self.run_validation_tests(sample_size=50)
        self.run_siem_tests(sample_size=20)
        self.run_stress_tests(duration=10.0)
        self.run_benchmarks(event_count=2000)
        
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()
        
        # Summary
        summary = {
            "test_run_id": start_time.strftime("%Y%m%d_%H%M%S"),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "overall_passed": True,
            "phases": {}
        }
        
        # Calculate pass/fail for each phase
        if "validation" in self.results:
            val = self.results["validation"]
            summary["phases"]["validation"] = {
                "passed": val["pass_rate"] >= 80,
                "pass_rate": val["pass_rate"],
                "generators": f"{val['generators_passed']}/{val['generators_tested']}"
            }
        
        if "siem" in self.results:
            siem = self.results["siem"]
            avg_extraction = sum(d["avg_extraction_rate"] for d in siem["details"]) / len(siem["details"])
            summary["phases"]["siem"] = {
                "passed": avg_extraction >= 0.7,
                "avg_extraction_rate": avg_extraction * 100
            }
        
        if "stress" in self.results:
            stress = self.results["stress"]
            all_passed = all(t["passed"] for t in stress["tests"])
            summary["phases"]["stress"] = {
                "passed": all_passed,
                "tests_passed": sum(1 for t in stress["tests"] if t["passed"])
            }
        
        if "benchmark" in self.results:
            bench = self.results["benchmark"]
            all_passed = all(r["passed"] for r in bench["results"])
            summary["phases"]["benchmark"] = {
                "passed": all_passed,
                "generators_tested": len(bench["results"])
            }
        
        summary["overall_passed"] = all(p["passed"] for p in summary["phases"].values())
        self.results["summary"] = summary
        
        return self.results
    
    def print_report(self, results: Dict[str, Any] = None):
        """Print formatted test report."""
        if results is None:
            results = self.results
        
        print("\n" + "=" * 70)
        print("📊 FINAL TEST REPORT")
        print("=" * 70)
        
        summary = results.get("summary", {})
        print(f"\nTest Run ID: {summary.get('test_run_id', 'N/A')}")
        print(f"Duration: {summary.get('duration_seconds', 0):.1f}s")
        
        print("\n📋 Phase Results:")
        for phase, result in summary.get("phases", {}).items():
            status = "✅ PASS" if result["passed"] else "❌ FAIL"
            print(f"  {phase:<20} {status}")
        
        overall = "✅ ALL TESTS PASSED" if summary.get("overall_passed") else "❌ SOME TESTS FAILED"
        print(f"\n{overall}")
        print("=" * 70)
    
    def export_results(self, filename: str = None):
        """Export results to JSON file."""
        if filename is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"test_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n💾 Results exported to: {filename}")


def main():
    """Main entry point."""
    suite = TestSuite()
    
    try:
        results = suite.run_all_tests()
        suite.print_report(results)
        suite.export_results()
        
        # Exit with appropriate code
        summary = results.get("summary", {})
        sys.exit(0 if summary.get("overall_passed") else 1)
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
