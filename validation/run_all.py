#!/usr/bin/env python3
"""
Run All Validations - Execute complete validation suite

This script runs all validation checks:
1. Schema validation
2. Reality checking (if samples available)
3. Version checking
4. Report generation

Usage:
    python -m validation.run_all
    python -m validation.run_all --source windows --output-dir reports/
    python -m validation.run_all --quick  # Skip reality checking

Author: SOC Log Generator Research Team
Version: 1.0.0
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import validation modules
from validation import RealityChecker, VersionManager, ReportGenerator
from validation.schemas import SchemaRegistry

# Import generators for testing
from core import AssetInventory
from generators.endpoint.windows import WindowsEventGenerator
from generators.endpoint.linux_generator import LinuxAuthGenerator
from generators.network.firewall import FirewallGenerator
from generators.network.proxy import ProxyGenerator
from generators.network.dns import DNSGenerator
from generators.network.ids import IDSensorGenerator
from generators.cloud.aws_cloudtrail import AWSCloudTrailGenerator
from generators.cloud.azure_activity import AzureActivityGenerator
from generators.cloud.azure_signin import AzureSignInGenerator
from generators.cloud.o365 import Office365Generator
from generators.cloud.gcp_audit import GCPAuditGenerator


class ValidationRunner:
    """Run complete validation suite."""
    
    def __init__(self, output_dir: Path = Path("validation_results")):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.inventory = AssetInventory()
        
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "tests": {}
        }
    
    def run_schema_validation(self, source_type: Optional[str] = None) -> Dict[str, Any]:
        """Run schema validation tests."""
        print("\n" + "=" * 70)
        print("🔍 SCHEMA VALIDATION")
        print("=" * 70)
        
        from validation import LogValidator
        
        validator = LogValidator()
        generators = self._get_generators()
        
        results = {}
        
        for name, gen_class in generators.items():
            if source_type and name != source_type:
                continue
            
            try:
                generator = gen_class({'eps': 100}, self.inventory)
                events = [generator.generate_event() for _ in range(100)]
                
                # Validate batch
                report = validator.validate_batch(events)
                stats = report.to_dict()
                
                passed = stats.get('validity_rate', 0) >= 80
                
                results[name] = {
                    "passed": passed,
                    "validity_rate": stats.get('validity_rate', 0),
                    "field_coverage": stats.get('field_coverage', {}),
                    "errors": list(stats.get('common_errors', {}).keys())[:5]
                }
                
                status = "✅" if passed else "❌"
                print(f"{status} {name:<25} Validity: {stats.get('validity_rate', 0):.1f}%")
                
            except Exception as e:
                print(f"❌ {name:<25} ERROR: {str(e)[:50]}")
                results[name] = {"passed": False, "error": str(e)}
        
        self.results["tests"]["schema_validation"] = results
        return results
    
    def run_reality_check(self, source_type: Optional[str] = None,
                          samples_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Run reality checking against real samples."""
        print("\n" + "=" * 70)
        print("🔍 REALITY CHECKING")
        print("=" * 70)
        
        samples_dir = samples_dir or Path("samples")
        checker = RealityChecker()
        
        results = {}
        
        # Map source types to sample directories
        source_mapping = {
            "windows": "windows",
            "linux": "linux",
            "aws": "aws",
            "azure": "azure",
            "gcp": "gcp",
            "firewall": "firewall",
            "proxy": "proxy",
            "dns": "dns",
            "ids": "ids"
        }
        
        for src, dir_name in source_mapping.items():
            if source_type and src != source_type:
                continue
            
            sample_path = samples_dir / dir_name
            if not sample_path.exists():
                print(f"⏭️  {src:<25} No samples found (skipping)")
                results[src] = {"skipped": True, "reason": "No samples"}
                continue
            
            try:
                # Load real samples
                count = checker.load_real_samples(sample_path, src)
                
                # Generate comparison samples
                generator = self._get_generator(src)
                if generator:
                    generated = [generator.generate_event() for _ in range(min(count, 100))]
                    checker.load_generated_samples(generated, src)
                    
                    # Run comparison
                    report = checker.compare(src)
                    
                    results[src] = {
                        "passed": report.overall_score >= 70,
                        "overall_score": report.overall_score,
                        "field_coverage": report.field_coverage,
                        "pattern_accuracy": report.pattern_accuracy,
                        "missing_fields": report.missing_fields[:10],
                        "recommendations": report.recommendations[:5]
                    }
                    
                    # Save detailed report
                    report_file = self.output_dir / f"reality_check_{src}.json"
                    with open(report_file, 'w') as f:
                        json.dump(report.to_dict(), f, indent=2)
                    
                    status = "✅" if report.overall_score >= 70 else "⚠️"
                    print(f"{status} {src:<25} Score: {report.overall_score:.1f}% "
                          f"(Coverage: {report.field_coverage:.1f}%)")
                else:
                    print(f"❌ {src:<25} No generator found")
                    results[src] = {"skipped": True, "reason": "No generator"}
                    
            except Exception as e:
                print(f"❌ {src:<25} ERROR: {str(e)[:50]}")
                results[src] = {"error": str(e)}
        
        self.results["tests"]["reality_check"] = results
        return results
    
    def run_version_check(self, source_type: Optional[str] = None) -> Dict[str, Any]:
        """Check version status for all sources."""
        print("\n" + "=" * 70)
        print("🔍 VERSION STATUS")
        print("=" * 70)
        
        vm = VersionManager()
        
        if source_type:
            sources = [source_type]
        else:
            sources = list(vm._registry.keys())
        
        results = {}
        
        for src in sources:
            current = vm.get_current_version(src)
            versions = vm.list_versions(src)
            
            if current:
                results[src] = {
                    "current_version": current.version,
                    "total_versions": len(versions),
                    "supported_versions": sum(1 for v in versions if v.supported),
                    "breaking_changes": any(v.breaking for v in versions),
                    "up_to_date": True  # Would compare with latest known
                }
                
                print(f"✅ {src:<25} v{current.version} ({len(versions)} versions)")
            else:
                results[src] = {"error": "No version registered"}
                print(f"⚠️  {src:<25} No version registered")
        
        self.results["tests"]["version_check"] = results
        return results
    
    def generate_reports(self, format: str = "all") -> Dict[str, Path]:
        """Generate validation reports."""
        print("\n" + "=" * 70)
        print("📊 GENERATING REPORTS")
        print("=" * 70)
        
        generator = ReportGenerator(self.output_dir)
        
        # Collect metrics
        metrics = generator.collect_metrics()
        
        # Generate full report
        report = generator.generate_full_report(metrics)
        
        output_files = {}
        
        if format in ("all", "json"):
            json_path = self.output_dir / "validation_report.json"
            generator.save_report(report, json_path, "json")
            output_files["json"] = json_path
            print(f"✅ JSON report: {json_path}")
        
        if format in ("all", "html"):
            html_path = self.output_dir / "validation_report.html"
            generator.save_report(report, html_path, "html")
            output_files["html"] = html_path
            print(f"✅ HTML report: {html_path}")
        
        if format in ("all", "markdown"):
            md_path = self.output_dir / "validation_report.md"
            generator.save_report(report, md_path, "markdown")
            output_files["markdown"] = md_path
            print(f"✅ Markdown report: {md_path}")
        
        # Save raw results
        results_path = self.output_dir / "validation_results.json"
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        output_files["results"] = results_path
        
        return output_files
    
    def _get_generators(self) -> Dict[str, Any]:
        """Get all available generators."""
        return {
            "windows": WindowsEventGenerator,
            "linux": LinuxAuthGenerator,
            "firewall": FirewallGenerator,
            "proxy": ProxyGenerator,
            "dns": DNSGenerator,
            "ids": IDSensorGenerator,
            "aws": AWSCloudTrailGenerator,
            "azure": AzureActivityGenerator,
            "azure-signin": AzureSignInGenerator,
            "o365": Office365Generator,
            "gcp": GCPAuditGenerator
        }
    
    def _get_generator(self, source_type: str) -> Optional[Any]:
        """Get generator instance for source type."""
        generators = self._get_generators()
        
        if source_type in generators:
            try:
                return generators[source_type]({'eps': 100}, self.inventory)
            except:
                return None
        return None
    
    def print_summary(self):
        """Print summary of all validation results."""
        print("\n" + "=" * 70)
        print("📋 VALIDATION SUMMARY")
        print("=" * 70)
        
        # Schema validation summary
        schema_results = self.results["tests"].get("schema_validation", {})
        passed = sum(1 for r in schema_results.values() if r.get("passed"))
        total = len(schema_results)
        print(f"\nSchema Validation: {passed}/{total} passed")
        
        # Reality check summary
        reality_results = self.results["tests"].get("reality_check", {})
        checked = sum(1 for r in reality_results.values() if not r.get("skipped"))
        passed_reality = sum(1 for r in reality_results.values() 
                            if r.get("passed") and not r.get("skipped"))
        print(f"Reality Check: {passed_reality}/{checked} passed ({len(reality_results) - checked} skipped)")
        
        # Overall score
        avg_scores = []
        for r in reality_results.values():
            if "overall_score" in r:
                avg_scores.append(r["overall_score"])
        
        if avg_scores:
            print(f"\nOverall Average Accuracy: {sum(avg_scores)/len(avg_scores):.1f}%")
        
        print("\n" + "=" * 70)
        
        # Recommendations
        critical = sum(1 for r in reality_results.values() 
                      if r.get("overall_score", 100) < 50)
        needs_work = sum(1 for r in reality_results.values() 
                        if 50 <= r.get("overall_score", 100) < 70)
        
        if critical > 0:
            print(f"⚠️  {critical} sources need critical attention")
        if needs_work > 0:
            print(f"⚠️  {needs_work} sources need improvement")
        if critical == 0 and needs_work == 0:
            print("✅ All validated sources performing well!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run complete validation suite"
    )
    parser.add_argument(
        "--source",
        help="Validate only specific source type"
    )
    parser.add_argument(
        "--output-dir",
        default="validation_results",
        help="Output directory for results"
    )
    parser.add_argument(
        "--samples-dir",
        default="samples",
        help="Directory containing real samples"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip reality checking (schema validation only)"
    )
    parser.add_argument(
        "--report-format",
        choices=["json", "html", "markdown", "all"],
        default="all",
        help="Report output format"
    )
    
    args = parser.parse_args()
    
    print("🧪" * 35)
    print("🧪  SOC LOG GENERATOR - VALIDATION SUITE  🧪")
    print("🧪" * 35)
    print(f"\nStarted: {datetime.utcnow().isoformat()}")
    
    runner = ValidationRunner(Path(args.output_dir))
    
    # Run validations
    runner.run_schema_validation(args.source)
    
    if not args.quick:
        runner.run_reality_check(args.source, Path(args.samples_dir))
    
    runner.run_version_check(args.source)
    
    # Generate reports
    output_files = runner.generate_reports(args.report_format)
    
    # Print summary
    runner.print_summary()
    
    print(f"\n📁 Results saved to: {args.output_dir}/")
    print("\nDone!")
    
    # Return exit code based on results
    schema_results = runner.results["tests"].get("schema_validation", {})
    failed = sum(1 for r in schema_results.values() if not r.get("passed"))
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
