#!/usr/bin/env python3
"""
Report Generator - Generate comprehensive accuracy reports

This module generates detailed accuracy reports showing how closely
generated logs match real-world samples across all dimensions.

Usage:
    from validation.report_generator import ReportGenerator
    
    generator = ReportGenerator()
    
    # Generate report for all sources
    report = generator.generate_full_report()
    generator.save_report(report, "accuracy_report.html", format="html")
    
    # Generate report for specific source
    source_report = generator.generate_source_report("windows")
    generator.save_report(source_report, "windows_accuracy.md", format="markdown")

Author: SOC Log Generator Research Team
Version: 1.0.0
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import html


@dataclass
class AccuracyMetrics:
    """Accuracy metrics for a single source."""
    source_type: str
    version: str
    
    # Coverage metrics
    field_coverage: float = 0.0
    pattern_accuracy: float = 0.0
    type_accuracy: float = 0.0
    distribution_similarity: float = 0.0
    
    # Test results
    unit_tests_passed: int = 0
    unit_tests_total: int = 0
    siem_tests_passed: int = 0
    siem_tests_total: int = 0
    live_validation_passed: bool = False
    
    # Sample counts
    real_samples_used: int = 0
    generated_samples_tested: int = 0
    
    # Timestamps
    last_updated: datetime = field(default_factory=datetime.utcnow)
    last_live_test: Optional[datetime] = None
    
    @property
    def overall_score(self) -> float:
        """Calculate weighted overall score."""
        weights = {
            "field_coverage": 0.30,
            "pattern_accuracy": 0.25,
            "type_accuracy": 0.20,
            "distribution_similarity": 0.15,
            "test_success": 0.10
        }
        
        test_score = 0.0
        if self.unit_tests_total > 0:
            test_score += (self.unit_tests_passed / self.unit_tests_total) * 50
        if self.siem_tests_total > 0:
            test_score += (self.siem_tests_passed / self.siem_tests_total) * 50
        
        score = (
            self.field_coverage * weights["field_coverage"] +
            self.pattern_accuracy * weights["pattern_accuracy"] +
            self.type_accuracy * weights["type_accuracy"] +
            self.distribution_similarity * weights["distribution_similarity"] +
            test_score * weights["test_success"]
        )
        
        return min(100.0, max(0.0, score))
    
    @property
    def status(self) -> str:
        """Get status based on score."""
        score = self.overall_score
        if score >= 95:
            return "excellent"
        elif score >= 85:
            return "good"
        elif score >= 70:
            return "acceptable"
        elif score >= 50:
            return "needs_improvement"
        else:
            return "critical"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "version": self.version,
            "metrics": {
                "field_coverage": round(self.field_coverage, 2),
                "pattern_accuracy": round(self.pattern_accuracy, 2),
                "type_accuracy": round(self.type_accuracy, 2),
                "distribution_similarity": round(self.distribution_similarity, 2),
                "overall_score": round(self.overall_score, 2),
                "status": self.status
            },
            "tests": {
                "unit": {
                    "passed": self.unit_tests_passed,
                    "total": self.unit_tests_total,
                    "rate": round(self.unit_tests_passed / self.unit_tests_total * 100, 1) if self.unit_tests_total else 0
                },
                "siem": {
                    "passed": self.siem_tests_passed,
                    "total": self.siem_tests_total,
                    "rate": round(self.siem_tests_passed / self.siem_tests_total * 100, 1) if self.siem_tests_total else 0
                },
                "live_validation": self.live_validation_passed
            },
            "samples": {
                "real": self.real_samples_used,
                "generated": self.generated_samples_tested
            },
            "timestamps": {
                "last_updated": self.last_updated.isoformat(),
                "last_live_test": self.last_live_test.isoformat() if self.last_live_test else None
            }
        }


class ReportGenerator:
    """
    Generate comprehensive accuracy reports.
    
    This class aggregates data from multiple validation sources:
    - Reality checker comparisons
    - Unit test results
    - SIEM integration tests
    - Live validation results
    
    And generates reports in multiple formats:
    - HTML (interactive dashboard)
    - Markdown (documentation)
    - JSON (machine-readable)
    - CSV (spreadsheet)
    
    Example:
        generator = ReportGenerator()
        
        # Load metrics from various sources
        metrics = generator.collect_metrics()
        
        # Generate full report
        report = generator.generate_full_report(metrics)
        
        # Export
        generator.save_report(report, "report.html", "html")
        generator.save_report(report, "report.md", "markdown")
    """
    
    # Score thresholds
    EXCELLENT_THRESHOLD = 95
    GOOD_THRESHOLD = 85
    ACCEPTABLE_THRESHOLD = 70
    NEEDS_IMPROVEMENT_THRESHOLD = 50
    
    def __init__(self, output_dir: Optional[Union[str, Path]] = None):
        """
        Initialize ReportGenerator.
        
        Args:
            output_dir: Default directory for report output
        """
        self.output_dir = Path(output_dir) if output_dir else Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Status icons
        self.status_icons = {
            "excellent": "🟢",
            "good": "🟢",
            "acceptable": "🟡",
            "needs_improvement": "🟠",
            "critical": "🔴",
            "unknown": "⚪"
        }
    
    def collect_metrics(self, source_types: Optional[List[str]] = None) -> Dict[str, AccuracyMetrics]:
        """
        Collect accuracy metrics from all validation sources.
        
        Args:
            source_types: Optional list of sources to collect (all if None)
            
        Returns:
            Dictionary mapping source types to AccuracyMetrics
        """
        from validation.reality_checker import RealityChecker
        from validation.version_manager import VersionManager
        from validation.schemas import SchemaRegistry
        
        metrics = {}
        
        # Get all source types from schema registry if not specified
        if source_types is None:
            source_types = SchemaRegistry.list_schemas()
        
        vm = VersionManager()
        
        for source_type in source_types:
            metric = AccuracyMetrics(source_type=source_type, version="")
            
            # Get current version
            current = vm.get_current_version(source_type)
            if current:
                metric.version = current.version
            
            # Load reality check results if available
            rc_file = self.output_dir / f"reality_check_{source_type}.json"
            if rc_file.exists():
                with open(rc_file, 'r') as f:
                    rc_data = json.load(f)
                    metric.field_coverage = rc_data.get("metrics", {}).get("field_coverage", 0)
                    metric.pattern_accuracy = rc_data.get("metrics", {}).get("pattern_accuracy", 0)
                    metric.type_accuracy = rc_data.get("metrics", {}).get("type_accuracy", 0)
                    metric.distribution_similarity = rc_data.get("metrics", {}).get("distribution_similarity", 0)
                    metric.real_samples_used = rc_data.get("sample_counts", {}).get("real", 0)
                    metric.generated_samples_tested = rc_data.get("sample_counts", {}).get("generated", 0)
            
            # Load test results if available
            test_file = self.output_dir / f"test_results_{source_type}.json"
            if test_file.exists():
                with open(test_file, 'r') as f:
                    test_data = json.load(f)
                    metric.unit_tests_passed = test_data.get("unit", {}).get("passed", 0)
                    metric.unit_tests_total = test_data.get("unit", {}).get("total", 0)
                    metric.siem_tests_passed = test_data.get("siem", {}).get("passed", 0)
                    metric.siem_tests_total = test_data.get("siem", {}).get("total", 0)
            
            metrics[source_type] = metric
        
        return metrics
    
    def generate_full_report(self, metrics: Optional[Dict[str, AccuracyMetrics]] = None) -> Dict[str, Any]:
        """
        Generate comprehensive accuracy report for all sources.
        
        Args:
            metrics: Optional pre-collected metrics
            
        Returns:
            Complete report data structure
        """
        if metrics is None:
            metrics = self.collect_metrics()
        
        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator_version": "1.0.0",
                "total_sources": len(metrics),
                "report_type": "full_accuracy_report"
            },
            "summary": self._generate_summary(metrics),
            "sources": {k: v.to_dict() for k, v in metrics.items()},
            "rankings": self._generate_rankings(metrics),
            "trends": self._generate_trends(metrics),
            "recommendations": self._generate_recommendations(metrics)
        }
        
        return report
    
    def generate_source_report(self, source_type: str, 
                                metrics: Optional[AccuracyMetrics] = None) -> Dict[str, Any]:
        """
        Generate detailed report for a single source.
        
        Args:
            source_type: Source type to report on
            metrics: Optional pre-collected metrics
            
        Returns:
            Source-specific report
        """
        if metrics is None:
            all_metrics = self.collect_metrics([source_type])
            metrics = all_metrics.get(source_type)
        
        if not metrics:
            return {"error": f"No metrics found for {source_type}"}
        
        # Load detailed comparison data
        rc_file = self.output_dir / f"reality_check_{source_type}.json"
        comparison_data = {}
        if rc_file.exists():
            with open(rc_file, 'r') as f:
                comparison_data = json.load(f)
        
        return {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "source_type": source_type,
                "version": metrics.version
            },
            "metrics": metrics.to_dict(),
            "comparison": comparison_data.get("findings", {}),
            "field_analysis": comparison_data.get("field_analysis", {}),
            "improvement_history": self._load_improvement_history(source_type)
        }
    
    def _generate_summary(self, metrics: Dict[str, AccuracyMetrics]) -> Dict[str, Any]:
        """Generate overall summary statistics."""
        if not metrics:
            return {}
        
        scores = [m.overall_score for m in metrics.values()]
        statuses = [m.status for m in metrics.values()]
        
        return {
            "overall_average": round(sum(scores) / len(scores), 2),
            "highest_score": round(max(scores), 2),
            "lowest_score": round(min(scores), 2),
            "sources_by_status": {
                "excellent": statuses.count("excellent"),
                "good": statuses.count("good"),
                "acceptable": statuses.count("acceptable"),
                "needs_improvement": statuses.count("needs_improvement"),
                "critical": statuses.count("critical")
            },
            "total_samples_tested": sum(m.generated_samples_tested for m in metrics.values()),
            "live_validation_pass_rate": sum(1 for m in metrics.values() if m.live_validation_passed) / len(metrics) * 100
        }
    
    def _generate_rankings(self, metrics: Dict[str, AccuracyMetrics]) -> List[Dict]:
        """Generate sorted rankings of sources by accuracy."""
        ranked = sorted(
            metrics.items(),
            key=lambda x: x[1].overall_score,
            reverse=True
        )
        
        return [
            {
                "rank": i + 1,
                "source_type": source_type,
                "score": round(metric.overall_score, 2),
                "status": metric.status,
                "version": metric.version
            }
            for i, (source_type, metric) in enumerate(ranked)
        ]
    
    def _generate_trends(self, metrics: Dict[str, AccuracyMetrics]) -> Dict[str, Any]:
        """Generate trend analysis (requires historical data)."""
        # Load historical data
        history_file = self.output_dir / "accuracy_history.json"
        if not history_file.exists():
            return {"message": "No historical data available"}
        
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        trends = {}
        for source_type, metric in metrics.items():
            if source_type in history:
                historical_scores = [h.get("score", 0) for h in history[source_type][-5:]]
                if len(historical_scores) >= 2:
                    trend = "improving" if historical_scores[-1] > historical_scores[0] else \
                            "declining" if historical_scores[-1] < historical_scores[0] else "stable"
                    change = historical_scores[-1] - historical_scores[0]
                    
                    trends[source_type] = {
                        "trend": trend,
                        "change": round(change, 2),
                        "current": round(historical_scores[-1], 2),
                        "historical_average": round(sum(historical_scores) / len(historical_scores), 2)
                    }
        
        return trends
    
    def _generate_recommendations(self, metrics: Dict[str, AccuracyMetrics]) -> List[Dict]:
        """Generate prioritized improvement recommendations."""
        recommendations = []
        
        for source_type, metric in metrics.items():
            if metric.status in ["critical", "needs_improvement"]:
                priority = "critical" if metric.status == "critical" else "high"
                
                if metric.field_coverage < 80:
                    recommendations.append({
                        "priority": priority,
                        "source_type": source_type,
                        "issue": "Low field coverage",
                        "current_value": f"{metric.field_coverage:.1f}%",
                        "target": "90%+",
                        "action": f"Add missing fields to {source_type} generator"
                    })
                
                if metric.pattern_accuracy < 90:
                    recommendations.append({
                        "priority": priority,
                        "source_type": source_type,
                        "issue": "Low pattern accuracy",
                        "current_value": f"{metric.pattern_accuracy:.1f}%",
                        "target": "95%+",
                        "action": f"Review and fix field patterns in {source_type} generator"
                    })
                
                if not metric.live_validation_passed:
                    recommendations.append({
                        "priority": priority,
                        "source_type": source_type,
                        "issue": "Live validation not passed",
                        "current_value": "Failed",
                        "target": "Pass",
                        "action": f"Run live SIEM validation for {source_type}"
                    })
        
        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        return recommendations
    
    def _load_improvement_history(self, source_type: str) -> List[Dict]:
        """Load historical improvement data for a source."""
        history_file = self.output_dir / "accuracy_history.json"
        if not history_file.exists():
            return []
        
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        return history.get(source_type, [])
    
    def save_report(self, report: Dict[str, Any], filepath: Union[str, Path], 
                    format: str = "json") -> None:
        """
        Save report to file.
        
        Args:
            report: Report data
            filepath: Output file path
            format: Output format (json, html, markdown, csv)
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "json":
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
        
        elif format == "html":
            html_content = self._generate_html(report)
            with open(filepath, 'w') as f:
                f.write(html_content)
        
        elif format == "markdown":
            md_content = self._generate_markdown(report)
            with open(filepath, 'w') as f:
                f.write(md_content)
        
        elif format == "csv":
            csv_content = self._generate_csv(report)
            with open(filepath, 'w') as f:
                f.write(csv_content)
        
        else:
            raise ValueError(f"Unknown format: {format}")
    
    def _generate_html(self, report: Dict[str, Any]) -> str:
        """Generate HTML report."""
        summary = report.get("summary", {})
        sources = report.get("sources", {})
        rankings = report.get("rankings", [])
        recommendations = report.get("recommendations", [])
        
        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<title>SOC Log Generator - Accuracy Report</title>",
            "<style>",
            self._get_css_styles(),
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<h1>🎯 SOC Log Generator - Accuracy Report</h1>",
            f"<p class='timestamp'>Generated: {report['metadata']['generated_at']}</p>",
            
            # Summary section
            "<div class='section'>",
            "<h2>📊 Summary</h2>",
            "<div class='summary-grid'>",
            f"<div class='metric'><span class='value'>{summary.get('overall_average', 0):.1f}%</span><span class='label'>Average Score</span></div>",
            f"<div class='metric'><span class='value'>{summary.get('highest_score', 0):.1f}%</span><span class='label'>Highest</span></div>",
            f"<div class='metric'><span class='value'>{summary.get('lowest_score', 0):.1f}%</span><span class='label'>Lowest</span></div>",
            f"<div class='metric'><span class='value'>{len(sources)}</span><span class='label'>Sources</span></div>",
            "</div>",
            "</div>",
            
            # Status distribution
            "<div class='section'>",
            "<h2>📈 Status Distribution</h2>",
            "<div class='status-bars'>"
        ]
        
        for status, count in summary.get("sources_by_status", {}).items():
            if count > 0:
                percentage = count / len(sources) * 100 if sources else 0
                html_parts.append(
                    f"<div class='status-bar {status}'>"
                    f"<span class='status-label'>{self.status_icons.get(status, '⚪')} {status.title()}</span>"
                    f"<div class='bar' style='width:{percentage}%'></div>"
                    f"<span class='count'>{count}</span>"
                    f"</div>"
                )
        
        html_parts.extend([
            "</div>",
            "</div>",
            
            # Rankings
            "<div class='section'>",
            "<h2>🏆 Source Rankings</h2>",
            "<table>",
            "<tr><th>Rank</th><th>Source</th><th>Version</th><th>Score</th><th>Status</th></tr>"
        ])
        
        for ranking in rankings[:10]:  # Top 10
            status_class = ranking.get("status", "unknown")
            html_parts.append(
                f"<tr class='{status_class}'>"
                f"<td>#{ranking['rank']}</td>"
                f"<td>{ranking['source_type']}</td>"
                f"<td>{ranking.get('version', 'N/A')}</td>"
                f"<td class='score'>{ranking['score']:.1f}%</td>"
                f"<td>{self.status_icons.get(status_class, '⚪')} {status_class.title()}</td>"
                f"</tr>"
            )
        
        html_parts.extend([
            "</table>",
            "</div>",
            
            # Recommendations
            "<div class='section'>",
            "<h2>🔧 Recommendations</h2>"
        ])
        
        if recommendations:
            html_parts.append("<ul class='recommendations'>")
            for rec in recommendations[:10]:
                priority_class = rec.get("priority", "medium")
                html_parts.append(
                    f"<li class='{priority_class}'>"
                    f"<strong>[{rec['priority'].upper()}]</strong> "
                    f"{rec['source_type']}: {rec['action']} "
                    f"(current: {rec['current_value']}, target: {rec['target']})"
                    f"</li>"
                )
            html_parts.append("</ul>")
        else:
            html_parts.append("<p class='success'>🎉 No critical recommendations - all sources performing well!</p>")
        
        html_parts.extend([
            "</div>",
            "</div>",
            "</body>",
            "</html>"
        ])
        
        return "\n".join(html_parts)
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML report."""
        return """
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1 { color: #333; margin-bottom: 10px; }
            h2 { color: #555; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 30px; }
            .timestamp { color: #888; font-size: 14px; margin-bottom: 20px; }
            .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
            .metric { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }
            .metric .value { display: block; font-size: 36px; font-weight: bold; color: #2ecc71; }
            .metric .label { display: block; color: #666; margin-top: 5px; }
            .status-bars { margin: 20px 0; }
            .status-bar { display: flex; align-items: center; margin: 10px 0; }
            .status-label { width: 150px; font-weight: 500; }
            .bar { height: 30px; background: #ddd; border-radius: 4px; margin: 0 10px; transition: width 0.3s; }
            .bar.excellent { background: #2ecc71; }
            .bar.good { background: #27ae60; }
            .bar.acceptable { background: #f39c12; }
            .bar.needs_improvement { background: #e67e22; }
            .bar.critical { background: #e74c3c; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
            th { background: #f8f9fa; font-weight: 600; }
            tr:hover { background: #f8f9fa; }
            .score { font-weight: bold; }
            .excellent .score { color: #2ecc71; }
            .good .score { color: #27ae60; }
            .acceptable .score { color: #f39c12; }
            .needs_improvement .score { color: #e67e22; }
            .critical .score { color: #e74c3c; }
            .recommendations { list-style: none; padding: 0; }
            .recommendations li { padding: 12px; margin: 8px 0; border-radius: 4px; border-left: 4px solid; }
            .recommendations li.critical { background: #fdf2f2; border-color: #e74c3c; }
            .recommendations li.high { background: #fff8f0; border-color: #e67e22; }
            .recommendations li.medium { background: #fffbeb; border-color: #f39c12; }
            .success { color: #27ae60; font-size: 18px; }
        """
    
    def _generate_markdown(self, report: Dict[str, Any]) -> str:
        """Generate Markdown report."""
        summary = report.get("summary", {})
        rankings = report.get("rankings", [])
        recommendations = report.get("recommendations", [])
        
        lines = [
            "# SOC Log Generator - Accuracy Report",
            "",
            f"**Generated**: {report['metadata']['generated_at']}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Overall Average | {summary.get('overall_average', 0):.1f}% |",
            f"| Highest Score | {summary.get('highest_score', 0):.1f}% |",
            f"| Lowest Score | {summary.get('lowest_score', 0):.1f}% |",
            f"| Total Sources | {len(report.get('sources', {}))} |",
            "",
            "## Rankings",
            "",
            f"| Rank | Source | Version | Score | Status |",
            f"|------|--------|---------|-------|--------|"
        ]
        
        for ranking in rankings[:20]:
            icon = self.status_icons.get(ranking.get("status", "unknown"), "⚪")
            lines.append(
                f"| #{ranking['rank']} | {ranking['source_type']} | "
                f"{ranking.get('version', 'N/A')} | {ranking['score']:.1f}% | "
                f"{icon} {ranking.get('status', 'unknown').title()} |"
            )
        
        lines.extend([
            "",
            "## Recommendations",
            ""
        ])
        
        if recommendations:
            for rec in recommendations[:15]:
                lines.append(f"- **[{rec['priority'].upper()}]** {rec['source_type']}: {rec['action']}")
        else:
            lines.append("🎉 No critical recommendations - all sources performing well!")
        
        return "\n".join(lines)
    
    def _generate_csv(self, report: Dict[str, Any]) -> str:
        """Generate CSV report."""
        lines = ["source_type,version,overall_score,field_coverage,pattern_accuracy,status"]
        
        for source_type, data in report.get("sources", {}).items():
            metrics = data.get("metrics", {})
            lines.append(
                f"{source_type},"
                f"{data.get('version', '')},"
                f"{metrics.get('overall_score', 0)},"
                f"{metrics.get('field_coverage', 0)},"
                f"{metrics.get('pattern_accuracy', 0)},"
                f"{metrics.get('status', 'unknown')}"
            )
        
        return "\n".join(lines)


def main():
    """CLI for Report Generator."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate accuracy reports")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--format", choices=["json", "html", "markdown", "csv"],
                        default="json", help="Output format")
    parser.add_argument("--source", help="Generate report for specific source only")
    
    args = parser.parse_args()
    
    generator = ReportGenerator()
    
    if args.source:
        report = generator.generate_source_report(args.source)
    else:
        metrics = generator.collect_metrics()
        report = generator.generate_full_report(metrics)
    
    generator.save_report(report, args.output, args.format)
    print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
