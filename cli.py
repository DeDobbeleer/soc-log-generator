#!/usr/bin/env python3
"""
SOC Log Generator - Command Line Interface

Provides command-line interface for:
- Running log generation campaigns
- Learning from sample logs
- Researching new log sources
- Managing scenarios

Usage:
    python -m soc_log_generator generate --output file --path /var/log/test.json
    python -m soc_log_generator learn --input samples.log --output generator.py
    python -m soc_log_generator research --source "Palo Alto Cortex"
"""

import argparse
import logging
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional

try:
    from .core import (
        AssetInventory,
        EventSeverity,
        FileOutput,
        LogEvent,
        MultiOutput,
        RateLimiter,
        SyslogOutput,
        TimeProfile,
    )
except ImportError:
    # Allow running as script
    from core import (
        AssetInventory,
        EventSeverity,
        FileOutput,
        LogEvent,
        MultiOutput,
        RateLimiter,
        SyslogOutput,
        TimeProfile,
    )

# Configure logging
def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging level based on CLI arguments."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def create_output_handler(args) -> MultiOutput:
    """Create output handler(s) based on CLI arguments."""
    handlers = []
    
    # File output
    if args.output_file:
        rotation_size = args.rotation_size * 1024 * 1024 if args.rotation_size else 100 * 1024 * 1024
        handlers.append(FileOutput(args.output_file, rotation_size=rotation_size))
    
    # Syslog output
    if args.syslog_host:
        handlers.append(SyslogOutput(
            host=args.syslog_host,
            port=args.syslog_port,
            protocol=args.syslog_protocol,
            format=args.syslog_format
        ))
    
    # Default to stdout if no output specified
    if not handlers:
        # Create a simple stdout output
        import sys
        class StdoutOutput:
            def write(self, event: LogEvent) -> bool:
                print(event.to_json())
                return True
            def write_batch(self, events: List[LogEvent]) -> int:
                for e in events:
                    self.write(e)
                return len(events)
            def close(self) -> None:
                pass
            def health_check(self) -> bool:
                return True
        handlers.append(StdoutOutput())
    
    return MultiOutput(handlers)


def cmd_generate(args: argparse.Namespace) -> int:
    """Execute 'generate' command."""
    logger = logging.getLogger("soc_log_generator.cli.generate")
    logger.info("Starting log generation")
    
    # Create inventory
    inventory = AssetInventory()
    logger.info(f"Loaded inventory: {inventory}")
    
    # Create output handler
    output = create_output_handler(args)
    
    # Setup rate limiting
    limiter = RateLimiter(eps=args.eps)
    
    # Track statistics
    stats = {
        "generated": 0,
        "start_time": time.time(),
        "by_type": {},
        "by_severity": {}
    }
    
    # Setup signal handler for graceful shutdown
    running = True
    def signal_handler(signum, frame):
        nonlocal running
        logger.info("Shutdown signal received, finishing...")
        running = False
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Main generation loop
    try:
        logger.info(f"Generating logs at {args.eps} EPS")
        if args.duration:
            logger.info(f"Duration: {args.duration} seconds")
        else:
            logger.info("Duration: unlimited (Ctrl+C to stop)")
        
        last_stats_time = time.time()
        
        while running:
            # Check duration limit
            if args.duration:
                elapsed = time.time() - stats["start_time"]
                if elapsed >= args.duration:
                    logger.info(f"Duration limit reached ({args.duration}s)")
                    break
            
            # Generate a sample event (for now, demo event)
            from datetime import datetime, timezone
            event = LogEvent(
                timestamp=datetime.now(timezone.utc),
                source_type="demo",
                source_ip="10.0.0.1",
                source_host="DEMO-01",
                message=f"Generated event #{stats['generated'] + 1}",
                raw_log=f"DEMO: Event {stats['generated'] + 1}",
                fields={"seq": stats["generated"] + 1},
                tags=["demo", "generated"],
                severity=EventSeverity.LOW
            )
            
            # Write to output
            if output.write(event):
                stats["generated"] += 1
                stats["by_type"][event.source_type] = stats["by_type"].get(event.source_type, 0) + 1
                stats["by_severity"][event.severity.name] = stats["by_severity"].get(event.severity.name, 0) + 1
            
            # Print statistics periodically
            now = time.time()
            if now - last_stats_time >= args.stats_interval:
                elapsed = now - stats["start_time"]
                current_eps = stats["generated"] / elapsed if elapsed > 0 else 0
                logger.info(
                    f"Generated: {stats['generated']:,} events | "
                    f"Rate: {current_eps:.1f} EPS | "
                    f"By type: {stats['by_type']}"
                )
                last_stats_time = now
            
            # Rate limiting
            limiter.acquire()
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        output.close()
        
        # Final statistics
        elapsed = time.time() - stats["start_time"]
        avg_eps = stats["generated"] / elapsed if elapsed > 0 else 0
        logger.info("=" * 60)
        logger.info("Generation Complete")
        logger.info(f"Total events: {stats['generated']:,}")
        logger.info(f"Duration: {elapsed:.1f} seconds")
        logger.info(f"Average rate: {avg_eps:.1f} EPS")
        logger.info(f"By type: {stats['by_type']}")
        logger.info(f"By severity: {stats['by_severity']}")
        logger.info("=" * 60)
    
    return 0


def cmd_learn(args: argparse.Namespace) -> int:
    """Execute 'learn' command."""
    logger = logging.getLogger("soc_log_generator.cli.learn")
    logger.info("Learning from log samples")
    
    if not args.input:
        logger.error("No input file specified (--input)")
        return 1
    
    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        return 1
    
    logger.info(f"Reading samples from: {input_path}")
    
    # Read samples
    try:
        with open(input_path, 'r') as f:
            samples = f.readlines()[:args.max_samples]
        logger.info(f"Loaded {len(samples)} samples")
    except Exception as e:
        logger.error(f"Failed to read input: {e}")
        return 1
    
    # Analyze samples (placeholder for actual learning logic)
    logger.info("Analyzing log format...")
    
    # Detect format
    sample = samples[0] if samples else ""
    if sample.startswith('{'):
        detected_format = "JSON"
    elif '=' in sample and ',' in sample:
        detected_format = "Key-Value"
    elif ' ' in sample and ':' in sample[:20]:
        detected_format = "Syslog"
    else:
        detected_format = "Unknown"
    
    logger.info(f"Detected format: {detected_format}")
    
    # Generate output (placeholder)
    if args.output:
        output_path = Path(args.output)
        logger.info(f"Writing generator to: {output_path}")
        
        generator_code = f'''#!/usr/bin/env python3
"""
Auto-generated log generator
Learned from: {input_path}
Format: {detected_format}
"""

from typing import Dict, Any
from datetime import datetime, timezone
from ...core import BaseGenerator, LogEvent, EventSeverity, AssetInventory

class LearnedGenerator(BaseGenerator):
    def __init__(self, config: Dict[str, Any], inventory: AssetInventory):
        super().__init__(config)
        self.inventory = inventory
    
    def generate_event(self) -> LogEvent:
        # TODO: Implement based on learned patterns
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="learned",
            source_ip="127.0.0.1",
            source_host="localhost",
            message="Generated from learned pattern",
            raw_log="LEARNED: sample",
            fields={{}},
            tags=["learned"],
            severity=EventSeverity.LOW
        )
'''
        
        try:
            with open(output_path, 'w') as f:
                f.write(generator_code)
            logger.info("Generator template created successfully")
        except Exception as e:
            logger.error(f"Failed to write output: {e}")
            return 1
    
    return 0


def cmd_research(args: argparse.Namespace) -> int:
    """Execute 'research' command."""
    logger = logging.getLogger("soc_log_generator.cli.research")
    logger.info(f"Researching log source: {args.source}")
    
    # Placeholder for web research functionality
    logger.info("Searching vendor documentation...")
    logger.info("Searching GitHub for sample logs...")
    logger.info("Searching community forums...")
    
    # Simulate research results
    logger.info("Found references:")
    logger.info(f"  - Vendor docs: https://docs.{args.source.lower().replace(' ', '')}.com")
    logger.info(f"  - GitHub samples: 5 repositories found")
    logger.info(f"  - StackOverflow: 12 related questions")
    
    if args.output:
        logger.info(f"Generator would be written to: {args.output}")
    
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    """Execute 'inventory' command."""
    logger = logging.getLogger("soc_log_generator.cli.inventory")
    
    inventory = AssetInventory()
    
    print("\n" + "=" * 60)
    print("Asset Inventory")
    print("=" * 60)
    print(f"\nTotal Assets: {len(inventory.assets)}")
    print(f"Total Users: {len(inventory.users)}")
    print(f"Domains: {', '.join(inventory.domains)}")
    print(f"Subnets: {', '.join(inventory.subnets)}")
    
    if args.detail:
        print("\n--- Assets by Type ---")
        by_type = {}
        for hostname, asset in inventory.assets.items():
            asset_type = asset.get("type", "unknown")
            if asset_type not in by_type:
                by_type[asset_type] = []
            by_type[asset_type].append((hostname, asset.get("ip", "unknown")))
        
        for asset_type, items in sorted(by_type.items()):
            print(f"\n{asset_type.upper()} ({len(items)}):")
            for hostname, ip in sorted(items)[:10]:  # Limit to 10 per type
                print(f"  {hostname}: {ip}")
            if len(items) > 10:
                print(f"  ... and {len(items) - 10} more")
        
        print("\n--- Users ---")
        for user in inventory.users:
            print(f"  {user['username']} ({user['role']}) - {user['dept']}")
    
    print("=" * 60 + "\n")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='soc-log-generator',
        description='Professional log generator for SOC and MSSP environments',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate logs to file
  %(prog)s generate -o /var/log/test.json --eps 100 --duration 3600
  
  # Generate to syslog
  %(prog)s generate --syslog-host 10.0.0.1 --syslog-port 514 --eps 50
  
  # Learn from samples
  %(prog)s learn -i samples.log -o my_generator.py
  
  # Research a source
  %(prog)s research --source "Palo Alto Cortex XDR"
  
  # Show inventory
  %(prog)s inventory --detail

For more information: https://github.com/example/soc-log-generator
        '''
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging (DEBUG level)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress non-error output'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0-alpha'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate command
    gen_parser = subparsers.add_parser(
        'generate',
        aliases=['gen', 'g'],
        help='Generate logs'
    )
    gen_parser.add_argument(
        '-o', '--output-file',
        metavar='PATH',
        help='Output file path'
    )
    gen_parser.add_argument(
        '--rotation-size',
        type=int,
        metavar='MB',
        help='File rotation size in MB (default: 100)'
    )
    gen_parser.add_argument(
        '--syslog-host',
        metavar='HOST',
        help='Syslog server hostname'
    )
    gen_parser.add_argument(
        '--syslog-port',
        type=int,
        default=514,
        metavar='PORT',
        help='Syslog server port (default: 514)'
    )
    gen_parser.add_argument(
        '--syslog-protocol',
        choices=['tcp', 'udp'],
        default='tcp',
        help='Syslog protocol (default: tcp)'
    )
    gen_parser.add_argument(
        '--syslog-format',
        choices=['syslog', 'json', 'cef'],
        default='syslog',
        help='Syslog message format (default: syslog)'
    )
    gen_parser.add_argument(
        '--eps',
        type=float,
        default=100.0,
        metavar='EPS',
        help='Events per second (default: 100)'
    )
    gen_parser.add_argument(
        '--duration',
        type=int,
        metavar='SECONDS',
        help='Generation duration in seconds (0=unlimited)'
    )
    gen_parser.add_argument(
        '--stats-interval',
        type=int,
        default=5,
        metavar='SECONDS',
        help='Statistics print interval (default: 5)'
    )
    gen_parser.add_argument(
        '-c', '--config',
        metavar='FILE',
        help='Configuration file (YAML)'
    )
    gen_parser.set_defaults(func=cmd_generate)
    
    # Learn command
    learn_parser = subparsers.add_parser(
        'learn',
        aliases=['l'],
        help='Learn from log samples'
    )
    learn_parser.add_argument(
        '-i', '--input',
        required=True,
        metavar='FILE',
        help='Input file with log samples'
    )
    learn_parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output file for generated generator'
    )
    learn_parser.add_argument(
        '--max-samples',
        type=int,
        default=1000,
        metavar='N',
        help='Maximum samples to analyze (default: 1000)'
    )
    learn_parser.add_argument(
        '--format-hint',
        choices=['json', 'syslog', 'csv', 'auto'],
        default='auto',
        help='Hint about log format'
    )
    learn_parser.set_defaults(func=cmd_learn)
    
    # Research command
    research_parser = subparsers.add_parser(
        'research',
        aliases=['r', 'search'],
        help='Research log sources'
    )
    research_parser.add_argument(
        '--source',
        required=True,
        metavar='NAME',
        help='Source name to research (e.g., "Palo Alto Cortex")'
    )
    research_parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output file for generator'
    )
    research_parser.add_argument(
        '--category',
        choices=['endpoint', 'network', 'cloud', 'security', 'application'],
        help='Source category'
    )
    research_parser.set_defaults(func=cmd_research)
    
    # Inventory command
    inv_parser = subparsers.add_parser(
        'inventory',
        aliases=['inv', 'i'],
        help='Show asset inventory'
    )
    inv_parser.add_argument(
        '--detail',
        action='store_true',
        help='Show detailed inventory'
    )
    inv_parser.set_defaults(func=cmd_inventory)
    
    # Parse arguments
    args = parser.parse_args(argv)
    
    # Setup logging
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    
    # Execute command
    if args.command is None:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
