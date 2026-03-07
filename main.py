#!/usr/bin/env python3
"""
SOC Log Generator - Main Entry Point

This module serves as the primary entry point for the SOC Log Generator.
It delegates to the CLI module for command-line interface functionality.

Usage:
    python -m soc_log_generator
    soc-log-generator
    slg
"""

import sys
from .cli import main

def entry_point():
    """Entry point for console scripts."""
    sys.exit(main())

if __name__ == '__main__':
    entry_point()
