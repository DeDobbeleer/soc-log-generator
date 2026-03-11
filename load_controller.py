#!/usr/bin/env python3
"""
Load Controller - Advanced Generation Modes

Imported from nxlog_simulator.py
Features:
- RAMP Mode: Progressive rate increase
- BURST Mode: Random traffic spikes
- CONSTANT Mode: Fixed rate
"""

import random
import time
import threading
from typing import List, Optional, Callable
from datetime import datetime

from core import RateLimiter, LogEvent, OutputHandler


class LoadController:
    """
    Load controller for advanced generation modes.
    
    Supported modes:
    - constant: Fixed rate
    - ramp: Progressive increase (start_eps → max_eps)
    - burst: Random traffic spikes
    """
    
    def __init__(self, start_eps: float, max_eps: float, ramp_duration: int, mode: str = "ramp"):
        """
        Initialize the controller.
        
        Args:
            start_eps: Starting EPS
            max_eps: Maximum EPS
            ramp_duration: Ramp duration in seconds
            mode: constant, ramp, or burst
        """
        self.start_eps = start_eps
        self.max_eps = max_eps
        self.ramp_duration = ramp_duration
        self.mode = mode
        self.start_time = time.time()
        self.current_eps = start_eps
        
    def update(self) -> float:
        """
        Update current rate according to mode.
        
        Returns:
            Current EPS target
        """
        elapsed = time.time() - self.start_time
        
        if self.mode == "constant":
            return self.max_eps
            
        elif self.mode == "ramp":
            if elapsed >= self.ramp_duration:
                return self.max_eps
            progress = elapsed / self.ramp_duration
            return self.start_eps + (self.max_eps - self.start_eps) * progress
            
        elif self.mode == "burst":
            # Random spikes every 10-30 seconds
            spike_interval = random.randint(10, 30)
            if int(elapsed) % spike_interval == 0:
                return self.max_eps * random.uniform(1.5, 3.0)
            return self.start_eps + (self.max_eps - self.start_eps) * 0.5
            
        return self.current_eps


class StatsReporter:
    """
    Real-time generation statistics display.
    
    Displays:
    - Generated events
    - Current EPS
    - Active output handlers
    - Errors
    """
    
    def __init__(self, outputs: List[OutputHandler], controller: LoadController, interval: int = 10):
        """
        Initialize the reporter.
        
        Args:
            outputs: List of output handlers
            controller: Load controller
            interval: Display interval in seconds
        """
        self.outputs = outputs
        self.controller = controller
        self.interval = interval
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.stats = {"generated": 0, "errors": 0, "start_time": time.time()}
        
    def start(self):
        """Start the reporter."""
        self.running = True
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
        
    def _run(self):
        """Main reporter loop."""
        while self.running:
            time.sleep(self.interval)
            self._print_stats()
            
    def _print_stats(self):
        """Display statistics."""
        elapsed = time.time() - self.stats["start_time"]
        eps = self.stats["generated"] / elapsed if elapsed > 0 else 0
        target_eps = self.controller.current_eps
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Stats:")
        print(f"  Generated: {self.stats['generated']:,} events")
        print(f"  Rate: {eps:.1f} EPS (target: {target_eps:.1f})")
        print(f"  Errors: {self.stats['errors']}")
        print(f"  Active outputs: {len(self.outputs)}")
        
    def update_stats(self, generated: int, errors: int):
        """Update statistics (called by generator)."""
        self.stats["generated"] += generated
        self.stats["errors"] += errors
        
    def stop(self):
        """Stop the reporter."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)


class MultiClientGenerator:
    """
    Generator with multiple parallel clients.
    
    Allows parallel generation for higher EPS.
    """
    
    def __init__(self, generator_fn: Callable[[], LogEvent], client_count: int = 1):
        """
        Initialize multi-client generator.
        
        Args:
            generator_fn: Event generation function
            client_count: Number of parallel clients
        """
        self.generator_fn = generator_fn
        self.client_count = client_count
        self.threads: List[threading.Thread] = []
        self.running = False
        
    def start(self, duration: Optional[int] = None):
        """
        Start generation.
        
        Args:
            duration: Duration in seconds (None = infinite)
        """
        self.running = True
        
        def worker():
            start = time.time()
            while self.running:
                if duration and (time.time() - start) >= duration:
                    break
                event = self.generator_fn()
                # Event is handled by caller
                
        for i in range(self.client_count):
            t = threading.Thread(target=worker, name=f"Generator-{i}")
            t.daemon = True
            t.start()
            self.threads.append(t)
            
    def stop(self):
        """Stop generation."""
        self.running = False
        for t in self.threads:
            t.join(timeout=2.0)


# Legacy compatibility
SyslogClient = None  # Now in core.py
LoadController = LoadController
StatsReporter = StatsReporter

__all__ = ['LoadController', 'StatsReporter', 'MultiClientGenerator']
