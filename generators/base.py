#!/usr/bin/env python3
"""
Base Generator Classes

Provides abstract base classes for all log generators.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

try:
    from ..core import LogEvent, AssetInventory, TimeProfile
except (ImportError, ValueError):
    from core import LogEvent, AssetInventory, TimeProfile


class BaseGenerator(ABC):
    """
    Abstract base class for all log generators.
    
    All generators must inherit from this class and implement
    the generate_event() method.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the generator.
        
        Args:
            config: Configuration dictionary with generator settings
        """
        self.config = config
        self.source_type = config.get('type', 'unknown')
        self.enabled = config.get('enabled', True)
        self.weight = config.get('weight', 1.0)
        self.time_profile = TimeProfile(
            base_eps=config.get('eps', 100),
            business_hours_multiplier=config.get('business_hours_mult', 2.0)
        )
    
    @abstractmethod
    def generate_event(self) -> LogEvent:
        """
        Generate a single log event.
        
        Returns:
            LogEvent instance
        """
        pass
    
    def get_eps(self) -> float:
        """
        Get current events per second target.
        
        Returns:
            Current EPS based on time profile and weight
        """
        return self.time_profile.get_current_eps() * self.weight
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(type={self.source_type}, enabled={self.enabled})"
