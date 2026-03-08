#!/usr/bin/env python3
"""
Stress Test Scenarios

Pre-defined stress test scenarios for different use cases.
"""

from dataclasses import dataclass
from typing import Dict, Any, List
from enum import Enum


class ScenarioType(Enum):
    """Types of stress scenarios."""
    BURST = "burst"
    SUSTAINED = "sustained"
    SPIKE = "spike"
    RAMP_UP = "ramp_up"
    RAMP_DOWN = "ramp_down"
    ENDURANCE = "endurance"
    SOAK = "soak"


@dataclass
class StressScenario:
    """Stress test scenario definition."""
    name: str
    scenario_type: ScenarioType
    description: str
    target_eps: float
    duration_seconds: float
    parameters: Dict[str, Any]
    expected_result: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "type": self.scenario_type.value,
            "description": self.description,
            "target_eps": self.target_eps,
            "duration_seconds": self.duration_seconds,
            "parameters": self.parameters,
            "expected_result": self.expected_result,
        }


# Pre-defined scenarios
class BurstScenario(StressScenario):
    """Sudden burst of traffic."""
    
    def __init__(self, base_eps: float = 100, burst_multiplier: float = 5.0):
        super().__init__(
            name="Traffic Burst",
            scenario_type=ScenarioType.BURST,
            description="Simulates sudden traffic spike (e.g., DDoS, batch job)",
            target_eps=base_eps * burst_multiplier,
            duration_seconds=60.0,
            parameters={
                "base_eps": base_eps,
                "burst_multiplier": burst_multiplier,
                "burst_duration": 20.0,
                "recovery_duration": 20.0,
            },
            expected_result="System handles burst without errors, returns to baseline"
        )


class SustainedScenario(StressScenario):
    """Sustained high load."""
    
    def __init__(self, target_eps: float = 1000):
        super().__init__(
            name="Sustained Load",
            scenario_type=ScenarioType.SUSTAINED,
            description="Constant high load for extended period",
            target_eps=target_eps,
            duration_seconds=300.0,
            parameters={
                "target_eps": target_eps,
                "warmup_seconds": 10.0,
            },
            expected_result="Stable EPS with low variance, no memory leaks"
        )


class SpikeScenario(StressScenario):
    """Multiple rapid spikes."""
    
    def __init__(self, base_eps: float = 50, spike_count: int = 10):
        super().__init__(
            name="Rapid Spikes",
            scenario_type=ScenarioType.SPIKE,
            description="Multiple rapid up/down variations",
            target_eps=base_eps * 4,
            duration_seconds=120.0,
            parameters={
                "base_eps": base_eps,
                "spike_eps": base_eps * 4,
                "spike_count": spike_count,
                "spike_duration": 5.0,
            },
            expected_result="Responsive to rapid changes, no lag buildup"
        )


class RampUpScenario(StressScenario):
    """Gradual ramp up."""
    
    def __init__(self, start_eps: float = 10, end_eps: float = 1000):
        super().__init__(
            name="Ramp Up",
            scenario_type=ScenarioType.RAMP_UP,
            description="Gradual increase to find breaking point",
            target_eps=(start_eps + end_eps) / 2,
            duration_seconds=300.0,
            parameters={
                "start_eps": start_eps,
                "end_eps": end_eps,
                "step_duration": 10.0,
            },
            expected_result="Smooth EPS increase, identify max sustainable rate"
        )


class RampDownScenario(StressScenario):
    """Gradual ramp down."""
    
    def __init__(self, start_eps: float = 1000, end_eps: float = 10):
        super().__init__(
            name="Ramp Down",
            scenario_type=ScenarioType.RAMP_DOWN,
            description="Gradual decrease, testing recovery",
            target_eps=(start_eps + end_eps) / 2,
            duration_seconds=300.0,
            parameters={
                "start_eps": start_eps,
                "end_eps": end_eps,
                "step_duration": 10.0,
            },
            expected_result="Graceful degradation, resources released"
        )


class EnduranceScenario(StressScenario):
    """Long-duration endurance test."""
    
    def __init__(self, target_eps: float = 500):
        super().__init__(
            name="Endurance Test",
            scenario_type=ScenarioType.ENDURANCE,
            description="Long-term stability test (1+ hour)",
            target_eps=target_eps,
            duration_seconds=3600.0,  # 1 hour
            parameters={
                "target_eps": target_eps,
                "sample_interval": 60.0,
            },
            expected_result="Stable performance over extended period, no degradation"
        )


class SoakScenario(StressScenario):
    """Memory leak detection test."""
    
    def __init__(self, target_eps: float = 100):
        super().__init__(
            name="Soak Test",
            scenario_type=ScenarioType.SOAK,
            description="Detect memory leaks over extended period",
            target_eps=target_eps,
            duration_seconds=7200.0,  # 2 hours
            parameters={
                "target_eps": target_eps,
                "memory_sample_interval": 300.0,  # Every 5 minutes
                "max_memory_growth_pct": 20.0,
            },
            expected_result="Memory usage stable, no leaks detected"
        )


# Scenario registry
SCENARIO_REGISTRY = {
    "burst": BurstScenario,
    "sustained": SustainedScenario,
    "spike": SpikeScenario,
    "ramp_up": RampUpScenario,
    "ramp_down": RampDownScenario,
    "endurance": EnduranceScenario,
    "soak": SoakScenario,
}


def get_scenario(name: str, **kwargs) -> StressScenario:
    """
    Get scenario by name.
    
    Args:
        name: Scenario name
        **kwargs: Scenario parameters
        
    Returns:
        StressScenario instance
    """
    scenario_class = SCENARIO_REGISTRY.get(name.lower())
    if scenario_class:
        return scenario_class(**kwargs)
    raise ValueError(f"Unknown scenario: {name}")


def list_scenarios() -> List[Dict[str, str]]:
    """List all available scenarios."""
    return [
        {
            "name": name,
            "type": scenario_class.__name__,
            "description": scenario_class.__doc__ or ""
        }
        for name, scenario_class in SCENARIO_REGISTRY.items()
    ]


if __name__ == "__main__":
    print("Available Stress Test Scenarios:")
    print("=" * 60)
    for scenario_info in list_scenarios():
        print(f"\n{scenario_info['name']}:")
        print(f"  Type: {scenario_info['type']}")
        print(f"  Description: {scenario_info['description']}")
