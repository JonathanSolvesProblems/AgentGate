"""Five deterministic stages plus one advisory sixth compose the AgentGate pipeline.

The verdict reads only the policy stage. Reasoning is advisory and never gates.
See pipeline.py for the fail-open / fail-closed split between advisory and
gating stages.
"""

from .blast_radius import BlastRadiusStage
from .cost import CostStage
from .injection import InjectionStage
from .pipeline import Pipeline, Stage, build_default_pipeline
from .policy import PolicyStage
from .reasoning import ReasoningStage

__all__ = [
    "BlastRadiusStage",
    "CostStage",
    "InjectionStage",
    "Pipeline",
    "PolicyStage",
    "ReasoningStage",
    "Stage",
    "build_default_pipeline",
]
