"""Agent-related data models.

Design Reference: DR-9
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Agent:
    """Basic agent information returned after registration."""

    agent_id: str
    agent_name: str
    created_at: datetime


@dataclass
class AgentProfile:
    """Full agent profile with capabilities."""

    agent_id: str
    agent_name: str
    capabilities: list[str]
    created_at: datetime


@dataclass
class Reputation:
    """Agent reputation score."""

    agent_id: str
    score: float  # 0.0 to 1.0
    updated_at: datetime
