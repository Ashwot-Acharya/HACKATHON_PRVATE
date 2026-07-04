"""
BankSentinel — Dependency Injection
=====================================
Singleton ``AgentRegistry`` that holds all loaded agents.

FastAPI route functions receive agents via ``Depends(get_registry)``.
Each agent load is wrapped in try/except so a missing model file
disables that one agent without crashing the whole server.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import Depends, HTTPException

logger = logging.getLogger(__name__)


class AgentRegistry:
    """
    Singleton holder for all loaded agent instances.

    Populated once during the FastAPI lifespan startup event.
    Individual agents may be ``None`` if their model files are missing.
    """

    def __init__(self):
        self.packet_agent = None
        self.flow_agent = None
        self.behavior_agent = None
        self.correlation_agent = None
        self.response_agent = None
        self.threat_engine = None
        self.startup_time: float = time.time()

    def load_all(self) -> dict[str, bool]:
        """
        Load every agent, returning a dict of agent_name → loaded_ok.

        Never raises — each agent failure is logged and the agent
        is left as ``None``.
        """
        status: dict[str, bool] = {}

        # ── Threat Intelligence Engine ────────────────────────────────
        try:
            from intel.threat_feed import threat_engine
            threat_engine.start()
            self.threat_engine = threat_engine
            status["threat_intel"] = True
            logger.info("[OK] ThreatIntelEngine started")
        except Exception as exc:
            logger.warning(f"[!!] ThreatIntelEngine failed: {exc}")
            status["threat_intel"] = False

        # ── Packet Agent (C4) ─────────────────────────────────────────
        try:
            from agents.packet_agent import PacketAgent
            self.packet_agent = PacketAgent.load(
                intel=self.threat_engine
            )
            status["packet_agent"] = True
            logger.info("[OK] PacketAgent loaded")
        except Exception as exc:
            logger.warning(f"[!!] PacketAgent failed: {exc}")
            status["packet_agent"] = False

        # ── Flow Agent (C2) ───────────────────────────────────────────
        try:
            from agents.flow_agent import FlowAgent
            self.flow_agent = FlowAgent.load()
            status["flow_agent"] = True
            logger.info("[OK] FlowAgent loaded")
        except Exception as exc:
            logger.warning(f"[!!] FlowAgent failed: {exc}")
            status["flow_agent"] = False

        # ── Behavior Agent (C1) ───────────────────────────────────────
        try:
            from agents.behaviour_agent import BehaviorAgent
            self.behavior_agent = BehaviorAgent.load()
            status["behavior_agent"] = True
            logger.info("[OK] BehaviorAgent loaded")
        except Exception as exc:
            logger.warning(f"[!!] BehaviorAgent failed: {exc}")
            status["behavior_agent"] = False

        # ── Correlation Agent (C3) — always succeeds (no model files)
        try:
            from agents.correlation_agent import CorrelationAgent
            self.correlation_agent = CorrelationAgent()
            status["correlation_agent"] = True
            logger.info("[OK] CorrelationAgent initialized")
        except Exception as exc:
            logger.warning(f"[!!] CorrelationAgent failed: {exc}")
            status["correlation_agent"] = False

        # ── Response Agent — always succeeds (just needs SQLite)
        try:
            from agents.response_agent import ResponseAgent
            self.response_agent = ResponseAgent()
            status["response_agent"] = True
            logger.info("[OK] ResponseAgent initialized")
        except Exception as exc:
            logger.warning(f"[!!] ResponseAgent failed: {exc}")
            status["response_agent"] = False

        return status

    def shutdown(self) -> None:
        """Stop background threads (threat feed refresh)."""
        if self.threat_engine is not None:
            try:
                self.threat_engine.stop()
                logger.info("ThreatIntelEngine stopped.")
            except Exception as exc:
                logger.warning(f"Error stopping ThreatIntelEngine: {exc}")

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.startup_time


# ── Module-level singleton ────────────────────────────────────────────────────
_registry: Optional[AgentRegistry] = None


def init_registry() -> AgentRegistry:
    """Create and populate the global registry. Called once at startup."""
    global _registry
    _registry = AgentRegistry()
    _registry.load_all()
    return _registry


def shutdown_registry() -> None:
    """Shut down the global registry. Called once at shutdown."""
    global _registry
    if _registry is not None:
        _registry.shutdown()


def get_registry() -> AgentRegistry:
    """FastAPI dependency — returns the global AgentRegistry."""
    if _registry is None:
        raise HTTPException(
            status_code=503,
            detail="Server is still starting up. Try again shortly.",
        )
    return _registry
