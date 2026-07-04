"""
BankSentinel — FastAPI Application
====================================
Main entry point for the BankSentinel IDS REST API.

Startup lifecycle:
  1. Load all ML models and analytical agents
  2. Start threat intelligence feed background refresh
  3. Initialize Correlation Agent (BBN + suppression engine)
  4. Initialize Response Agent (SQLite audit DB)

Shutdown lifecycle:
  1. Stop threat feed background thread

Run with:
    uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
"""

from contextlib import asynccontextmanager
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.dependencies import init_registry, shutdown_registry

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  [%(name)s]  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("banksentinel.api")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan — load agents on startup, cleanup on shutdown.
    """
    logger.info("=" * 60)
    logger.info("  BankSentinel API -- Starting up ...")
    logger.info("=" * 60)

    registry = init_registry()

    loaded = {
        k: v
        for k, v in {
            "Packet Agent (C4)": registry.packet_agent is not None,
            "Flow Agent (C2)": registry.flow_agent is not None,
            "Behavior Agent (C1)": registry.behavior_agent is not None,
            "Correlation Agent (C3)": registry.correlation_agent is not None,
            "Response Agent": registry.response_agent is not None,
            "Threat Intel": registry.threat_engine is not None,
        }.items()
    }
    for name, ok in loaded.items():
        status = "[OK] loaded" if ok else "[--] unavailable"
        logger.info(f"  {name:25s} -- {status}")

    logger.info("=" * 60)
    logger.info("  BankSentinel API -- Ready to serve requests")
    logger.info("=" * 60)

    import asyncio
    async def cleanup_loop():
        while True:
            await asyncio.sleep(3600)  # Run every hour
            if registry.correlation_agent is not None:
                cleared = registry.correlation_agent.cleanup_caches(3600.0)
                logger.info(f"CorrelationAgent cache cleanup: {cleared} expired alerts removed.")

    cleanup_task = asyncio.create_task(cleanup_loop())

    yield

    logger.info("BankSentinel API -- Shutting down ...")
    cleanup_task.cancel()
    shutdown_registry()
    logger.info("BankSentinel API -- Shutdown complete.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="BankSentinel IDS API",
    description=(
        "Five-Agent AI Intrusion Detection System for "
        "Real-Time Threat Correlation in Nepalese Banking Networks.\n\n"
        "**Challenges Addressed:**\n"
        "- **C1** Zero-Day Attacks (Behavior Agent — BiLSTM autoencoder)\n"
        "- **C2** High-Volume False Positives (Flow Agent — Context-aware Isolation Forest)\n"
        "- **C3** Alert Fatigue (Correlation Agent — Bayesian Fusion & 4-layer Suppression)\n"
        "- **C4** Encrypted TLS 1.3 Traffic (Packet Agent — JA3/JA3S + Beacon IAT)\n"
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
from api.routes.health import router as health_router
from api.routes.packet import router as packet_router
from api.routes.flow import router as flow_router
from api.routes.behavior import router as behavior_router
from api.routes.correlation import router as correlation_router
from api.routes.pipeline import router as pipeline_router
from api.routes.response import router as response_router
from api.routes.threat_intel import router as threat_intel_router
from api.routes.stats import router as stats_router
from api.routes.redteam import router as redteam_router
from api.routes.federation import router as federation_router
from api.routes.dashboard_stats import router as dashboard_stats_router
from api.routes.websocket import router as websocket_router
from api.routes.auth import router as auth_router

app.include_router(health_router)
app.include_router(packet_router)
app.include_router(flow_router)
app.include_router(behavior_router)
app.include_router(correlation_router)
app.include_router(pipeline_router)
app.include_router(response_router)
app.include_router(threat_intel_router)
app.include_router(stats_router)
app.include_router(redteam_router)
app.include_router(federation_router)
app.include_router(dashboard_stats_router)
app.include_router(websocket_router)
app.include_router(auth_router)


# ── Root ──────────────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
def root():
    """API root — returns service identity and documentation link."""
    return {
        "service": "BankSentinel IDS API",
        "version": "2.0.0",
        "description": (
            "Five-Agent AI Intrusion Detection System for "
            "Nepalese Banking Networks"
        ),
        "docs": "/docs",
        "challenges": {
            "C1": "Zero-Day Attacks (Behavior Agent)",
            "C2": "False Positive Reduction (Flow Agent)",
            "C3": "Alert Fatigue Suppression (Correlation Agent)",
            "C4": "Encrypted TLS Detection (Packet Agent)",
        },
    }