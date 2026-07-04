import logging
import requests
from pathlib import Path
from typing import Optional
import json

from config import DISCORD_WEBHOOK_URL
from agents.correlation_agent import CorrelationResult

logger = logging.getLogger(__name__)

class NotificationAgent:
    """
    Dispatches rich notifications to the SOC via external channels (e.g., Discord).
    """

    def __init__(self, webhook_url: Optional[str] = DISCORD_WEBHOOK_URL):
        self.webhook_url = webhook_url

    def send_alert(self, alert: CorrelationResult, pdf_path: Optional[Path] = None, stix_path: Optional[Path] = None) -> bool:
        """
        Alert dispatch has been disabled by user request.
        Nothing will be sent to Discord or external webhooks.
        """
        logger.info(f"NotificationAgent: Alert dispatch is explicitly disabled. Skipping alert {alert.record_id}.")
        return False
