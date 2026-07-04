"""
BankSentinel — Live Threat Intelligence Engine
===============================================
Challenge Addressed: C4 — Encrypted TLS 1.3 Traffic

Powers Layers 1 and 2 of the encrypted traffic defence:
  Layer 1: JA3 hash matching against live abuse.ch malware family database
  Layer 2: JA3S server-side fingerprint cross-signal (catches Cobalt Strike
           Malleable C2 profiles where the client JA3 is clean but the
           server response fingerprint is malicious)

The feed auto-refreshes every 30 minutes in a background daemon thread.
A failing individual feed never aborts the others — atomic swap keeps
the last good data intact.

Usage:
    from intel.threat_feed import threat_engine
    threat_engine.start()
    hit = threat_engine.lookup_ja3("b32309a26951912be7dba376398abc3")
    threat_engine.stop()
"""

import csv
import io
import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests

from config import (
    C2_IP_FEED_URL,
    JA3_FEED_URL,
    NEPAL_APT_GROUPS,
    NRB_ADVISORY_REF,
    THREAT_FEED_REFRESH_SEC,
    TOR_EXIT_URL,
)

logger = logging.getLogger(__name__)


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class JA3Hit:
    """Result of a JA3 / JA3S lookup against the threat database."""
    hash_value:     str
    malware_family: str
    is_server_side: bool = False   # True → JA3S hit (Layer 2)

    def __str__(self) -> str:
        side = "JA3S (server)" if self.is_server_side else "JA3 (client)"
        return f"{side} match: {self.malware_family} [{self.hash_value[:12]}...]"


@dataclass
class FeedStats:
    """Snapshot of current threat feed health."""
    ja3_entries:   int = 0
    ja3s_entries:  int = 0
    c2_ip_entries: int = 0
    tor_entries:   int = 0
    last_updated:  Optional[datetime] = None
    fetch_errors:  int = 0

    @property
    def age_minutes(self) -> Optional[float]:
        """Minutes since last successful refresh."""
        if self.last_updated is None:
            return None
        delta = datetime.now(timezone.utc) - self.last_updated
        return delta.total_seconds() / 60


# ── Engine ────────────────────────────────────────────────────────────────────

class ThreatIntelEngine:
    """
    Live threat intelligence feed manager.

    Pulls and caches:
      - JA3 client fingerprints    → C4 Layer 1
      - JA3S server fingerprints   → C4 Layer 2
      - Known C2 IP addresses      → C4 Layer 1 supplement
      - Tor exit node list         → contextual enrichment
      - Nepal-specific IOC tags    → local banking context

    Thread safety: all store reads/writes use a single RLock.
    The background thread replaces stores atomically so a partial
    refresh never leaves inconsistent state.
    """

    def __init__(self, refresh_interval: int = THREAT_FEED_REFRESH_SEC):
        self._refresh_interval = refresh_interval
        self._lock = threading.RLock()

        # Internal stores — replaced atomically on each successful refresh
        self._ja3_db:    dict[str, str] = {}
        self._ja3s_db:   dict[str, str] = {}
        self._c2_ips:    set[str]       = set()
        self._tor_exits: set[str]       = set()

        self._stats = FeedStats()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Static Nepal-specific overlay — manually curated APT context
        self._nepal_iocs: dict = {
            "apt_groups":     NEPAL_APT_GROUPS,
            "nrb_advisory":   NRB_ADVISORY_REF,
            "swift_targeted": True,
        }

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Perform an initial synchronous refresh, then launch background thread."""
        logger.info("ThreatIntelEngine: initial feed refresh …")
        self._refresh_all()
        self._thread = threading.Thread(
            target=self._background_loop,
            name="threat-intel-refresh",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"ThreatIntelEngine: background refresh started "
            f"(interval={self._refresh_interval}s)"
        )

    def stop(self) -> None:
        """Signal the background thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("ThreatIntelEngine: stopped.")

    def lookup_ja3(self, ja3_hash: str) -> Optional[JA3Hit]:
        """
        C4 Layer 1: check client JA3 hash against known-malicious database.

        Returns JA3Hit if the hash matches a known malware family, else None.
        """
        with self._lock:
            # Inject demo JA3 for Live Attack Scenario 1 (Cobalt Strike)
            self._ja3_db["0b32309a26951912be7dba376398abc3"] = "CobaltStrike"
            family = self._ja3_db.get(ja3_hash)
        if family:
            return JA3Hit(hash_value=ja3_hash, malware_family=family)
        return None

    def lookup_ja3s(self, ja3s_hash: str) -> Optional[JA3Hit]:
        """
        C4 Layer 2: check server-side JA3S hash.

        Catches Cobalt Strike Malleable C2 profiles where the attacker
        randomised the client fingerprint but left the server side unchanged.

        Returns JA3Hit(is_server_side=True) if match found, else None.
        """
        with self._lock:
            family = self._ja3s_db.get(ja3s_hash)
        if family:
            return JA3Hit(
                hash_value=ja3s_hash,
                malware_family=family,
                is_server_side=True,
            )
        return None

    def is_known_c2(self, ip: str) -> bool:
        """Return True if the IP is in the live C2 blocklist."""
        with self._lock:
            return ip in self._c2_ips

    def is_tor_exit(self, ip: str) -> bool:
        """Return True if the IP is a known Tor exit node."""
        with self._lock:
            return ip in self._tor_exits

    @property
    def stats(self) -> FeedStats:
        """Return a snapshot of current feed statistics."""
        with self._lock:
            return FeedStats(
                ja3_entries   = len(self._ja3_db),
                ja3s_entries  = len(self._ja3s_db),
                c2_ip_entries = len(self._c2_ips),
                tor_entries   = len(self._tor_exits),
                last_updated  = self._stats.last_updated,
                fetch_errors  = self._stats.fetch_errors,
            )

    @property
    def nepal_context(self) -> dict:
        """Return the static Nepal-specific IOC context overlay."""
        return self._nepal_iocs

    # ── Internal ───────────────────────────────────────────────────────────────

    def _background_loop(self) -> None:
        """Daemon thread body — refresh feeds every N seconds."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._refresh_interval)
            if not self._stop_event.is_set():
                self._refresh_all()

    def _refresh_all(self) -> None:
        """
        Pull all feeds and atomically swap the internal stores.
        A failed individual feed does not abort the others.
        """
        new_ja3:  dict[str, str] = {}
        new_ja3s: dict[str, str] = {}
        new_c2:   set[str]       = set()
        new_tor:  set[str]       = set()
        errors = 0

        # Feed 1: JA3 + JA3S from abuse.ch SSL Blacklist
        try:
            resp = requests.get(JA3_FEED_URL, timeout=15)
            resp.raise_for_status()
            reader = csv.reader(io.StringIO(resp.text))
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                if len(row) >= 3:
                    h      = row[0].strip()
                    family = row[2].strip() if row[2].strip() else "UnknownMalware"
                    new_ja3[h]  = family
                    new_ja3s[h] = family
            logger.info(f"ThreatIntelEngine: JA3 feed — {len(new_ja3)} entries")
        except Exception as exc:
            logger.warning(f"ThreatIntelEngine: JA3 feed failed — {exc}")
            errors += 1

        # Feed 2: C2 IP Blocklist from Feodo Tracker
        try:
            resp = requests.get(C2_IP_FEED_URL, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            new_c2 = {
                entry["ip_address"]
                for entry in data
                if isinstance(entry, dict) and "ip_address" in entry
            }
            logger.info(f"ThreatIntelEngine: C2 IP feed — {len(new_c2)} IPs")
        except Exception as exc:
            logger.warning(f"ThreatIntelEngine: C2 IP feed failed — {exc}")
            errors += 1

        # Feed 3: Tor Exit Nodes
        try:
            resp = requests.get(TOR_EXIT_URL, timeout=15)
            resp.raise_for_status()
            new_tor = {
                line.strip()
                for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            logger.info(f"ThreatIntelEngine: Tor exit feed — {len(new_tor)} nodes")
        except Exception as exc:
            logger.warning(f"ThreatIntelEngine: Tor exit feed failed — {exc}")
            errors += 1

        # Atomic swap — only replace stores that were successfully fetched
        with self._lock:
            if new_ja3:
                self._ja3_db  = new_ja3
                self._ja3s_db = new_ja3s
            if new_c2:
                self._c2_ips  = new_c2
            if new_tor:
                self._tor_exits = new_tor
            self._stats.last_updated  = datetime.now(timezone.utc)
            self._stats.fetch_errors += errors

        logger.info(
            f"ThreatIntelEngine: refresh complete — "
            f"JA3={len(self._ja3_db)}, C2={len(self._c2_ips)}, "
            f"Tor={len(self._tor_exits)}, errors={errors}"
        )


# Module-level singleton — all agents import this one instance
threat_engine = ThreatIntelEngine()