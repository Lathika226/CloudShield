"""
logger.py — Structured WAF event logger with in-memory stats.
"""

import os
import time
from datetime import datetime
from threading import Lock
from typing import List, Dict, Tuple


class WAFLogger:
    """
    Logs WAF events to a file and tracks aggregate stats in memory.

    Log line format (tab-separated):
        ISO_TIMESTAMP  IP  VERDICT  RISK_SCORE  PAYLOAD  REASON
    """

    def __init__(self, filepath: str = "logs.txt"):
        self.filepath = filepath
        self._lock = Lock()
        self._stats = {'total': 0, 'blocked': 0, 'allowed': 0, 'rate_limited': 0}
        self._load_existing_stats()

    # ── Public API ──────────────────────────────────────────────────────────

    def log_event(
        self,
        ip: str,
        payload: str,
        verdict: str,          # 'BLOCKED' | 'ALLOWED' | 'RATE_LIMITED'
        reason: str = "",
        risk_score: int = 0,
    ) -> None:
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        # Sanitise payload for log line (strip tabs/newlines)
        safe_payload = payload.replace('\t', ' ').replace('\n', ' ')[:300]
        line = f"{ts}\t{ip}\t{verdict}\t{risk_score}\t{safe_payload}\t{reason}\n"

        with self._lock:
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(line)
            self._stats['total'] += 1
            key = verdict.lower()
            if key in self._stats:
                self._stats[key] += 1

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def get_recent(self, n: int = 50) -> Tuple[str, List[Dict]]:
        """
        Returns (raw_log_tail, parsed_rows) for the last n lines.
        """
        if not os.path.exists(self.filepath):
            return "", []

        with self._lock:
            with open(self.filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

        recent = lines[-n:]
        raw = "".join(recent)

        rows = []
        for line in reversed(recent):
            parts = line.strip().split('\t')
            if len(parts) >= 5:
                rows.append({
                    'time':    parts[0],
                    'ip':      parts[1],
                    'verdict': parts[2],
                    'score':   parts[3],
                    'payload': parts[4][:120],
                    'reason':  parts[5] if len(parts) > 5 else '',
                })

        return raw, rows

    # ── Internal ────────────────────────────────────────────────────────────

    def _load_existing_stats(self) -> None:
        """Rebuild stats counters from an existing log file on startup."""
        if not os.path.exists(self.filepath):
            return
        with open(self.filepath, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) < 3:
                    continue
                self._stats['total'] += 1
                verdict = parts[2].lower()
                if verdict in self._stats:
                    self._stats[verdict] += 1
