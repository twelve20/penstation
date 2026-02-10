"""WebSocket manager for real-time log streaming and alerts."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Set

from fastapi import WebSocket

logger = logging.getLogger("penstation.ws")


class ConnectionManager:
    """Manages WebSocket connections for logs and alerts."""

    def __init__(self):
        self.log_connections: Set[WebSocket] = set()
        self.alert_connections: Set[WebSocket] = set()
        self._log_history: list[dict] = []
        self._max_history = 200

    async def connect_logs(self, ws: WebSocket):
        await ws.accept()
        self.log_connections.add(ws)
        # Send recent history
        for entry in self._log_history[-50:]:
            try:
                await ws.send_json(entry)
            except Exception:
                break

    async def connect_alerts(self, ws: WebSocket):
        await ws.accept()
        self.alert_connections.add(ws)

    def disconnect_logs(self, ws: WebSocket):
        self.log_connections.discard(ws)

    def disconnect_alerts(self, ws: WebSocket):
        self.alert_connections.discard(ws)

    async def broadcast_log(self, level: str, message: str):
        entry = {
            "type": "log",
            "level": level,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._log_history.append(entry)
        if len(self._log_history) > self._max_history:
            self._log_history = self._log_history[-self._max_history:]

        dead = set()
        for ws in self.log_connections:
            try:
                await ws.send_json(entry)
            except Exception:
                dead.add(ws)
        self.log_connections -= dead

    async def broadcast_alert(self, alert_data: dict):
        entry = {
            "type": "alert",
            "timestamp": datetime.utcnow().isoformat(),
            **alert_data,
        }
        dead = set()
        for ws in self.alert_connections:
            try:
                await ws.send_json(entry)
            except Exception:
                dead.add(ws)
        self.alert_connections -= dead

        # Also send to log connections
        await self.broadcast_log(
            alert_data.get("severity", "INFO").upper(),
            alert_data.get("message", ""),
        )


manager = ConnectionManager()
