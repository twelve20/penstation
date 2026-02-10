"""PENSTATION — Autonomous Network Security Station."""

import asyncio
import logging
import signal
import sys

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from config import settings
from db.database import init_db
from api.routes import router
from api.ws import manager
from scanner.scheduler import (
    set_alert_callback,
    set_log_callback,
    start_scheduler,
    stop_scheduler,
)

# ── Logging ────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"{settings.LOGS_DIR}/penstation.log"),
    ],
)
logger = logging.getLogger("penstation")

# ── App ────────────────────────────────────────────────────────────

app = FastAPI(title="PENSTATION", version="1.0.0")

app.include_router(router)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def index():
    return FileResponse("static/index.html")


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket):
    await manager.connect_logs(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_logs(ws)


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await manager.connect_alerts(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect_alerts(ws)


# ── Lifecycle ──────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    logger.info("PENSTATION starting up...")
    await init_db()
    set_log_callback(manager.broadcast_log)
    set_alert_callback(manager.broadcast_alert)
    start_scheduler()
    logger.info("PENSTATION ready — http://%s:%s", settings.HOST, settings.PORT)


@app.on_event("shutdown")
async def shutdown():
    logger.info("PENSTATION shutting down...")
    stop_scheduler()


# ── Graceful shutdown ──────────────────────────────────────────────

def _handle_signal(sig, frame):
    logger.info("Received signal %s, shutting down...", sig)
    stop_scheduler()
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="info",
    )
