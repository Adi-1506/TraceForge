"""Scheduled retraining: keeps the behavioural baseline current as device habits change."""

import asyncio
import logging

from server.config import settings
from server.database import SessionLocal
from server.detection import ml_model

log = logging.getLogger("traceforge.scheduler")


def retrain_once() -> dict | None:
    with SessionLocal() as db:
        try:
            status = ml_model.train(db)
        except ValueError as exc:  # not enough history yet; try again next interval
            log.info("Scheduled retraining skipped: %s", exc)
            return None
    log.info("Scheduled retraining done on %s connections (%s excluded).", status["training_rows"], status["excluded_rows"])
    return status


async def retrain_loop() -> None:
    while True:
        await asyncio.sleep(settings.retrain_interval_hours * 3600)
        await asyncio.to_thread(retrain_once)
