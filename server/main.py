from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server import models  # noqa: F401  (registers tables on Base.metadata)
from server.database import Base, engine
from server.routers import anomalies, devices, events, incidents, risk, system


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="TraceForge", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (events, devices, anomalies, risk, incidents, system):
    app.include_router(r.router)


@app.get("/health")
def health():
    return {"status": "ok"}
