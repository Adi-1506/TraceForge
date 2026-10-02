# TraceForge

USB forensic investigation and device trust analysis. A live agent on each monitored machine reports USB connect/disconnect events to a central server, which profiles devices, detects identity anomalies (rules + explainable ML), scores risk, and groups related suspicious events into incidents. A React dashboard shows it all.

```
agent (Windows, WMI) --POST /events/ingest--> FastAPI --> PostgreSQL
                                                |-- rules.py        identity / descriptor / source-machine checks
                                                |-- ml_model.py     Isolation Forest + SHAP explanations
                                                |-- risk.py         weighted score with recorded reasoning
                                                '-- correlate.py    incidents (same device + machine, 30 min window)
React dashboard <-- REST JSON (devices, timelines, incidents, anomalies)
```

## Quick start

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env          # edit if needed
```

**Database** - either PostgreSQL via Docker (Docker Desktop must be running):

```bash
docker compose up -d
```

or no Docker: set `DATABASE_URL=sqlite:///./traceforge.db` in `.env`.

**Server + demo data**

```bash
.venv\Scripts\python -m server.seed_synthetic_data --reset
.venv\Scripts\uvicorn server.main:app --reload
```

The seeder replays six weeks of normal usage, trains the ML model on it, then runs five planted attack scenarios through the live pipeline (type-switching BadUSB device, serial cloning, behavioural burst, missing serial, plain unknown device). API docs: http://localhost:8000/docs

**Dashboard**

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Set `VITE_API_URL` if the server is not on `localhost:8000`.

**Live agent** (on each monitored Windows machine; `TRACEFORGE_SERVER` defaults to `http://localhost:8000`)

```bash
.venv\Scripts\python agent\agent.py
```

Plug in a USB device and it appears in the dashboard within a few seconds.

**Tests**

```bash
.venv\Scripts\python -m pytest
```

## How detection works

| Layer | Finding | Weight |
| --- | --- | --- |
| rule | `unknown_device` - never seen before | 25 |
| rule | `device_type_mismatch` - same identity, different declared type | 40 |
| rule | `serial_reuse_across_models` - serial belongs to a different VID/PID | 40 |
| rule | `descriptor_mismatch` - descriptor structure differs from the recorded profile | 35 |
| rule | `missing_serial` / `serial_format_mismatch` - differs from other units of the same model | 30 |
| rule | `new_source_machine` - device never connected to this machine before | 15 |
| ML | `behavioural_outlier` - Isolation Forest on timing, hour, frequency, machine count | 15-45 |

Score = 5 baseline + sum of weights, capped at 100. Levels: low < 25 <= medium < 50 <= high < 75 <= critical. Every factor is stored with its explanation, and ML findings carry the SHAP drivers (e.g. "inter-event timing was 20s vs a typical 69,836s"). A connection scoring 40+ opens an incident; later events for the same device and machine within 30 minutes join it. Disconnects inherit the score of the connection they close.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/events/ingest` | agent pushes a USB event |
| GET | `/devices`, `/devices/{id}` | profiles with latest risk |
| GET | `/devices/{id}/timeline` | chronological events with anomalies |
| GET | `/anomalies?device_id=&source=` | flagged anomalies with explanations |
| GET | `/risk-scores/{device_id}` | score history with reasoning |
| GET | `/incidents`, `/incidents/{id}` | correlated incidents |
| GET | `/stats`, `/ml/status` | dashboard counters, model state |
| POST | `/ml/train` | retrain the model on stored history |

## Known limits

- The agent polls WMI every 2 s (no kernel-level hooks) and runs on Windows only.
- Real devices report `pnp_class` and `service` in their descriptor; `interface_classes` and `endpoint_count` come from the synthetic dataset only (reading them live needs a libusb-level library).
- No authentication on the API; intended for a lab network.
- The ML model is trained on whatever history exists; retrain with `POST /ml/train` once real data accumulates.
