from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EventIngest(BaseModel):
    machine_hostname: str
    vendor_id: str
    product_id: str
    serial_number: str | None = None
    device_type: str | None = None
    event_type: str  # "connect" | "disconnect"
    timestamp: datetime | None = None
    descriptor: dict | None = None


class EventOut(ORM):
    id: int
    device_id: int
    machine_id: int
    event_type: str
    timestamp: datetime


class IngestResult(BaseModel):
    event: EventOut
    is_new_device: bool
    risk_score: float
    risk_level: str
    incident_id: int | None = None


class AnomalyOut(ORM):
    id: int
    event_id: int
    source: str
    name: str
    weight: float
    explanation: str
    detail: dict | None = None


class RiskOut(ORM):
    event_id: int
    device_id: int
    score: float
    level: str
    reasoning: list
    computed_at: datetime


class TimelineEntry(BaseModel):
    event_id: int
    timestamp: datetime
    event_type: str
    machine_hostname: str
    risk_score: float | None = None
    risk_level: str | None = None
    anomalies: list[AnomalyOut] = []


class DeviceOut(BaseModel):
    id: int
    vendor_id: str
    product_id: str
    serial_number: str | None
    device_type: str | None
    first_seen: datetime
    last_seen: datetime | None
    event_count: int
    machine_count: int
    risk_score: float | None
    risk_level: str | None
    known: bool


class DeviceDetailOut(DeviceOut):
    descriptor_json: dict | None
    machines: list[str]


class IncidentOut(BaseModel):
    id: int
    device_id: int
    device_label: str
    machine_hostname: str
    start_time: datetime
    end_time: datetime
    max_score: float
    level: str
    status: str
    event_count: int


class IncidentDetailOut(IncidentOut):
    timeline: list[TimelineEntry]


class StatsOut(BaseModel):
    devices: int
    machines: int
    events: int
    anomalies: int
    open_incidents: int
    high_risk_devices: int
    ml_trained: bool
