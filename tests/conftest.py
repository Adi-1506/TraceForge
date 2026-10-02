import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="traceforge-tests-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from server.database import Base, engine  # noqa: E402
from server.detection import ml_model  # noqa: E402
from server.main import app  # noqa: E402


@pytest.fixture()
def client():
    ml_model.MODEL_PATH = _tmp / "iforest.joblib"
    ml_model.MODEL_PATH.unlink(missing_ok=True)
    ml_model._bundle = None
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c


HID = {"pnp_class": "HIDClass", "service": "HidUsb", "interface_classes": [3], "endpoint_count": 2}
MASS = {"pnp_class": "USB", "service": "USBSTOR", "interface_classes": [8], "endpoint_count": 2}


def make_event(machine="PC-1", vid="0951", pid="1666", serial="ABC123456", dtype="USB Mass Storage Device",
               kind="connect", ts="2026-09-01T10:00:00Z", descriptor=MASS):
    return {
        "machine_hostname": machine,
        "vendor_id": vid,
        "product_id": pid,
        "serial_number": serial,
        "device_type": dtype,
        "event_type": kind,
        "timestamp": ts,
        "descriptor": descriptor,
    }
