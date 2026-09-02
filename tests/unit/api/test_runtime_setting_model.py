import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.models import RuntimeSetting  # noqa: E402


def test_table_shape():
    cols = RuntimeSetting.__table__.columns
    assert RuntimeSetting.__tablename__ == "runtime_settings"
    assert cols["key"].primary_key
    assert cols["value"].type.__class__.__name__ == "JSONB"
    assert cols["is_secret"].default.arg is False
    assert cols["updated_by"].nullable is True
