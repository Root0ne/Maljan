from app.models import RuntimeSetting


def test_table_shape():
    cols = RuntimeSetting.__table__.columns
    assert RuntimeSetting.__tablename__ == "runtime_settings"
    assert cols["key"].primary_key
    assert cols["value"].type.__class__.__name__ == "JSONB"
    assert cols["is_secret"].default.arg is False
    assert cols["updated_by"].nullable is True
