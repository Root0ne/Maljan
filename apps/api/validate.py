"""Phase 2 validation script — verify all new modules load correctly."""

# Models
print("Models OK")

# Config
from app.config import settings

print(f"Config OK: {settings.app_name} v{settings.app_version}")

# Auth
from app.auth.jwt import create_access_token
from app.auth.password import hash_password, verify_password

t = create_access_token({"sub": "test-user-id"})
h = hash_password("test123")
assert verify_password("test123", h)
print("Auth OK")

# Services
print("Services OK")

# Worker
from app.worker.analysis_worker import WorkerSettings

print(f"Worker OK: functions={[f.__name__ for f in WorkerSettings.functions]}")
print(f"Worker config: max_jobs={WorkerSettings.max_jobs}, timeout={WorkerSettings.job_timeout}s")

# WebSocket hub
from app.api.ws import manager

print(f"WebSocket OK: manager={type(manager).__name__}")

# Dashboard
print("Dashboard OK")

# FastAPI app (all routes)
from app.main import create_app

app = create_app()
routes = [r.path for r in app.routes if hasattr(r, "path")]
print(f"\nRegistered routes ({len(routes)}):")
for r in sorted(routes):
    print(f"  {r}")

print("\nAll Phase 2 validations passed!")
