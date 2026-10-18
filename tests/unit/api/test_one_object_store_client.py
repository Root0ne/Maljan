"""Every reader and writer of the object store goes through one module.

The sample upload, the sandbox-report upload and read, the deletes, the health
probe and the worker's sample download build their client in
``app.services.object_store`` and create the bucket there: lazily, under the
configured name, and always with the anonymous-deny policy — the sandbox-report
upload used to create it without one.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import stat
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.config import settings
from app.services import object_store


class _Store:
    """A MinIO client double that remembers the calls and holds objects in memory."""

    def __init__(self, *, exists: bool = False, policy_error: Exception | None = None) -> None:
        self.exists = exists
        self.policy_error = policy_error
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.objects: dict[str, bytes] = {}

    def bucket_exists(self, bucket: str) -> bool:
        self.calls.append(("bucket_exists", (bucket,)))
        return self.exists

    def make_bucket(self, bucket: str) -> None:
        self.calls.append(("make_bucket", (bucket,)))
        self.exists = True

    def set_bucket_policy(self, bucket: str, policy: str) -> None:
        self.calls.append(("set_bucket_policy", (bucket, policy)))
        if self.policy_error is not None:
            raise self.policy_error

    def put_object(self, bucket: str, path: str, data: Any, length: int, content_type: str) -> None:
        self.calls.append(("put_object", (bucket, path, length, content_type)))
        self.objects[path] = data.read()

    def fput_object(self, bucket: str, path: str, source: str, content_type: str) -> None:
        self.calls.append(("fput_object", (bucket, path, source, content_type)))
        self.objects[path] = Path(source).read_bytes()

    def fget_object(self, bucket: str, path: str, destination: str) -> None:
        self.calls.append(("fget_object", (bucket, path, destination)))
        Path(destination).write_bytes(self.objects[path])

    def get_object(self, bucket: str, path: str) -> Any:
        self.calls.append(("get_object", (bucket, path)))
        response = MagicMock()
        response.read.return_value = self.objects[path]
        self.response = response
        return response

    def remove_object(self, bucket: str, path: str) -> None:
        self.calls.append(("remove_object", (bucket, path)))
        self.objects.pop(path, None)

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


def _policy(store: _Store) -> dict[str, Any]:
    [args] = [args for name, args in store.calls if name == "set_bucket_policy"]
    assert args[0] == settings.minio_bucket
    return json.loads(args[1])


def test_a_fresh_bucket_gets_the_anonymous_deny_policy() -> None:
    store = _Store()
    object_store.ensure_bucket(store)

    assert store.names() == ["bucket_exists", "make_bucket", "set_bucket_policy"]
    (statement,) = _policy(store)["Statement"]
    assert statement["Effect"] == "Deny"
    assert statement["Action"] == ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    assert statement["Resource"] == [
        f"arn:aws:s3:::{settings.minio_bucket}",
        f"arn:aws:s3:::{settings.minio_bucket}/*",
    ]
    assert statement["Condition"] == {"StringEquals": {"aws:PrincipalType": "Anonymous"}}


def test_an_existing_bucket_is_left_as_it_is() -> None:
    store = _Store(exists=True)
    object_store.ensure_bucket(store)
    assert store.names() == ["bucket_exists"]


def test_a_refused_policy_is_loud_and_not_fatal(caplog: pytest.LogCaptureFixture) -> None:
    store = _Store(policy_error=RuntimeError("policy refused"))
    with caplog.at_level("WARNING"):
        object_store.ensure_bucket(store)
    assert store.exists
    assert "Verify the bucket is not anonymously readable." in caplog.text


def test_the_sandbox_report_upload_creates_the_bucket_with_the_policy() -> None:
    from app.api.v1 import sandbox_reports

    store = _Store()
    with patch.object(sandbox_reports, "_minio_client", lambda: store):
        sandbox_reports._put_object_blocking("sandbox-reports/ab/abc/r.json", b"{}")

    assert store.names() == ["bucket_exists", "make_bucket", "set_bucket_policy", "put_object"]
    assert _policy(store)["Statement"][0]["Effect"] == "Deny"
    with patch.object(sandbox_reports, "_minio_client", lambda: store):
        assert sandbox_reports.get_object("sandbox-reports/ab/abc/r.json") == b"{}"


def test_the_sample_upload_creates_the_bucket_with_the_policy(tmp_path: Path) -> None:
    from app.api.v1 import samples

    source = tmp_path / "sample.bin"
    source.write_bytes(b"MZ")
    store = _Store()
    with patch.object(samples, "_minio_client", lambda: store):
        samples._store_sample_bytes_blocking(
            "samples/aa/aaaa", str(source), "application/octet-stream"
        )

    assert store.names() == ["bucket_exists", "make_bucket", "set_bucket_policy", "fput_object"]
    assert store.objects["samples/aa/aaaa"] == b"MZ"


def test_a_read_returns_the_bytes_and_releases_the_connection() -> None:
    store = _Store(exists=True)
    store.objects["x/y"] = b"payload"
    assert object_store.read_bytes(store, "x/y") == b"payload"
    store.response.close.assert_called_once()
    store.response.release_conn.assert_called_once()


def test_a_download_is_readable_by_its_owner_only(tmp_path: Path) -> None:
    store = _Store(exists=True)
    store.objects["samples/aa/aaaa"] = b"MZ"
    destination = tmp_path / "aaaa.exe"

    object_store.download(store, "samples/aa/aaaa", str(destination))

    assert destination.read_bytes() == b"MZ"
    assert stat.S_IMODE(os.stat(destination).st_mode) == 0o600
    assert ("fget_object", (settings.minio_bucket, "samples/aa/aaaa", str(destination))) in (
        store.calls
    )


def test_the_client_is_built_from_the_settings() -> None:
    with patch("minio.Minio") as minio:
        object_store.client()
    _, kwargs = minio.call_args
    assert minio.call_args.args == (settings.minio_endpoint,)
    assert kwargs["access_key"] == settings.minio_access_key
    assert kwargs["secure"] == settings.minio_secure


def test_no_other_module_builds_a_client() -> None:
    """The guard: ``Minio(`` is called in the object-store module and nowhere else."""
    root = Path(object_store.__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
        if path == Path(object_store.__file__).resolve():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "id", None) or getattr(func, "attr", None)
                if name == "Minio":
                    offenders.append(str(path.relative_to(root)))
    assert offenders == []
    assert "Minio(" in inspect.getsource(object_store)
