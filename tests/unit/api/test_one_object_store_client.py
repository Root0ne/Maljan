"""Every reader and writer of the object store goes through one module.

The sample upload, the sandbox-report upload and read, the deletes, the health
probe and the worker's sample download build their client in
``app.services.object_store`` and create the bucket there: lazily, under the
configured name, and always private: MinIO refuses the deny policy a fresh
bucket used to be given (``aws:PrincipalType`` is not a condition key it knows),
so a fresh bucket gets no policy, which is how MinIO refuses an anonymous
caller; the health probe asks the bucket, anonymously, whether it still does.

Checked live against a throwaway MinIO server (RELEASE.2025-09-07T16-13-09Z,
on Alpine as docker/Dockerfile.minio builds it): with no bucket policy an
anonymous GET, PUT, listing and bucket HEAD are refused (403) while the root
and a ``readwrite`` user's keys read, write and list; the old deny policy is
refused with ``MalformedPolicy``; an anonymous ``s3:GetObject`` grant answers a
missing key with ``NoSuchKey`` and an ``s3:ListBucket`` grant answers the
bucket HEAD, which is what ``anonymous_access`` asks.
"""

from __future__ import annotations

import ast
import inspect
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

    def __init__(self, *, exists: bool = False) -> None:
        self.exists = exists
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.objects: dict[str, bytes] = {}

    def bucket_exists(self, bucket: str) -> bool:
        self.calls.append(("bucket_exists", (bucket,)))
        return self.exists

    def make_bucket(self, bucket: str) -> None:
        self.calls.append(("make_bucket", (bucket,)))
        self.exists = True

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


@pytest.fixture(autouse=True)
def _no_settled_bucket() -> Any:
    """These tests are about one client and the policy, so the bucket choice is
    settled on the configured name up front; the choice between the configured
    and the previous bucket has its own tests."""
    object_store._SETTLED.clear()
    object_store._SETTLED[settings.minio_bucket] = settings.minio_bucket
    yield
    object_store._SETTLED.clear()


def test_a_fresh_bucket_is_created_private_with_no_policy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _Store()
    with caplog.at_level("INFO"):
        object_store.ensure_bucket(store)

    assert store.names() == ["bucket_exists", "make_bucket"]
    assert "private (no bucket policy)" in caplog.text


def test_an_existing_bucket_is_left_as_it_is() -> None:
    store = _Store(exists=True)
    object_store.ensure_bucket(store)
    assert store.names() == ["bucket_exists"]


def test_the_sandbox_report_upload_creates_the_bucket_private() -> None:
    from app.api.v1 import sandbox_reports

    store = _Store()
    with patch.object(sandbox_reports, "_minio_client", lambda: store):
        sandbox_reports._put_object_blocking("sandbox-reports/ab/abc/r.json", b"{}")

    assert store.names() == ["bucket_exists", "make_bucket", "put_object"]
    with patch.object(sandbox_reports, "_minio_client", lambda: store):
        assert sandbox_reports.get_object("sandbox-reports/ab/abc/r.json") == b"{}"


def test_the_sample_upload_creates_the_bucket_private(tmp_path: Path) -> None:
    from app.api.v1 import samples

    source = tmp_path / "sample.bin"
    source.write_bytes(b"MZ")
    store = _Store()
    with patch.object(samples, "_minio_client", lambda: store):
        samples._store_sample_bytes_blocking(
            "samples/aa/aaaa", str(source), "application/octet-stream"
        )

    assert store.names() == ["bucket_exists", "make_bucket", "fput_object"]
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


# ---- the health probe asks whether the bucket is still private --------------


def _refusal(code: str) -> Exception:
    from minio.error import S3Error

    return S3Error(MagicMock(), code, code, "/bucket", "req", "host")


class _Anonymous:
    """A client with no credentials, answering as a MinIO bucket under ``grants`` does."""

    def __init__(self, grants: tuple[str, ...] = ()) -> None:
        self.grants = grants

    def bucket_exists(self, bucket: str) -> bool:
        if "s3:ListBucket" not in self.grants:
            raise _refusal("AccessDenied")
        return True

    def stat_object(self, bucket: str, key: str) -> Any:
        assert key == object_store.ANONYMOUS_PROBE_KEY
        raise _refusal("NoSuchKey" if "s3:GetObject" in self.grants else "AccessDenied")


class _Policied(_Store):
    def __init__(self, policy: dict[str, Any] | None) -> None:
        super().__init__(exists=True)
        self.policy = policy

    def get_bucket_policy(self, bucket: str) -> str:
        if self.policy is None:
            raise _refusal("NoSuchBucketPolicy")
        import json

        return json.dumps(self.policy)


def _allow_anyone(*actions: str, principal: Any = None) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": principal if principal is not None else {"AWS": ["*"]},
                "Action": list(actions),
                "Resource": [f"arn:aws:s3:::{settings.minio_bucket}/*"],
            }
        ],
    }


def test_a_bucket_with_no_policy_is_private() -> None:
    assert object_store.anonymous_access(_Policied(None), _Anonymous()) == []


def test_an_anonymous_read_and_listing_are_found_by_asking() -> None:
    granted = object_store.anonymous_access(
        _Policied(None), _Anonymous(("s3:GetObject", "s3:ListBucket"))
    )
    assert granted == ["list", "read"]


@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["*"]}])
def test_a_policy_that_lets_anyone_write_is_found_without_writing(principal: Any) -> None:
    store = _Policied(_allow_anyone("s3:PutObject", principal=principal))
    assert object_store.anonymous_access(store, _Anonymous()) == ["policy allows s3:PutObject"]
    assert "put_object" not in store.names()


def test_a_deny_or_a_named_principal_is_not_anonymous_access() -> None:
    policy = _allow_anyone("s3:GetObject", principal={"AWS": ["arn:aws:iam::1:user/x"]})
    policy["Statement"].append({**_allow_anyone("s3:GetObject")["Statement"][0], "Effect": "Deny"})
    assert object_store.anonymous_access(_Policied(policy), _Anonymous()) == []


def test_a_failure_other_than_a_refusal_is_raised() -> None:
    class _Broken(_Anonymous):
        def bucket_exists(self, bucket: str) -> bool:
            raise _refusal("InternalError")

    with pytest.raises(Exception, match="InternalError"):
        object_store.anonymous_access(_Policied(None), _Broken())


def test_the_health_probe_fails_a_bucket_that_is_not_private(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _Policied(_allow_anyone("s3:GetObject"))
    with (
        patch.object(object_store, "client", lambda: store),
        patch.object(object_store, "anonymous_client", lambda: _Anonymous(("s3:GetObject",))),
        caplog.at_level("ERROR"),
    ):
        answer = object_store.probe()
    # The endpoint is unauthenticated: the answer says only that it is not private.
    assert answer == {"ok": False, "error": "the bucket is not private; see the API log"}
    assert "read, policy allows s3:GetObject" in caplog.text


def test_the_health_probe_passes_a_private_bucket_and_a_missing_one() -> None:
    with (
        patch.object(object_store, "client", lambda: _Policied(None)),
        patch.object(object_store, "anonymous_client", lambda: _Anonymous()),
    ):
        assert object_store.probe() is None
    with patch.object(object_store, "client", lambda: _Store()):
        assert object_store.probe() is None


def test_the_anonymous_client_carries_no_credentials() -> None:
    with patch("minio.Minio") as minio:
        object_store.anonymous_client()
    _, kwargs = minio.call_args
    assert minio.call_args.args == (settings.minio_endpoint,)
    assert "access_key" not in kwargs and "secret_key" not in kwargs
