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

    # The privacy check asks whether the bucket is there before the write.
    assert store.names() == ["bucket_exists", "make_bucket", "bucket_exists", "put_object"]
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

    # The privacy check asks whether the bucket is there before the write.
    assert store.names() == ["bucket_exists", "make_bucket", "bucket_exists", "fput_object"]
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


# ---- the bucket is asked whether it is still private ------------------------

_OWN_ANONYMOUS_CLIENT = object_store.anonymous_client
_OWN_CHECK_AT_START = object_store.check_privacy_at_start


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
    def __init__(self, policy: dict[str, Any] | None | Exception) -> None:
        super().__init__(exists=True)
        self.policy = policy

    def get_bucket_policy(self, bucket: str) -> str:
        if isinstance(self.policy, Exception):
            raise self.policy
        if self.policy is None:
            raise _refusal("NoSuchBucketPolicy")
        import json

        return json.dumps(self.policy)


def _statement(**fields: Any) -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Principal": {"AWS": ["*"]},
        "Action": ["s3:GetObject"],
        "Resource": [f"arn:aws:s3:::{settings.minio_bucket}/*"],
        **fields,
    }


def _policy(*statements: Any) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _anonymously(*grants: str) -> Any:
    return lambda *_args: _Anonymous(grants)


def test_a_bucket_with_no_policy_is_private() -> None:
    assert object_store.anonymous_access(_Policied(None), _Anonymous()) == []


def test_an_anonymous_read_and_listing_are_found_by_asking() -> None:
    granted = object_store.anonymous_access(
        _Policied(None), _Anonymous(("s3:GetObject", "s3:ListBucket"))
    )
    assert granted == ["list", "read"]


@pytest.mark.parametrize(
    ("statement", "granted"),
    [
        (_statement(Principal="*"), ["policy allows s3:GetObject"]),
        (_statement(Principal={"AWS": "*"}), ["policy allows s3:GetObject"]),
        (
            _statement(Principal={"AWS": ["arn:aws:iam::1:user/x", "*"]}),
            ["policy allows s3:GetObject"],
        ),
        (
            _statement(Principal={"AWS": "*", "Service": "x.amazonaws.com"}),
            ["policy allows s3:GetObject"],
        ),
        (
            {**_statement(NotPrincipal={"AWS": ["arn:aws:iam::1:user/x"]}), "Principal": None},
            ["policy allows s3:GetObject"],
        ),
        (
            {
                k: v
                for k, v in _statement(Principal="*", NotAction=["s3:DeleteObject"]).items()
                if k != "Action"
            },
            ["policy allows all but s3:DeleteObject"],
        ),
        (_statement(Action="s3:PutObject"), ["policy allows s3:PutObject"]),
    ],
    ids=[
        "star",
        "aws-star",
        "star-among-arns",
        "star-beside-a-service",
        "not-principal",
        "not-action",
        "a-write",
    ],
)
def test_every_spelling_of_an_open_grant_is_found(
    statement: dict[str, Any], granted: list[str]
) -> None:
    store = _Policied(_policy(statement))
    assert object_store.anonymous_access(store, _Anonymous()) == granted
    assert "put_object" not in store.names(), "a write is read from the policy, never tried"


def test_a_deny_a_named_principal_and_a_malformed_statement_are_not_open() -> None:
    policy = _policy(
        _statement(Principal={"AWS": ["arn:aws:iam::1:user/x"]}),
        _statement(Effect="Deny", Principal="*"),
        "not a statement",
        ["nor", "this"],
    )
    assert object_store.anonymous_access(_Policied(policy), _Anonymous()) == []


def test_a_key_that_may_not_read_the_policy_keeps_the_anonymous_verdict(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _Policied(_refusal("AccessDenied"))
    with caplog.at_level("WARNING"):
        assert object_store.anonymous_access(store, _Anonymous(("s3:GetObject",))) == ["read"]
        assert object_store.anonymous_access(store, _Anonymous()) == []
    said = [r for r in caplog.records if "not checked" in r.getMessage()]
    assert len(said) == 1, "said once"
    assert "may not read the bucket policy" in said[0].getMessage()


def test_a_failure_other_than_a_refusal_is_raised() -> None:
    class _Broken(_Anonymous):
        def bucket_exists(self, bucket: str) -> bool:
            raise _refusal("InternalError")

    with pytest.raises(Exception, match="InternalError"):
        object_store.anonymous_access(_Policied(None), _Broken())


def test_the_verdict_is_kept_for_a_while_and_asked_again_after(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import time

    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    asked: list[int] = []
    grants: list[tuple[str, ...]] = [("s3:GetObject",)]

    def _anonymous(*_args: Any) -> _Anonymous:
        asked.append(1)
        return _Anonymous(grants[0])

    monkeypatch.setattr(object_store, "anonymous_client", _anonymous)
    store = _Policied(None)
    with caplog.at_level("INFO"):
        assert object_store.privacy(store) == ("read",)
        clock[0] += object_store.PRIVACY_TTL_SECONDS - 1
        assert object_store.privacy(store) == ("read",)
        assert len(asked) == 1
        # The store is fixed: within the cache's life it is served again, without a restart.
        grants[0] = ()
        clock[0] += 2
        assert object_store.privacy(store) == ()
    assert len(asked) == 2
    assert "is not private" in caplog.text and "is private again" in caplog.text


def test_a_store_that_cannot_be_asked_is_no_verdict_and_is_asked_again_soon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    # The suite's own fixture leaves the anonymous client unreachable.
    assert object_store.privacy(_Policied(None)) is None
    object_store.require_private(_Policied(None))
    # Kept a few seconds only, not the minute a verdict is kept.
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
    assert object_store.privacy(_Policied(None)) is None
    clock[0] += object_store.UNCHECKED_TTL_SECONDS + 0.1
    assert object_store.privacy(_Policied(None)) == ("read",)


def test_a_bucket_anyone_can_read_refuses_samples_and_reports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fail closed: the sample upload, the worker's download and a report's write and read."""
    from app.api.v1 import samples, sandbox_reports

    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
    store = _Policied(None)
    source = tmp_path / "sample.bin"
    source.write_bytes(b"MZ")
    with patch.object(samples, "_minio_client", lambda: store):
        with pytest.raises(object_store.StoreNotPrivate):
            samples._store_sample_bytes_blocking("samples/aa/aaaa", str(source), "x")
    with patch.object(sandbox_reports, "_minio_client", lambda: store):
        with pytest.raises(object_store.StoreNotPrivate):
            sandbox_reports._put_object_blocking("sandbox-reports/r.json", b"{}")
        with pytest.raises(object_store.StoreNotPrivate):
            sandbox_reports.get_object("sandbox-reports/r.json")
    with pytest.raises(object_store.StoreNotPrivate):
        object_store.download(store, "samples/aa/aaaa", str(tmp_path / "out"))
    assert not {"put_object", "fput_object", "get_object", "fget_object"} & set(store.names())
    assert str(object_store.StoreNotPrivate()) == "object store is not private; see the API log"


def test_the_health_probe_fails_a_bucket_that_is_not_private_as_required(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = _Policied(_policy(_statement()))
    monkeypatch.setattr(object_store, "client", lambda: store)
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
    with caplog.at_level("ERROR"):
        answer = object_store.probe()
    # The endpoint is unauthenticated: the answer does not announce the exposure.
    assert answer == {
        "ok": False,
        "error": "object store policy check failed; see the API log",
        "required": True,
    }
    assert "read, policy allows s3:GetObject" in caplog.text


def test_the_health_probe_fails_a_bucket_it_could_not_ask_as_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(object_store, "client", lambda: _Policied(None))
    assert object_store.probe() == {
        "ok": False,
        "error": "object store privacy not checked; see the API log",
    }


def test_the_health_probe_passes_a_private_bucket_and_a_missing_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously())
    monkeypatch.setattr(object_store, "client", lambda: _Policied(None))
    assert object_store.probe() is None
    monkeypatch.setattr(object_store, "client", lambda: _Store())
    assert object_store.probe() is None


def test_the_start_asks_the_bucket_once_it_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:ListBucket"))
    monkeypatch.setattr(object_store, "client", lambda: _Store())
    _OWN_CHECK_AT_START()
    assert object_store._PRIVACY == {}
    monkeypatch.setattr(object_store, "client", lambda: _Policied(None))
    _OWN_CHECK_AT_START()
    assert object_store._PRIVACY[settings.minio_bucket][1] == ("list",)


def test_the_anonymous_client_carries_no_credentials_and_is_bounded() -> None:
    # The suite's fixture replaced it; the module's own, held at import, is under test.
    own = _OWN_ANONYMOUS_CLIENT
    store = MagicMock()
    store._get_region.return_value = "eu-west-1"
    with patch("minio.Minio") as minio:
        own(store, "bucket")
    _, kwargs = minio.call_args
    assert minio.call_args.args == (settings.minio_endpoint,)
    assert "access_key" not in kwargs and "secret_key" not in kwargs
    assert "credentials" not in kwargs
    assert kwargs["region"] == "eu-west-1"
    store._get_region.assert_called_once_with("bucket")
    pool = kwargs["http_client"]
    assert pool.connection_pool_kw["timeout"].connect_timeout == object_store.ANONYMOUS_SECONDS
    assert pool.connection_pool_kw["timeout"].read_timeout == object_store.ANONYMOUS_SECONDS
    assert pool.connection_pool_kw["retries"].total is False


# ---- the reviewer's probes: open grants, a passing error, a bucket not made --


class _AnonymousRefused:
    def bucket_exists(self, bucket: str) -> bool:
        raise _refusal("AccessDenied")

    def stat_object(self, bucket: str, key: str) -> Any:
        raise _refusal("AccessDenied")


def _one(**fields: Any) -> dict[str, Any]:
    return _policy({"Effect": "Allow", "Resource": ["arn:aws:s3:::x/*"], **fields})


@pytest.mark.parametrize(
    ("policy", "granted"),
    [
        (
            _one(Principal={"AWS": ["arn:aws:iam::1:root", "*"]}, Action="s3:GetObject"),
            ["policy allows s3:GetObject"],
        ),
        (
            _one(NotPrincipal={"AWS": ["arn:aws:iam::1:root"]}, Action="s3:GetObject"),
            ["policy allows s3:GetObject"],
        ),
        (
            _one(Principal="*", NotAction="s3:DeleteObject"),
            ["policy allows all but s3:DeleteObject"],
        ),
        (
            _one(Principal={"AWS": "*", "Service": "x"}, Action="s3:GetObject"),
            ["policy allows s3:GetObject"],
        ),
        (
            {"Statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:*"}},
            ["policy allows s3:*"],
        ),
        (
            _one(
                Principal="*",
                Action="s3:GetObject",
                Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            ),
            ["policy allows s3:GetObject"],
        ),
    ],
    ids=["mixed-list", "not-principal", "not-action", "dict-and-service", "one-statement", "cond"],
)
def test_the_reviewer_s_open_grants_are_found(policy: dict[str, Any], granted: list[str]) -> None:
    # A grant held to a condition is still a grant to callers nobody signed for.
    assert object_store.anonymous_access(_Policied(policy), _AnonymousRefused()) == granted


def test_a_passing_error_never_opens_a_bucket_found_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Flaky:
        def bucket_exists(self, bucket: str) -> bool:
            raise TimeoutError("slow")

    store = _Policied(None)
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
    assert object_store.privacy(store, fresh=True) == ("read",)
    held = object_store._PRIVACY[settings.minio_bucket]
    monkeypatch.setattr(object_store, "anonymous_client", lambda *_args: _Flaky())
    assert object_store.privacy(store, fresh=True) == ("read",)
    assert object_store._PRIVACY[settings.minio_bucket] == held, "verdict and time kept"
    with pytest.raises(object_store.StoreNotPrivate):
        object_store.require_private(store)
    monkeypatch.setattr(object_store, "client", lambda: store)
    assert (object_store.probe() or {}).get("required") is True


def test_a_listing_counts_only_when_the_bucket_answers_that_it_is_there() -> None:
    class _Gone(_AnonymousRefused):
        def bucket_exists(self, bucket: str) -> bool:
            return False

    assert object_store.anonymous_access(_Policied(None), _Gone()) == []


def test_a_bucket_not_made_yet_is_not_asked_and_not_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
    assert object_store.privacy(_Store()) == ()
    assert object_store._PRIVACY == {}


# ---- every read and write of the store's primitives is refused ---------------


def test_every_primitive_refuses_a_bucket_anyone_can_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
    store = _Policied(None)
    store.objects["x/y"] = b"MZ"
    source = tmp_path / "s.bin"
    source.write_bytes(b"MZ")
    calls = [
        lambda: object_store.put_file(store, "x/z", str(source), content_type="x"),
        lambda: object_store.put_bytes(store, "x/z", b"MZ", content_type="x"),
        lambda: object_store.read_bytes(store, "x/y"),
        lambda: object_store.open_object(store, "x/y"),
        lambda: object_store.download(store, "x/y", str(tmp_path / "out")),
    ]
    for call in calls:
        with pytest.raises(object_store.StoreNotPrivate):
            call()
    assert not {"put_object", "fput_object", "get_object", "fget_object"} & set(store.names())


def test_an_evidence_write_is_failed_as_not_private_and_its_read_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib

    store = _Policied(None)
    spill = object_store.JobEvidenceSpill("job-1", 1024, store=store)
    blob = b"the whole answer"
    sha = hashlib.sha256(blob).hexdigest()
    monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
    spill.put(sha, blob, "text/plain")
    assert spill.drain(5) == {sha: "store not private"}
    assert "put_object" not in store.names()
    assert spill.read(sha) is None


def test_a_failed_ask_never_writes_over_an_open_verdict_found_meanwhile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two asks interleaved: the first fails after the second found the bucket open."""
    store = _Policied(None)
    found: list[Any] = []

    def _first_fails_after_the_second_answers(*_args: Any) -> Any:
        # The second ask runs to its end while the first is still out.
        monkeypatch.setattr(object_store, "anonymous_client", _anonymously("s3:GetObject"))
        found.append(object_store.privacy(store, fresh=True))
        raise TimeoutError("slow")

    monkeypatch.setattr(object_store, "anonymous_client", _first_fails_after_the_second_answers)
    assert object_store.privacy(store, fresh=True) == ("read",)
    assert found == [("read",)]
    assert object_store._PRIVACY[settings.minio_bucket][1] == ("read",)
    assert isinstance(object_store._PRIVACY_LOCK, type(__import__("threading").Lock()))
