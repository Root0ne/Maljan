"""Present a ``SandboxProvider`` as the legacy ``SandboxClient`` protocol.

``src/maljan/app.py`` and every existing sandbox test drive submit / wait /
fetch_report and sniff for an optional ``fetch_pcap``. Adapting the provider
to them — rather than rewriting them onto the provider — is what keeps
sub-project A a refactor: ``app.py`` is untouched, and the neutral report
rides along in the new ``SubmissionResult.normalized`` field for whoever
wants it next.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from maljan.loaders.sandbox_client import SubmissionResult
from maljan.providers.cape_view import to_cape_shaped_dict

if TYPE_CHECKING:
    from maljan.loaders.sandbox_client import SandboxClient
    from maljan.providers.base import SandboxProvider


def as_sandbox_client(provider: SandboxProvider) -> SandboxClient:
    """Present a provider as the ``SandboxClient`` the pipeline already speaks."""

    class _ProviderBackedClient:
        def __init__(self) -> None:
            self._provider = provider

        def submit(self, sample_path: str | Path) -> str:
            # str(...): SandboxProvider.submit's declared parameter is `str`
            # (concrete adapters accept the wider `str | Path`, but the
            # provider here is typed by the ABC), so the boundary narrows
            # before crossing it.
            return self._provider.submit(str(sample_path))

        def wait_for_completion(
            self, task_id: str, timeout_seconds: int = 300, poll_interval_seconds: int = 10
        ) -> str:
            return self._provider.wait_for_completion(
                task_id,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )

        def fetch_report(self, task_id: str) -> SubmissionResult:
            run = self._provider.fetch(task_id)
            return SubmissionResult(
                task_id=run.task_id,
                sample_sha256=run.sample_sha256,
                sample_name=run.sample_name,
                status=run.status,
                report=to_cape_shaped_dict(run.report),
                error=run.error,
                normalized=run.report,
            )

        def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
            if not self._provider.capabilities.can_fetch_pcap:
                return None
            return self._provider.fetch_pcap(task_id, str(dest_dir))

        def close(self) -> None:
            self._provider.close()

    return _ProviderBackedClient()  # type: ignore[return-value]
