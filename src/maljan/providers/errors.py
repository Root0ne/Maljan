"""Failures a provider can raise, in the project's existing exception tree."""

from __future__ import annotations

from maljan.core.exceptions import MaljanError


class ProviderError(MaljanError):
    """A provider could not do what it was asked."""


class ProviderConfigurationError(ProviderError):
    """The settings name a provider that does not exist, or configure it wrongly."""


class AttachedReportRefused(ProviderError):
    """An attached sandbox report the platform refuses to read, in a sentence it composed.

    Composed from the format name the upload route recorded and the format
    settings (``sandbox.report_formats``, ``sandbox.upload.allowed_formats``),
    never from the report's bytes or another component's words, so a job states
    it whole. Any other ``ProviderError`` a provider raises over an attached
    report is stated by its class alone.
    """


# The artefact a sandbox may offer beside its report that the platform fetches:
# the detonation's packet capture.
PACKET_CAPTURE = "packet capture"


class ArtefactFetchFailed(ProviderError):
    """An artefact the sandbox offered beside its report that could not be fetched.

    ``cause`` is composed by the provider, never quoted from the sandbox: an
    HTTP status, an exception's type, or the size of a file too small to be
    the artefact (``empty``). ``reason`` is the run's degradation reason and
    ``statement`` what the run summary's coverage record says in place of the
    sandbox offering none.
    """

    def __init__(self, artefact: str, cause: str, *, empty: bool = False) -> None:
        self.artefact = artefact
        self.cause = cause
        self.empty = empty
        if empty:
            self.reason = f"{artefact} fetched empty ({cause})"
            self.statement = f"the {artefact} was fetched empty ({cause})"
        else:
            self.reason = f"{artefact} not fetched ({cause})"
            self.statement = f"the {artefact} could not be fetched ({cause})"
        super().__init__(self.reason)

    def record(self) -> dict[str, str]:
        """What the job keeps of the failure (``ServiceContainer.artefact_fetch_failures``)."""
        return {"artefact": self.artefact, "reason": self.reason, "statement": self.statement}
