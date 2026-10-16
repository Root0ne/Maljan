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
