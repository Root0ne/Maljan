"""Failures a provider can raise, in the project's existing exception tree."""

from __future__ import annotations

from maljan.core.exceptions import MaljanError


class ProviderError(MaljanError):
    """A provider could not do what it was asked."""


class ProviderConfigurationError(ProviderError):
    """The settings name a provider that does not exist, or configure it wrongly."""
