"""What the replay holds the platform's code to while it runs.

Three doors are closed for the length of a replay, and put back as they were
when it ends:

* **the network.** Every socket connection (``connect``, ``connect_ex``,
  ``create_connection``), every datagram sent to an address (``sendto``,
  ``sendmsg``) and every name or address lookup (``getaddrinfo``,
  ``gethostbyname``, ``gethostbyname_ex``, ``gethostbyaddr``, ``getnameinfo``)
  raises :class:`ReplayRefused`. A socket that cannot connect sends nothing
  through ``send``. Not covered: a socket made from the low-level ``_socket``
  module, and a child process. No rule the replay calls needs the network,
  and a rule that reached for it (a catalogue refresh, a model index) must
  answer as it does on a box that cannot reach anything.
* **the ATT&CK cache.** The catalogue is read from the vendored tables in the
  rules' own tree (``data/attck_*.json``) and nothing else: the bundle loads
  and downloads are refused, and the cache directory points at a directory of
  the replay's own, so nothing is read from or written to the machine's
  cache. A run replayed on two machines reads the same catalogue.
* **the settings.** The process settings are built store-only
  (``settings_overrides.build_settings``) from the run's own snapshot, for
  the sections the rules read, so neither the environment nor a ``.env`` file
  changes what a rule decides.

The doors are named attributes of the platform's modules. One a given tree
does not have is left alone and said (:attr:`ReplayEnvironment.missing`); the
network refusal stands behind all of them.
"""

from __future__ import annotations

import logging
import os
import socket
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The environment variable the ATT&CK loader reads its cache directory from at
# import. Set before the platform is first imported in a process of its own.
ATTCK_CACHE_VARIABLE = "MALJAN_ATTCK_CACHE"

# The settings sections the replayed rules read. Only these are taken from the
# run's snapshot; every other setting is the rules' own default.
SETTINGS_SECTIONS: tuple[str, ...] = ("validation.", "preprocessing.", "reporting.")


class ReplayRefused(OSError):
    """A rule reached for something the replay does not allow: a connection or a catalogue load."""


def _refuse(*_args: Any, **_kwargs: Any) -> Any:
    raise ReplayRefused("the replay makes no network call and loads no ATT&CK bundle")


@dataclass
class ReplayEnvironment:
    """What the doors were set to, for the replay's own record."""

    cache_dir: Path
    settings_applied: list[str] = field(default_factory=list)
    settings_refused: dict[str, str] = field(default_factory=dict)
    # Doors this tree does not have, by module and attribute.
    missing: list[str] = field(default_factory=list)


def prepare_process(cache_dir: Path) -> str | None:
    """Point the ATT&CK cache at ``cache_dir`` before the platform is imported.

    For a process of the replay's own: the loader reads the variable once, at
    import. :func:`replay_environment` repoints the module attributes as well,
    for a process that imported the platform already. Returns the variable's
    value before, for :func:`restore_process`.
    """
    previous = os.environ.get(ATTCK_CACHE_VARIABLE)
    os.environ[ATTCK_CACHE_VARIABLE] = str(cache_dir)
    return previous


def restore_process(previous: str | None) -> None:
    """Put the ATT&CK cache variable back as :func:`prepare_process` found it."""
    if previous is None:
        os.environ.pop(ATTCK_CACHE_VARIABLE, None)
    else:
        os.environ[ATTCK_CACHE_VARIABLE] = previous


def _settings_overrides(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """The snapshot's values for the sections the rules read, by dotted key."""
    return {
        str(key): value
        for key, value in snapshot.items()
        if isinstance(key, str) and key.startswith(SETTINGS_SECTIONS)
    }


def _build_settings(snapshot: Mapping[str, Any], env: ReplayEnvironment) -> Any:
    """Store-only settings over the snapshot's values, each refused value dropped and named."""
    from pydantic import ValidationError

    from maljan.core.settings_overrides import build_settings

    overrides = _settings_overrides(snapshot)
    # One pass per refused key at most: each failed build names the keys it
    # refused, they are dropped, and the rest is built again.
    for _attempt in range(len(overrides) + 1):
        try:
            settings = build_settings(overrides)
        except ValidationError as exc:
            refused = {
                ".".join(str(part) for part in error.get("loc", ()) if part != "__root__")
                for error in exc.errors()
            }
            dropped = [key for key in overrides if any(key.startswith(r) for r in refused if r)]
            if not dropped:
                # Not one of the snapshot's keys: the defaults alone.
                env.settings_refused.update({"(snapshot)": type(exc).__name__})
                return build_settings({})
            for key in dropped:
                env.settings_refused[key] = "refused by this tree's settings model"
                overrides.pop(key, None)
            continue
        env.settings_applied = sorted(overrides)
        return settings
    return build_settings({})


@contextmanager
def replay_environment(snapshot: Mapping[str, Any] | None = None) -> Iterator[ReplayEnvironment]:
    """Close the three doors for the length of the block, and put each back after it."""
    # Each door as it was: its owner, its name, its value, and whether the
    # owner held it itself or inherited it (a class's method), which is then
    # put back by removing the replay's own.
    saved: list[tuple[Any, str, Any, bool]] = []

    def _swap(owner: Any, attribute: str, value: Any, label: str) -> None:
        if owner is None or not hasattr(owner, attribute):
            env.missing.append(label)
            return
        held = attribute in vars(owner)
        saved.append((owner, attribute, getattr(owner, attribute), held))
        setattr(owner, attribute, value)

    with tempfile.TemporaryDirectory(prefix="maljan-replay-attck-") as cache:
        env = ReplayEnvironment(cache_dir=Path(cache))
        quiet = logging.getLogger("maljan")
        level = quiet.level
        try:
            # A connection, a datagram sent to an address, and every name or
            # address lookup. A socket that cannot connect can send nothing
            # through ``send``; a socket pair (the event loop's own wake-up)
            # neither connects nor looks anything up.
            for name in ("connect", "connect_ex", "sendto", "sendmsg"):
                _swap(socket.socket, name, _refuse, f"socket.socket.{name}")
            for name in (
                "create_connection",
                "getaddrinfo",
                "gethostbyname",
                "gethostbyname_ex",
                "gethostbyaddr",
                "getnameinfo",
            ):
                _swap(socket, name, _refuse, f"socket.{name}")

            from maljan.memory import attck_loader

            try:
                from maljan.memory import attck_index
            except ImportError:  # a tree without it
                attck_index = None  # type: ignore[assignment]
            try:
                from maljan.memory import embeddings
            except ImportError:
                embeddings = None  # type: ignore[assignment]
            try:
                from maljan.memory import semantic_attck_index
            except ImportError:
                semantic_attck_index = None  # type: ignore[assignment]

            cache_dir = Path(cache)
            domains = tuple(getattr(attck_loader, "DOMAINS", ("enterprise", "mobile", "ics")))
            _swap(attck_loader, "ATTCK_CACHE_DIR", cache_dir, "attck_loader.ATTCK_CACHE_DIR")
            _swap(
                attck_loader,
                "ATTCK_CACHE_FILES",
                {domain: cache_dir / f"{domain}-attack.json" for domain in domains},
                "attck_loader.ATTCK_CACHE_FILES",
            )
            _swap(
                attck_loader,
                "ATTCK_CACHE_FILE",
                cache_dir / "enterprise-attack.json",
                "attck_loader.ATTCK_CACHE_FILE",
            )
            for name in ("load_all_domains", "load_attck_data", "_fetch_bundle"):
                _swap(attck_loader, name, _refuse, f"attck_loader.{name}")
            _swap(
                attck_loader, "_download_bundle_file", _refuse, "attck_loader._download_bundle_file"
            )
            _swap(attck_index, "load_all_domains", _refuse, "attck_index.load_all_domains")
            _swap(embeddings, "_try_load_fastembed", lambda: None, "embeddings._try_load_fastembed")
            _swap(
                semantic_attck_index,
                "_EMB_CACHE_DIR",
                cache_dir,
                "semantic_attck_index._EMB_CACHE_DIR",
            )
            # A platform catalogue cached before the block is the machine's:
            # read again, from the vendored tables, inside it.
            reset = getattr(attck_loader, "reset_caches", None)
            if callable(reset):
                reset()

            from maljan.core import config

            _swap(
                config,
                "_settings_instance",
                _build_settings(snapshot or {}, env),
                "config._settings_instance",
            )

            # The rules log what they decide at warning level for an operator;
            # the replay prints its own record instead.
            quiet.setLevel(logging.ERROR)
            yield env
        finally:
            quiet.setLevel(level)
            for owner, attribute, value, held in reversed(saved):
                if held:
                    setattr(owner, attribute, value)
                else:
                    delattr(owner, attribute)
            try:
                from maljan.memory import attck_loader as _loader

                reset_after = getattr(_loader, "reset_caches", None)
                if callable(reset_after):
                    reset_after()
            except ImportError:
                pass
