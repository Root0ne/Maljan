"""Draw the seeded teams as SVG, from the profiles themselves.

The architecture page needs a picture of each team, and a picture drawn by
hand is a picture that stops being true the first time a stage moves. These
are generated from ``Settings().agents.profiles``, so a stage added to a
seeded team either shows up in the diagram on the next run or fails the smoke
test that checks the two agree.

Deliberately no graphing library. A team is a column of boxes with a few
labelled arrows, and hand-written SVG keeps the output diffable, dependency
free and readable in both light and dark pages — the colours are the two the
existing ``docs/assets/architecture.svg`` uses.

Run: ``uv run python scripts/goldens/render_team_graphs.py``
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "docs" / "assets"

# The teams drawn on the architecture page, in the order they are introduced.
TEAMS: tuple[str, ...] = ("default", "mobile", "deep_static")

BOX_WIDTH = 460
BOX_HEIGHT = 58
GAP = 34
MARGIN = 24

# One fill per stage kind, so a reader can tell an analysis stage from the
# debate at a glance without reading the label.
KIND_FILL: dict[str, str] = {
    "analysis": "#1f2937",
    "debate": "#312e28",
    "verdict": "#26313a",
    "report": "#2a2536",
}
STROKE = "#4b5563"
TEXT = "#e5e7eb"
MUTED = "#9ca3af"
ACCENT = "#7dd3fc"


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _stage_rows(profile: Any) -> list[dict[str, str]]:
    """One row per stage: what it is, who is in it, and when it runs."""
    rows: list[dict[str, str]] = []
    for stage in profile.stages:
        rows.append(
            {
                "key": stage.key,
                "kind": stage.kind,
                "agents": ", ".join(stage.agents) or "—",
                "when": stage.when,
                "reads": stage.inject_upstream,
            }
        )
    return rows


def render(name: str, profile: Any) -> str:
    """One team as a column of stages, top to bottom in run order."""
    rows = _stage_rows(profile)
    height = MARGIN * 2 + len(rows) * BOX_HEIGHT + (len(rows) - 1) * GAP + 34
    width = BOX_WIDTH + MARGIN * 2
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="The {_esc(name)} team, stage by stage">',
        f"<title>{_esc(profile.label or name)} team</title>",
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{STROKE}"/></marker></defs>',
        f'<text x="{MARGIN}" y="{MARGIN}" fill="{TEXT}" font-family="monospace" '
        f'font-size="14">{_esc(profile.label or name)}</text>',
    ]

    top = MARGIN + 26
    for index, row in enumerate(rows):
        y = top + index * (BOX_HEIGHT + GAP)
        fill = KIND_FILL.get(row["kind"], KIND_FILL["analysis"])
        parts.append(
            f'<rect x="{MARGIN}" y="{y}" width="{BOX_WIDTH}" height="{BOX_HEIGHT}" rx="6" '
            f'fill="{fill}" stroke="{STROKE}"/>'
        )
        parts.append(
            f'<text x="{MARGIN + 14}" y="{y + 23}" fill="{TEXT}" font-family="monospace" '
            f'font-size="13">{_esc(row["key"])}'
            f'<tspan fill="{MUTED}" font-size="11">  {_esc(row["kind"])}</tspan></text>'
        )
        parts.append(
            f'<text x="{MARGIN + 14}" y="{y + 43}" fill="{MUTED}" font-family="monospace" '
            f'font-size="11">{_esc(row["agents"])}</text>'
        )
        if row["when"]:
            parts.append(
                f'<text x="{MARGIN + BOX_WIDTH - 14}" y="{y + 43}" fill="{ACCENT}" '
                f'text-anchor="end" font-family="monospace" font-size="11">'
                f"when {_esc(row['when'])}</text>"
            )
        if index + 1 < len(rows):
            arrow_top = y + BOX_HEIGHT
            parts.append(
                f'<line x1="{MARGIN + BOX_WIDTH / 2}" y1="{arrow_top}" '
                f'x2="{MARGIN + BOX_WIDTH / 2}" y2="{arrow_top + GAP - 4}" '
                f'stroke="{STROKE}" stroke-width="1.5" marker-end="url(#arrow)"/>'
            )
            parts.append(
                f'<text x="{MARGIN + BOX_WIDTH / 2 + 10}" y="{arrow_top + GAP - 12}" '
                f'fill="{MUTED}" font-family="monospace" font-size="10">'
                f"reads {_esc(rows[index + 1]['reads'])}</text>"
            )

    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def asset_path(name: str) -> Path:
    return ASSETS / f"team-{name.replace('_', '-')}.svg"


def render_all() -> list[Path]:
    """Write one SVG per seeded team and return what was written."""
    from maljan.core.config import Settings

    profiles = Settings(_env_file=None).agents.profiles
    ASSETS.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in TEAMS:
        profile = profiles.get(name)
        if profile is None:
            raise SystemExit(f"no seeded profile named {name!r}")
        path = asset_path(name)
        path.write_text(render(name, profile), encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":
    for written in render_all():
        print(f"wrote {written.relative_to(ROOT)}")
