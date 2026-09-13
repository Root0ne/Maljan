"""The team diagrams on the architecture page are generated, and stay generated.

A diagram drawn by hand stops being true the first time a stage moves, which
is why these are rendered from the seeded profiles. What is checked here is
that the renderer runs, that every stage of every drawn team reaches its SVG,
and that the committed assets are the ones the current profiles produce — so a
stage added to a seeded team fails here rather than quietly leaving the docs
describing a team the product no longer ships.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "goldens"))

from render_team_graphs import TEAMS, asset_path, render  # noqa: E402


def _profiles() -> dict:
    from maljan.core.config import Settings

    return Settings(_env_file=None).agents.profiles


class TestTheRenderer:
    def test_it_draws_every_stage_of_every_team_it_is_asked_for(self) -> None:
        profiles = _profiles()
        for name in TEAMS:
            svg = render(name, profiles[name])
            assert svg.startswith("<svg")
            assert svg.rstrip().endswith("</svg>")
            for stage in profiles[name].stages:
                assert f">{stage.key}<" in svg or f">{stage.key}<tspan" in svg

    def test_a_condition_is_drawn_where_a_stage_has_one(self) -> None:
        profiles = _profiles()
        svg = render("mobile", profiles["mobile"])
        assert "when file_type in" in svg

    def test_the_default_team_has_no_condition_to_draw(self) -> None:
        profiles = _profiles()
        assert "when " not in render("default", profiles["default"])

    def test_the_committed_assets_are_what_the_profiles_produce(self) -> None:
        profiles = _profiles()
        for name in TEAMS:
            path = asset_path(name)
            assert path.exists(), f"{path} has not been rendered"
            assert path.read_text(encoding="utf-8") == render(name, profiles[name]), (
                f"{path.name} is stale; run scripts/goldens/render_team_graphs.py"
            )
