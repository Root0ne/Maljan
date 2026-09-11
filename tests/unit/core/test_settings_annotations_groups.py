"""Task 2: the read-only group's wording reflects that it is deployment
config, not a place any remaining application setting lives."""

from maljan.core.settings_annotations import GROUP_DESCRIPTIONS, GROUP_ORDER


def test_system_group_is_titled_deployment_read_only():
    titles = dict(GROUP_ORDER)
    assert titles["system"] == "Deployment (read-only)"


def test_system_group_description_matches_the_ruling_exactly():
    assert GROUP_DESCRIPTIONS["system"] == (
        "Set in the process environment when the service starts; changed by redeploying."
    )
