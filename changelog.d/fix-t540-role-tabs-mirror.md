### Fixed

- **The agent editor's role tabs are held to the settings', and a locked built-in is told nothing about a tab it cannot pick (T-540).** The console's `ROLE_TABS`, which decides which roles are told that the sections their tools' kinds do not place go to EVIDENCE, is a copy of `core.config.ROLE_TABS`; a test now reads the console's constant and fails when a role is added, removed or moved on one side only. The hint "Sections its tools' kinds do not place go to EVIDENCE unless you pick a tab" is no longer shown on a built-in agent, whose tab select is disabled.
