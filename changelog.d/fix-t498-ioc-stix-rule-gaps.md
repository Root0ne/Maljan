### Fixed

- **A published user agent gets a Suricata rule (T-498).** The Suricata draft read the published domains, addresses and URLs only, so a user agent the run publishes from the call that sends it had no rule. Each published user agent now gets an `http.user_agent` content rule, after the other rules so their SIDs do not move, with the value's quotes, semicolons, parentheses and control characters written as hex bytes, the publish reason in the comment above it, and the per-kind cap and its closing note as the other kinds have.
