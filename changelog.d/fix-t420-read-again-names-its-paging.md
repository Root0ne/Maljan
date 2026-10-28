### Fixed

- **A shortened answer read again with `read_evidence` names `read_evidence`'s own paging (T-420).** The line under it ended "this tool takes no argument that pages it", although the tool pages with `offset` and `limit`: a ledger row stores no narrowing, so the read of a row and an analyst's read of an entry outside its loop passed none. The line now names the paging arguments read off the tool's own schema; an analyst reading its own entries is unchanged.
