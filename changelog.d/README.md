# Changelog fragments

One Markdown file per change, named after the branch or a short slug
(`fix-ghidra-guard.md`). Each file holds one or more sections; the text under a
section is written exactly as it should appear in `CHANGELOG.md`:

```markdown
### Fixed

- **What changed, in the words a user would read.** Why, and what stays as it was.
```

Known sections: Added, Changed, Deprecated, Removed, Fixed, Security,
Documentation, Upgrading.

`scripts/changelog/fold.py` folds every fragment into the top of the matching
section under Unreleased (sections in the order above, then file name) and
deletes the folded files; run it when promoting `dev` to `main`. In a pull
request `python scripts/changelog/fold.py --check` validates the fragments
without writing.
