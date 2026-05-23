# Triage - Custom Yara

Source: https://tria.ge/docs/yara/
Mirrored: 2026-05-23

---

# Custom Yara

Under the `Researcher` tab, select Yara from the submenu and select `New Yara Rule`. Under the `Organization` tab, select Yara from the submenu and select `New Yara Rule`.

Enter a name for the file and use the editor box to enter the Yara rule.

## Metadata fields

Any metadata value can be provided in custom rules. However the following have particular uses within Triage™:

- `description`: This field is used as the 'title' of the signature, which appears in the main UI.
- `triage_description`: Optional. This field is used to provide a more detailed description of the signature. In the UI, it is visible in the dropdown section of the signature.
- `triage_score`: Optional - The score value that should be assigned to the signature; defaults to 10 if not defined. As a rough guideline:
- 1-4 = Benign/informational
- 5-7 = Possibly malicious
- 8-9 = Likely malicious
- 10 = Known bad
- `triage_tags`: Optional. Used to define tags which are applied to the analysis as a whole. These are generally intended to define the class of malware - e.g. `dropper`, `trojan`, `ransomware` etc. These can be used in Search to find samples with these tags applied using the `tag:` query. Note that these tags are also visible to anyone else who has access to your analyses.
- `triage_family`: Optional. This is used to mark a sample as belonging to a particular malware family. The value defined here appears as a tag in the UI and can be used in Search with the `family:` query. Note that if this tag is defined then a sample will automatically receive a score of 10 regardless of the value set in `triage_score`.
