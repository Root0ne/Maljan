### Fixed

- **The console's rule card says what the analyst report says of each drafted rule (T-528).** Each generated rule, in the list and in its side panel, now carries the report's §8.2 line: the Precision line of a rule the analyst report prints (published strings and stored values counted apart, and that no retro-hunt was run), or why the report does not print it. A YARA draft that matched its sample by its sha256 or import hash alone now says it did not match by its content, where the card had shown only its badge. Read from the fields the report already serves; no API change.
