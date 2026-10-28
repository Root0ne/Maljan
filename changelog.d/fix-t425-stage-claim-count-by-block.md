### Fixed

- **A stage's claim count counts a claim mapped to several techniques once (T-425).** The stage record a team's condition reads (`stages.<key>.claim_count`) counted each technique-split copy of a claim, so one claim whose TECHNIQUE line listed three ids was three claims there while the run summary's row and the judge's ISR line counted it once. It now counts claim blocks, the count every other surface uses since T-424. A stored run keeps the count it stored: nothing recomputes it from the stored claims.
