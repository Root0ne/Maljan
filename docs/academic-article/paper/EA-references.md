# References

*Verification status is recorded per entry rather than assumed. Of the nine sources added by the
adjacent-field counter-search and checked individually, three had been cited for something they do
not say; those are corrected in the text and marked here. Sources listed in an earlier draft as
company for the ones actually fetched have been dropped rather than carried as decoration.*

[1] W. Yu et al. "Maltracker: A Fine-Grained NPM Malware Tracker Copiloted by LLM-Enhanced
Dataset." *ISSTA 2024*. DOI 10.1145/3650212.3680397.

[2] A. Rollinson and N. Polatidis. "LLM-Generated Samples for Android Malware Detection."
*Digital* 6(1):5, 2026. DOI 10.3390/digital6010005.

[3] W. Zhao et al. "AppPoet: LLM-based Android malware detection via multi-view prompt
engineering." *Expert Systems with Applications* 262, 2025. arXiv:2404.18816.

[4] S. Saha et al. "MaLAware: Automating the Comprehension of Malicious Software Behaviours using
LLMs." *MSR 2025*. arXiv:2504.01145.

[5] M. Büchel, T. Paladini, S. Longari, M. Carminati, S. Zanero, et al. "SoK: Automated TTP
Extraction from CTI Reports — Are We There Yet?" *USENIX Security 2025*, pp. 4621–4641.

[6] K. D'Oosterlinck, O. Khattab, F. Remy, T. Demeester, C. Develder, and C. Potts. "In-Context
Learning for Extreme Multi-Label Classification." arXiv:2401.12178.

[7] A. Lekssays, U. Shukla, H. T. Sencar, and M. Parvez. "TechniqueRAG: Retrieval Augmented
Generation for Adversarial Technique Annotation in CTI Text." *ACL Findings 2025*.
arXiv:2505.11988.

[8] "Identifying Adversary Tactics and Techniques in Malware Binaries with an LLM Agent"
(TTPDetect). arXiv:2602.06325.

[9] R. Evertz, N. Risse, C. Neuer, N. Müller, S. Normann, et al. "Chasing Shadows: Pitfalls in
LLM Security Research." *NDSS 2026*. arXiv:2512.09549. Living appendix at llmpitfalls.org.

[10] B. Bertalanič and B. Fortuna. "The Cost of Consensus: Isolated Self-Correction Prevails Over
Unguided Homogeneous Multi-Agent Debate." arXiv:2605.00914.

[11] D. Tran and D. Kiela. "Single-Agent LLMs Outperform Multi-Agent Systems on Multi-Hop
Reasoning Under Equal Thinking Token Budgets." arXiv:2604.02460.

[12] D. Lea, J. Ghawaly, G. G. Richard III, A. Ali-Gombe, and A. Case. "REx86: A Local Large
Language Model for Assisting in x86 Assembly Reverse Engineering." *ACSAC 2025*. arXiv:2510.20975.

[13] J. Ng and A. Milani Fard. "Evaluating Retrieval-Augmented Generation for Explainable Malware
Analysis." Poster, *ACM SecDev 2026*. arXiv:2605.03140.

[14] R. B. Metz, N. Spolaôr, E. A. Cherman, and M. C. Monard. "Comparing published multi-label
classifier performance measures to the ones obtained by a simple multi-label baseline classifier."
arXiv:1503.06952.

[15] L. Lange, H. Adel, et al. "AnnoCTR: A Dataset for Detecting and Linking Entities, Tactics,
and Techniques in Cyber Threat Reports." *LREC-COLING 2024*. arXiv:2404.07765. CC-BY-SA 4.0.

[16] M. Abdallah, J. Holdcroft, R. Ali, and A. Jatowt. "Are LLM-Based Retrievers Worth Their
Cost?" arXiv:2604.03676.

[17] H. T. Ng et al. "The CoNLL-2014 Shared Task on Grammatical Error Correction." *CoNLL 2014*;
C. Bryant, M. Felice, Ø. E. Andersen, and T. Briscoe. "The BEA-2019 Shared Task on Grammatical
Error Correction." *BEA 2019*. — cited for the F0.5 convention, which weights precision twice
recall to penalise over-correction. *Re-anchored 2026-08-15: two candidate papers previously
listed here were never fetched and are dropped; the convention is documented by the shared tasks
themselves.*

[18] S. Welleck, I. Kulikov, S. Roller, E. Dinan, K. Cho, and J. Weston. "Neural Text Generation
with Unlikelihood Training." arXiv:1908.04319; H. Li, Z. Lan, et al. "Repetition In Repetition
Out: Towards Understanding Neural Text Degeneration from the Data Perspective."
arXiv:2310.10226. — *Corrected 2026-08-15. An earlier draft attributed a single blended account
to these two. Welleck et al. blame the likelihood objective itself; the training-data account is
the second paper's, which argues self-reinforcement explanations reduce to it.*

[19] A. Lazaridou, A. Kuncoro, E. Gribovskaya, et al. "Mind the Gap: Assessing Temporal
Generalization in Neural Language Models." *NeurIPS 2021*. arXiv:2102.01951.

[20] W. Wu. "When Errors Become Narratives: A Longitudinal Taxonomy of Silent Failures in a
Production LLM Agent Runtime." arXiv:2606.14589. — *Abstract read; full text not read. Our mapping
of M1–M3 onto its five classes is our reading of the abstract and is stated as such in the text.*

[21] "From REST to MCP: An Empirical Study of API Wrapping and Automated Server Generation for LLM
Agents." arXiv:2507.16044. — *Corrected 2026-08-15. A sentence previously quoted from this paper is
not in it; it came from a search summary. What the abstract does state — 76% of sampled tools wrap
successfully, 94.2% after automated repair — is what is cited now.*

[22] Y. Li, Z. Liu, P.-L. Poon, D. Towey, C.-A. Sun, et al. "Metamorphic Relation Generation:
State of the Art and Research Directions." *ACM TOSEM*. DOI 10.1145/3708521. Preprint
arXiv:2406.05397.

[23] A. Dev, M. Sloan, B. Kavner, S. Kong, and M. Sandler. "Judge Reliability Harness: Stress
Testing the Reliability of LLM Judges." arXiv:2603.05399. — *Corrected 2026-08-15. This paper does
not establish the duplicate-item practice we previously cited it for; it perturbs formatting,
paraphrase, verbosity and labels. We have no verified source for that practice and no longer
assert one, which weakens a demotion of our own detector.*

[24] "Brevity Constraints Reverse Performance Hierarchies in Language Models." arXiv:2604.00025.
— *Abstract read; full text not read. Our claim that the reasoning-flag arm is a
brevity-constrained arm under another name is our reading and is stated as such.*

[25] Token-limit incompatibility across OpenAI-compatible servers: `ggml-org/llama.cpp` issue
#8634 (`max_tokens` not respected on the non-chat endpoint); `vllm-project/vllm` issue #11976
(request for a server-side cap). — *Search results; the issues have not been read in full. Cited to
demote our own mechanism to a known integration wart, which is the conservative direction.*

## Datasets

**MalwareBazaar** (abuse.ch), `https://bazaar.abuse.ch` — the dated, family-labelled Windows PE
samples analysed end to end. Samples are handled only in a scanner-excluded directory and are never
committed.

**MABEL — Malware Analysis Benchmark for AI/ML** (features only, v2.10) — mined offline into the
family-fingerprint catalogue and the ATT&CK case corpus. No binaries downloaded.

**Ultimate-RAT-Collection** — RAT builder and payload binaries, used for the family-fingerprint
catalogue and the leakage-free retrieval evaluation's held-out split.

**DikeDataset** — raw Windows PE binaries, downloaded and assessed but not catalogued: its labels
are coarse malice scores with no family or technique annotation.

**MITRE ATT&CK** (Enterprise), `https://attack.mitre.org` — the family-to-technique `uses`
relationships are the per-sample ground truth, derived from `mitre-attack/attack-stix-data`
under the ATT&CK Terms of Use.
