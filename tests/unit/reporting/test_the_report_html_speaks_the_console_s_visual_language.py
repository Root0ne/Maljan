"""The analyst report and the evidence bundle print in the console's visual language.

The PDF is printed from the analyst report's HTML, so both carry the console's
light tokens, its type scale, its five-rung severity scale and a cover that
leads with the verdict, its confidence, the severity and the family, as the
console's header does. The analyst report then opens as the console's Overview
does: the cover, the executive summary, and only then the contents. The
single-file layout prints exactly as it did, and the document policy and the
style nonce are those of every other export.
"""

from __future__ import annotations

from maljan.reporting.models import (
    FamilyAttribution,
    FileHashes,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    SeverityAssessment,
)
from maljan.reporting.renderers.html import _STYLESHEET, CONTENT_SECURITY_POLICY, HtmlRenderer


def _report(**fields: object) -> MalwareReport:
    base: dict[str, object] = {
        "identity": SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.exe"),
        "verdict": "Malware",
        "overall_confidence": 0.85,
        "severity": SeverityAssessment(rating="High"),
        "attribution": FamilyAttribution(family="<b>Loader</b>"),
        "executive_summary": "The sample decodes its strings at run time.",
        "key_findings": [KeyFinding(text="It beacons over HTTPS.", evidence_ids=[])],
    }
    base.update(fields)
    return MalwareReport(**base)  # type: ignore[arg-type]


def test_the_analyst_report_opens_on_a_cover_with_the_verdict() -> None:
    out = HtmlRenderer(layout="analyst").render(_report(), embed_figures=False)
    cover = out[out.index('<header class="cover"') : out.index("</header>")]
    assert 'data-verdict="malicious"' in cover
    assert '<span class="cover-verdict">Malicious</span>' in cover
    assert "Confidence <b>85%</b>" in cover
    assert '<span class="sev sev-4">High 4/5</span>' in cover
    # A value from the run is text, never markup.
    assert "Family <b>&lt;b&gt;Loader&lt;/b&gt;</b>" in cover
    # The title block the Markdown writes stays inside the cover.
    assert "<h1>" in cover


def test_the_executive_summary_comes_before_the_contents() -> None:
    out = HtmlRenderer(layout="analyst").render(_report(), embed_figures=False)
    assert out.index("</header>") < out.index("Executive summary") < out.index('<nav class="toc">')


def test_the_bundle_keeps_its_contents_first_under_the_cover() -> None:
    out = HtmlRenderer(layout="bundle").render(_report(), embed_figures=False)
    assert out.index("</header>") < out.index('<nav class="toc">')
    assert "--sev-4: #bc4c00" in out


def test_an_unassessed_verdict_is_said_and_drawn_neutral() -> None:
    report = _report(
        verdict_not_assessed="the run stopped before its verdict stage",
        overall_confidence=None,
        severity=None,
        attribution=FamilyAttribution(family="unknown"),
    )
    out = HtmlRenderer(layout="analyst").render(report, embed_figures=False)
    cover = out[out.index('<header class="cover"') : out.index("</header>")]
    assert 'data-verdict="unknown"' in cover
    assert '<span class="cover-verdict">No verdict</span>' in cover
    assert "Confidence <b>not assessed</b>" in cover
    assert "Severity <b>not assessed</b>" in cover
    assert "Family <b>not identified</b>" in cover


def test_the_single_file_layout_prints_as_it_did() -> None:
    out = HtmlRenderer().render(_report(), embed_figures=False, nonce="n0nce")
    assert '<header class="cover"' not in out
    assert "--sev-4" not in out
    assert f'<style nonce="n0nce">{_STYLESHEET}</style>' in out
    assert out.index('<nav class="toc">') < out.index("Key findings")


def test_every_layout_keeps_the_policy_and_the_nonce() -> None:
    for layout in ("analyst", "bundle"):
        out = HtmlRenderer(layout=layout).render(_report(), embed_figures=False, nonce="n0nce")
        assert f'content="{CONTENT_SECURITY_POLICY}"' in out
        assert out.count("<style") == 1
        assert '<style nonce="n0nce">' in out
        assert "<script" not in out
