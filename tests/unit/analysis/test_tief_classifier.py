"""Tests for the TIEF (Threat Intelligence Extraction Framework) Classifier."""

from unittest.mock import MagicMock, patch

from maljan.analysis.tief_classifier import TIEFClassifier


def test_tief_classifier_init():
    """Test the TIEF classifier initializes correctly without loading the model."""
    classifier = TIEFClassifier(model_name="dummy_model", threshold=0.5)
    assert classifier.model_name == "dummy_model"
    assert classifier.threshold == 0.5
    assert not classifier._initialized
    assert classifier.classifier is None


@patch("maljan.analysis.tief_classifier.pipeline")
def test_tief_classifier_extract(mock_pipeline):
    """Test extracting techniques returns correct format above threshold."""
    # Mock the HF pipeline
    mock_classifier = MagicMock()
    mock_classifier.return_value = [
        [
            {"label": "T1055", "score": 0.95},
            {"label": "T1027", "score": 0.85},
            {"label": "T1059", "score": 0.40},  # Below threshold
        ]
    ]
    mock_pipeline.return_value = mock_classifier

    classifier = TIEFClassifier(threshold=0.8)
    results = classifier.extract_techniques("Some malicious process injection text.")

    # Initialization happens automatically on first call
    assert classifier._initialized
    mock_pipeline.assert_called_once_with(
        "text-classification", model="distilbert-base-uncased", return_all_scores=True
    )

    # Should only return predictions above 0.8
    assert len(results) == 2
    assert results[0]["technique_id"] == "T1055"
    assert results[0]["score"] == 0.95
    assert results[1]["technique_id"] == "T1027"


@patch("maljan.analysis.tief_classifier.pipeline")
def test_tief_generate_isr(mock_pipeline):
    """Test AgentISR generation from TIEF classifier."""
    mock_classifier = MagicMock()
    mock_classifier.return_value = [
        [
            {"label": "T1055", "score": 0.92},
        ]
    ]
    mock_pipeline.return_value = mock_classifier

    classifier = TIEFClassifier(threshold=0.8)
    isr = classifier.generate_isr("Injected process XYZ", source_ref="decompiler_log")

    assert isr is not None
    assert isr.agent_id == "tief_classifier"
    assert isr.domain == "tief"
    assert len(isr.claims) == 1

    claim = isr.claims[0]
    assert claim.technique_id == "T1055"
    assert claim.confidence == 0.92
    assert claim.evidence_ref == "decompiler_log"
