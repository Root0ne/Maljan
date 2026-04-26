"""TIEF (Threat Intelligence Extraction Framework) Classifier.

This module implements a local, lightweight NLP classifier (based on transformers)
to extract MITRE ATT&CK techniques deterministically from text (e.g. logs, decompiled code).
This acts as Layer 2 in the TTP Cascade Engine, reducing reliance on slow LLM calls
and eliminating LLM hallucinations for technique ID mapping.
"""

from typing import Any

try:
    from transformers import pipeline
except ImportError:
    pipeline = None  # type: ignore[assignment]

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


class TIEFClassifier:
    """NLP-based ATT&CK technique classifier."""

    def __init__(self, model_name: str = "distilbert-base-uncased", threshold: float = 0.6):
        """Initialize the classifier.

        Args:
            model_name: The HuggingFace model ID fine-tuned for ATT&CK mapping.
                        In production, a custom fine-tuned model path should be used.
            threshold: Minimum confidence score to accept a prediction.
        """
        self.model_name = model_name
        self.threshold = threshold
        self.classifier: Any = None

        # Lazy initialization to save memory if not used
        self._initialized = False

    def initialize(self) -> None:
        if self._initialized:
            return

        if pipeline is None:
            logger.warning("transformers library not installed. TIEF classifier disabled.")
            return

        try:
            logger.info("Loading TIEF classifier model: %s", self.model_name)
            # In a real scenario, this would be a multi-label classification pipeline
            # mapping to ATT&CK techniques.
            # We use 'text-classification' with top_k=None to get all scores if supported.
            self.classifier = pipeline(
                "text-classification", model=self.model_name, return_all_scores=True
            )
            self._initialized = True
        except Exception as e:
            logger.error("Failed to load TIEF model '%s': %s", self.model_name, e)

    def extract_techniques(self, text: str) -> list[dict[str, Any]]:
        """Extract MITRE ATT&CK techniques from text.

        Returns:
            List of dictionaries with 'technique_id' and 'score'.
        """
        if not self._initialized:
            self.initialize()

        if not self.classifier or not text.strip():
            return []

        # Truncate text to model max length (usually 512 tokens)
        # A proper implementation would chunk the text, but for simplicity
        # we take the first 2000 chars as a rough heuristic.
        safe_text = text[:2000]

        try:
            predictions = self.classifier(safe_text)[0]
            # Filter by threshold and map labels to T-codes
            results = []
            for pred in predictions:
                if pred["score"] >= self.threshold:
                    label = pred["label"]
                    # If the model is a generic one during development, we map its dummy labels
                    # In production, the model outputs "T1055" etc directly.
                    if not label.startswith("T1"):
                        # Mock mapping for standard transformers like distilbert
                        if label == "LABEL_1" or label == "POSITIVE":
                            label = "T1059"  # Command and Scripting Interpreter as a generic match
                        else:
                            continue

                    results.append({"technique_id": label, "score": pred["score"]})
            return results
        except Exception as e:
            logger.error("TIEF prediction failed: %s", e)
            return []

    def generate_isr(self, text: str, source_ref: str = "tief_nlp") -> AgentISR | None:
        """Process text and generate an AgentISR formatted report."""
        techniques = self.extract_techniques(text)

        if not techniques:
            return None

        claims = []
        for tech in techniques:
            claims.append(
                ClaimEvidence(
                    claim=f"TIEF model predicted {tech['technique_id']} from source.",
                    confidence=float(tech["score"]),
                    technique_id=tech["technique_id"],
                    evidence_ref=source_ref,
                )
            )

        return AgentISR(
            agent_id="tief_classifier",
            domain="tief",
            claims=claims,
            revision_round=0,
        )
