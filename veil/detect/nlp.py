"""Optional name / place / organisation detection via Microsoft Presidio + spaCy.

Install:  pip install ".[nlp]"  &&  python -m spacy download en_core_web_sm
Enable:   VEIL_NLP=1   (optional: VEIL_NLP_MODEL=en_core_web_lg for better accuracy)
"""
from __future__ import annotations

import os

from .engine import Match

_MAP = {"PERSON": "PERSON", "LOCATION": "LOCATION", "ORGANIZATION": "ORG", "NRP": "ORG"}


class PresidioNER:
    def __init__(self, model: str | None = None, min_score: float = 0.6):
        model = model or os.environ.get("VEIL_NLP_MODEL", "en_core_web_sm")
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("VEIL_NLP=1 needs: pip install '.[nlp]'") from e
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            }
        )
        self._engine = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        self._min = min_score

    def find(self, text: str) -> list[Match]:  # pragma: no cover - needs spaCy model
        res = self._engine.analyze(text=text, language="en", entities=list(_MAP), score_threshold=self._min)
        return [
            Match(r.start, r.end, _MAP[r.entity_type], text[r.start : r.end], 10, "nlp") for r in res
        ]
