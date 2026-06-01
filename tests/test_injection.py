"""Injection-detector quality tests against curated positive + negative corpora.

Publishes precision / recall / specificity so the README has citable numbers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentgate.middleware.injection import detect

CORPORA = Path(__file__).resolve().parent / "corpora"


def _lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


POSITIVE = _lines(CORPORA / "injection_positive.txt")
NEGATIVE = _lines(CORPORA / "injection_negative.txt")


@pytest.mark.parametrize("example", POSITIVE)
def test_each_positive_is_flagged(example: str) -> None:
    hits = detect([example])
    assert hits, f"positive not flagged: {example!r}"


@pytest.mark.parametrize("example", NEGATIVE)
def test_each_negative_is_not_flagged(example: str) -> None:
    hits = detect([example])
    assert not hits, f"false positive on benign string: {example!r} -> {hits}"


def test_metrics_report() -> None:
    """Compute and print precision, recall, F1, specificity over the full corpora."""
    tp = sum(1 for s in POSITIVE if detect([s]))
    fn = len(POSITIVE) - tp
    tn = sum(1 for s in NEGATIVE if not detect([s]))
    fp = len(NEGATIVE) - tn

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    print()  # rich pytest output starts on a fresh line
    print(f"injection corpus:  positives={len(POSITIVE)} negatives={len(NEGATIVE)}")
    print(f"  TP={tp} FN={fn} TN={tn} FP={fp}")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}  specificity={specificity:.3f}")
    # The bar is set high; assertions ratchet up as the corpus grows.
    assert precision >= 0.90, f"precision too low: {precision}"
    assert recall >= 0.90, f"recall too low: {recall}"
    assert specificity >= 0.90, f"specificity too low: {specificity}"
