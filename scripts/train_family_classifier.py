"""Offline trainer for the static-feature malware-family classifier (§4 workstream).

Produces the model artifact that ``maljan.analysis.family_classifier`` loads at
runtime. This is an OPERATOR / OFFLINE script — it is never imported by the
pipeline and its heavy deps (ember, lightgbm, scikit-learn, joblib) are NOT
runtime dependencies of Maljan; install them only when training:

    uv pip install lightgbm scikit-learn joblib numpy
    # EMBER's feature extractor (feature parity with inference):
    uv pip install git+https://github.com/elastic/ember.git

FEATURE PARITY is the whole point: inference (``family_classifier._extract_features``)
and this trainer both use EMBER's ``PEFeatureExtractor``, so the vectors are
identical by construction. Do not swap in a different extractor for one side only.

Training data — two interchangeable / combinable sources:
  * ``--samples-dir DIR``   a folder-per-family tree of RAW binaries (e.g. the
                            Ultimate-RAT-Collection ingested for §U1). Features are
                            extracted on the fly with the SAME EMBER extractor, so
                            parity is guaranteed. This is the recommended path.
  * ``--features X.npy --labels y.csv``  pre-extracted EMBER feature matrix + a
                            one-family-per-row label file (e.g. MABEL re-vectorised
                            with EMBER, or your own export). ``X`` must be EMBER
                            feature-version 2 vectors to match inference.

Artifact (joblib): ``{"estimator", "families", "ember_feature_version": 2}``.
``estimator`` exposes ``predict_proba`` + ``classes_`` (LightGBM or sklearn).

Run:
    uv run python scripts/train_family_classifier.py --samples-dir ./rats \
        --out models/family_classifier_v1.joblib --min-per-family 10
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)
    return 2


def _load_deps():  # noqa: ANN202 - operator script, deps resolved at call time
    """Import the heavy training deps with a clear message if any is missing."""
    try:
        import joblib  # noqa: F401
        import numpy as np  # noqa: F401
        from ember import PEFeatureExtractor  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            _fail(
                f"missing training dependency ({exc}). Install with:\n"
                "  uv pip install lightgbm scikit-learn joblib numpy\n"
                "  uv pip install git+https://github.com/elastic/ember.git"
            )
        ) from exc


def _features_from_samples_dir(root: Path):  # noqa: ANN202
    """Yield (feature_vector, family) from a folder-per-family raw-binary tree."""
    import numpy as np
    from ember import PEFeatureExtractor

    extractor = PEFeatureExtractor(print_feature_warning=False)
    for fam_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        family = fam_dir.name
        for f in sorted(fam_dir.rglob("*")):
            if not f.is_file():
                continue
            try:
                vec = np.array(extractor.feature_vector(f.read_bytes()), dtype="float32")
            except Exception as exc:  # noqa: BLE001 - skip unparseable members
                print(f"  skip {f.name}: {exc}", flush=True)
                continue
            yield vec, family


def _load_pre_extracted(features_path: Path, labels_path: Path):  # noqa: ANN202
    import numpy as np

    x = np.load(features_path)
    families = [ln.strip() for ln in labels_path.read_text().splitlines() if ln.strip()]
    if len(families) != x.shape[0]:
        raise SystemExit(_fail(f"label count {len(families)} != feature rows {x.shape[0]}"))
    return list(x), families


def _build_estimator():  # noqa: ANN202
    """LightGBM multiclass if available, else sklearn GradientBoosting."""
    try:
        from lightgbm import LGBMClassifier

        return LGBMClassifier(
            objective="multiclass", n_estimators=300, learning_rate=0.05, num_leaves=64
        )
    except ImportError:
        from sklearn.ensemble import HistGradientBoostingClassifier

        print("lightgbm not found — using sklearn HistGradientBoostingClassifier.", flush=True)
        return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05)


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the static-feature family classifier.")
    ap.add_argument("--samples-dir", type=str, help="Folder-per-family raw-binary tree.")
    ap.add_argument("--features", type=str, help="Pre-extracted EMBER feature matrix (.npy).")
    ap.add_argument("--labels", type=str, help="One-family-per-row label file (with --features).")
    ap.add_argument("--out", type=str, default="models/family_classifier_v1.joblib")
    ap.add_argument("--min-per-family", type=int, default=10, help="Drop rarer families.")
    ap.add_argument("--test-frac", type=float, default=0.2, help="Held-out fraction for the card.")
    args = ap.parse_args()

    _load_deps()
    import joblib
    import numpy as np
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split

    # 1. Gather (vector, family) pairs.
    vectors: list = []
    labels: list[str] = []
    if args.samples_dir:
        root = Path(args.samples_dir)
        if not root.is_dir():
            return _fail(f"--samples-dir not found: {root}")
        for vec, fam in _features_from_samples_dir(root):
            vectors.append(vec)
            labels.append(fam)
    if args.features:
        if not args.labels:
            return _fail("--features requires --labels.")
        vv, ll = _load_pre_extracted(Path(args.features), Path(args.labels))
        vectors.extend(vv)
        labels.extend(ll)
    if not vectors:
        return _fail("no training data — pass --samples-dir and/or --features/--labels.")

    # 2. Drop families below the support threshold (too few to learn / evaluate).
    counts = Counter(labels)
    keep = {fam for fam, n in counts.items() if n >= args.min_per_family}
    if len(keep) < 2:
        return _fail(
            f"only {len(keep)} family(ies) meet --min-per-family={args.min_per_family}; "
            "need >=2. Lower the threshold or add data."
        )
    xy = [(v, fam) for v, fam in zip(vectors, labels, strict=True) if fam in keep]
    x = np.vstack([v for v, _ in xy])
    y = np.array([fam for _, fam in xy])
    print(
        f"Training on {x.shape[0]} samples, {len(keep)} families, {x.shape[1]} features.",
        flush=True,
    )

    # 3. Train + held-out card.
    x_tr, x_te, y_tr, y_te = train_test_split(
        x, y, test_size=args.test_frac, random_state=0, stratify=y
    )
    est = _build_estimator()
    est.fit(x_tr, y_tr)
    print("\n=== Held-out classification report ===", flush=True)
    print(classification_report(y_te, est.predict(x_te), zero_division=0), flush=True)

    # 4. Persist the artifact in the contract family_classifier.load_classifier expects.
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"estimator": est, "families": sorted(keep), "ember_feature_version": 2}, out_path)
    print(f"\nWrote model: {out_path} ({len(keep)} families).", flush=True)
    print(
        "Enable at runtime with PREPROCESSING__USE_STATIC_FEATURE_CLASSIFIER=true and "
        f"PREPROCESSING__STATIC_CLASSIFIER_MODEL_PATH={out_path}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
