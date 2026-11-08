"""Tests for semantic clustering and benchmark assignment consistency."""
import numpy as np
import pandas as pd
import pytest
from pathlib import Path
from src.granite.clustering import (
    fit_semantic_clusters,
    predict_semantic_clusters,
    save_cluster_model,
    load_cluster_model,
    derive_family_names_and_representatives,
)


def test_invalid_cluster_counts():
    rng = np.random.default_rng(42)
    emb = rng.normal(size=(5, 16)).astype(np.float32)
    with pytest.raises(ValueError, match="Invalid n_clusters"):
        fit_semantic_clusters(emb, n_clusters=1, seed=42)
    with pytest.raises(ValueError, match="Invalid n_clusters"):
        fit_semantic_clusters(emb, n_clusters=10, seed=42)


def test_reproducible_clustering_and_benchmark_consistency(tmp_path: Path):
    rng = np.random.default_rng(42)
    # Create 3 well-separated synthetic clusters in 16-D
    c1 = rng.normal(loc=2.0, scale=0.1, size=(10, 16))
    c2 = rng.normal(loc=-2.0, scale=0.1, size=(10, 16))
    c3 = rng.normal(loc=0.0, scale=0.1, size=(10, 16))
    c3[:, 0] = 5.0
    emb = np.vstack([c1, c2, c3]).astype(np.float32)

    model1, labels1, metrics1 = fit_semantic_clusters(emb, n_clusters=3, seed=42)
    model2, labels2, _ = fit_semantic_clusters(emb, n_clusters=3, seed=42)
    assert np.array_equal(labels1, labels2)
    assert metrics1["n_clusters"] == 3
    assert len(labels1) == 30

    df = pd.DataFrame({
        "cve_id": [f"CVE-2024-{1000+i}" for i in range(30)],
        "description": (
            ["Remote SQL injection in web login"] * 10
            + ["Local buffer overflow in kernel driver"] * 10
            + ["Cross-site scripting (XSS) in comment field"] * 10
        ),
    })
    name_map, details = derive_family_names_and_representatives(df, emb, model1, labels1)
    assert len(name_map) == 3
    assert sum(d["size"] for d in details.values()) == 30

    # Save and reload fitted model to verify benchmark assignment stability without refitting
    save_path = save_cluster_model(model1, name_map, tmp_path / "km.pkl")
    loaded = load_cluster_model(save_path)
    pred_labels, _ = predict_semantic_clusters(loaded["model"], emb)
    assert np.array_equal(labels1, pred_labels)

