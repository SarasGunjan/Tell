"""IBM Granite semantic embedding generation with deterministic caching."""
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional
import numpy as np
import torch
from sentence_transformers import SentenceTransformer

from src.granite.config import PRIMARY_MODEL_ID, DEFAULT_CACHE_DIR

logger = logging.getLogger("ThreatRank.GraniteEmbeddings")

_MODEL_CACHE: dict[tuple[str, str], SentenceTransformer] = {}


def detect_device(preferred: Optional[str] = None) -> str:
    """Automatically detects CUDA GPU availability and otherwise falls back to CPU."""
    if preferred:
        return preferred
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


def get_granite_embedding_model(
    model_id: str = PRIMARY_MODEL_ID,
    device: Optional[str] = None,
) -> SentenceTransformer:
    """Loads and caches the official IBM Granite embedding model locally."""
    resolved_device = detect_device(device)
    cache_key = (model_id, resolved_device)
    if cache_key in _MODEL_CACHE:
        return _MODEL_CACHE[cache_key]

    logger.info(f"Loading IBM Granite embedding model '{model_id}' on device '{resolved_device}'...")
    # On CPU, float32 avoids slow emulated bfloat16 ops on Windows x86_64
    model_kwargs = {"dtype": torch.float32} if resolved_device == "cpu" else {}

    try:
        model = SentenceTransformer(
            model_id,
            device=resolved_device,
            local_files_only=True,
            model_kwargs=model_kwargs,
        )
    except Exception:
        logger.info("Model not found in local offline cache; attempting Hugging Face Hub download...")
        model = SentenceTransformer(
            model_id,
            device=resolved_device,
            model_kwargs=model_kwargs,
        )

    _MODEL_CACHE[cache_key] = model
    return model


def compute_cache_key(
    cve_ids: list[str],
    descriptions: list[str],
    model_id: str,
    normalize_embeddings: bool = True,
    preprocess_version: str = "v1",
) -> str:
    """Computes a SHA-256 cache key accounting for CVE IDs, text, model ID, and preprocessing config."""
    hasher = hashlib.sha256()
    meta = f"{model_id}|norm={normalize_embeddings}|prep={preprocess_version}|n={len(cve_ids)}\n"
    hasher.update(meta.encode("utf-8"))
    for cid, desc in zip(cve_ids, descriptions):
        hasher.update(cid.encode("utf-8", errors="replace"))
        hasher.update(b"\t")
        hasher.update(desc.encode("utf-8", errors="replace"))
        hasher.update(b"\n")
    return hasher.hexdigest()[:24]


def generate_embeddings(
    cve_ids: list[str],
    descriptions: list[str],
    model_id: str = PRIMARY_MODEL_ID,
    batch_size: int = 64,
    cache_dir: Optional[str | Path] = DEFAULT_CACHE_DIR,
    normalize_embeddings: bool = True,
    device: Optional[str] = None,
    force_recompute: bool = False,
) -> tuple[np.ndarray, dict]:
    """
    Generates or loads cached IBM Granite semantic embeddings for vulnerability descriptions.

    Returns:
        embeddings: np.ndarray of shape (N, D) in float32
        metadata: dict with model_id, embedding_dim, cache_hit, cache_path, device
    """
    if len(cve_ids) != len(descriptions):
        raise ValueError(f"Length mismatch: {len(cve_ids)} cve_ids vs {len(descriptions)} descriptions.")
    if len(cve_ids) == 0:
        raise ValueError("Cannot generate embeddings for an empty record list.")

    cache_key = compute_cache_key(
        cve_ids=cve_ids,
        descriptions=descriptions,
        model_id=model_id,
        normalize_embeddings=normalize_embeddings,
    )

    cache_file: Optional[Path] = None
    meta_file: Optional[Path] = None
    if cache_dir is not None:
        cdir = Path(cache_dir)
        cdir.mkdir(parents=True, exist_ok=True)
        safe_model = model_id.replace("/", "_")
        cache_file = cdir / f"emb_{safe_model}_{len(cve_ids)}_{cache_key}.npz"
        meta_file = cdir / f"emb_{safe_model}_{len(cve_ids)}_{cache_key}.json"

        if not force_recompute and cache_file.exists():
            try:
                loaded = np.load(cache_file, allow_pickle=False)
                cached_vecs = loaded["embeddings"]
                cached_ids = loaded["cve_ids"].tolist()
                if cached_ids == list(cve_ids) and len(cached_vecs) == len(cve_ids):
                    logger.info(f"Loaded {len(cached_vecs):,} cached Granite embeddings from {cache_file.name}")
                    meta = {
                        "model_id": model_id,
                        "embedding_dim": int(cached_vecs.shape[1]),
                        "num_records": len(cached_vecs),
                        "cache_hit": True,
                        "cache_key": cache_key,
                        "cache_path": str(cache_file),
                        "device": detect_device(device),
                    }
                    return cached_vecs.astype(np.float32), meta
            except Exception as e:
                logger.warning(f"Cache read failed for {cache_file.name} ({e}); regenerating...")

    model = get_granite_embedding_model(model_id=model_id, device=device)
    # Cap max_seq_length to 256 tokens (~180 words) to prevent outlier 8192-token quadratic CPU stalls
    if getattr(model, "max_seq_length", 8192) > 256:
        model.max_seq_length = 256
    resolved_device = detect_device(device)
    logger.info(
        f"Encoding {len(descriptions):,} descriptions with '{model_id}' "
        f"(batch_size={batch_size}, device={resolved_device})..."
    )

    vectors = model.encode(
        descriptions,
        batch_size=batch_size,
        normalize_embeddings=normalize_embeddings,
        show_progress_bar=len(descriptions) >= 200,
        convert_to_numpy=True,
    ).astype(np.float32)

    if vectors.shape[0] != len(cve_ids):
        raise RuntimeError(f"Embedding output row count {vectors.shape[0]} != input count {len(cve_ids)}")

    meta = {
        "model_id": model_id,
        "embedding_dim": int(vectors.shape[1]),
        "num_records": len(vectors),
        "normalize_embeddings": normalize_embeddings,
        "cache_hit": False,
        "cache_key": cache_key,
        "cache_path": str(cache_file) if cache_file else None,
        "device": resolved_device,
    }

    if cache_file is not None and meta_file is not None:
        np.savez_compressed(
            cache_file,
            embeddings=vectors,
            cve_ids=np.array(cve_ids, dtype=str),
        )
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        logger.info(f"Saved embeddings to cache: {cache_file.name}")

    return vectors, meta
