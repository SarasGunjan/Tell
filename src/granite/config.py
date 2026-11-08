"""Configuration constants and path resolution for the IBM Granite pipeline."""
import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXTERNAL_DATASET_DIR = Path(r"c:\Users\johnj\OneDrive\Documentos\Datathon 2026\dataset\data\data")
DEFAULT_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "outputs" / "granite"
DEFAULT_CACHE_DIR = PROJECT_ROOT / ".cache" / "granite"

PRIMARY_MODEL_ID = "ibm-granite/granite-embedding-small-english-r2"
PRIMARY_EMBEDDING_DIM = 384
OPTIONAL_INSTRUCT_MODEL_ID = "ibm-granite/granite-3.1-2b-instruct"

# Suffix-agnostic canonical dataset filename aliases
DATASET_ALIASES = {
    "vulnerabilities": ["vulnerabilities.csv", "vulnerabilities(4).csv"],
    "weakness_types": ["weakness_types.csv", "weakness_types(3).csv"],
    "known_exploited": ["known_exploited.csv", "known_exploited(4).csv"],
    "affected_products": ["affected_products.csv", "affected_products(2).csv"],
    "exploit_signals_2024": ["exploit_signals_2024.csv", "exploit_signals_2024(4).csv"],
    "exploit_signals_2025": ["exploit_signals_2025.csv", "exploit_signals_2025(3).csv"],
    "references": ["references.csv", "references(2).csv"],
    "scoreboard_2026": ["scoreboard_2026.csv", "scoreboard_2026(4).csv"],
}


def resolve_dataset_path(path_or_name: str | Path, search_dirs: Optional[list[Path]] = None) -> Path:
    """Resolves a dataset path, handling browser suffixes like (4).csv and fallback directories."""
    candidate = Path(path_or_name)
    if candidate.exists():
        return candidate.resolve()

    # Strip browser download suffix like (2), (3), (4) before extension
    stem_clean = re.sub(r"\(\d+\)$", "", candidate.stem)
    unsuffixed_name = f"{stem_clean}{candidate.suffix}"

    # Check in the same parent directory without suffix
    if candidate.parent and (candidate.parent / unsuffixed_name).exists():
        return (candidate.parent / unsuffixed_name).resolve()

    dirs = search_dirs or [
        DEFAULT_RAW_DIR,
        PROJECT_ROOT / "data",
        EXTERNAL_DATASET_DIR,
    ]
    for d in dirs:
        for name_variant in [candidate.name, unsuffixed_name]:
            p = Path(d) / name_variant
            if p.exists():
                return p.resolve()

    raise FileNotFoundError(
        f"Dataset file '{path_or_name}' not found. Checked exact path and fallback directories: "
        f"{[str(d) for d in dirs]}"
    )


@dataclass
class GraniteConfig:
    """Configuration for a Granite pipeline run."""
    input_path: Path
    output_dir: Path = DEFAULT_OUTPUT_DIR
    cache_dir: Path = DEFAULT_CACHE_DIR
    model_id: str = PRIMARY_MODEL_ID
    limit: Optional[int] = 100
    clusters: int = 5
    batch_size: int = 64
    seed: int = 42
    id_column: str = "cve_id"
    text_column: str = "description"
    case_mode: str = "lower"  # 'lower' or 'upper' for remote_local / auth_required
    run_research: bool = False
    fit_cohort_mode: str = "sample"  # 'sample', 'historical', 'fit_and_assign_benchmark'
    kev_path: Optional[Path] = None
    weakness_path: Optional[Path] = None
    scoreboard_path: Optional[Path] = None
    device: Optional[str] = None

