"""
ThreatRank Member 2 — End-to-End IBM Granite Intelligence & Research Pipeline CLI.

Example MVP Usage:
    python -m src.granite.pipeline --input "data/raw/vulnerabilities(4).csv" --limit 100 --clusters 5

Example Historical Research + 2026 Benchmark Fit/Assign Usage:
    python -m src.granite.pipeline --input "data/raw/vulnerabilities(4).csv" --limit 10000 --clusters 10 --research --benchmark "data/raw/scoreboard_2026(4).csv"
"""
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional
import numpy as np
import pandas as pd

from src.granite.config import (
    DEFAULT_CACHE_DIR,
    DEFAULT_OUTPUT_DIR,
    PRIMARY_MODEL_ID,
    resolve_dataset_path,
)
from src.granite.load_data import (
    load_and_prepare_vulnerabilities,
    load_kev_catalog,
    load_scoreboard_2026,
    load_weakness_types,
)
from src.granite.embeddings import generate_embeddings
from src.granite.extraction import extract_features_dataframe
from src.granite.clustering import (
    derive_family_names_and_representatives,
    fit_semantic_clusters,
    load_cluster_model,
    predict_semantic_clusters,
    save_cluster_model,
)
from src.granite.cwe_analysis import (
    compute_cwe_semantic_table,
    find_cross_cwe_semantic_pairs,
)
from src.granite.family_analysis import (
    compute_family_kev_statistics,
    evaluate_granite_vs_baselines,
    evaluate_leakage_free_temporal_split,
)
from src.granite.export import (
    build_output_tables,
    export_deliverables,
    validate_outputs,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ThreatRank.GranitePipeline")


def run_pipeline(
    input_path: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    limit: Optional[int] = 100,
    clusters: int = 5,
    batch_size: int = 64,
    seed: int = 42,
    id_column: str = "cve_id",
    text_column: str = "description",
    model_id: str = PRIMARY_MODEL_ID,
    run_research: bool = False,
    published_after: Optional[str] = None,
    published_before: Optional[str] = None,
    benchmark_path: Optional[str | Path] = None,
    benchmark_limit: Optional[int] = None,
    benchmark_output_dir: Optional[str | Path] = None,
    case_mode: str = "lower",
    device: Optional[str] = None,
) -> dict:
    """
    Executes the IBM Granite embedding, clustering, extraction, research, and export workflow.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    c_dir = Path(cache_dir)
    c_dir.mkdir(parents=True, exist_ok=True)

    # Load KEV catalog early if available
    kev_df = None
    kev_cve_set = None
    try:
        kev_df = load_kev_catalog()
        if run_research:
            kev_cve_set = set(kev_df["cve_id"])
    except Exception as e:
        logger.warning(f"Could not load KEV catalog: {e}")

    # 1. Load & prepare vulnerability cohort
    df = load_and_prepare_vulnerabilities(
        input_path=input_path,
        id_column=id_column,
        text_column=text_column,
        limit=limit,
        published_after=published_after,
        published_before=published_before,
        stratified_kev_cves=kev_cve_set,
        seed=seed,
    )

    # 2. Generate or load cached IBM Granite semantic embeddings
    embeddings, emb_meta = generate_embeddings(
        cve_ids=df["cve_id"].tolist(),
        descriptions=df["description"].tolist(),
        model_id=model_id,
        batch_size=batch_size,
        cache_dir=c_dir,
        normalize_embeddings=True,
        device=device,
    )

    # 3. Extract structured + deterministic technical attributes
    df = extract_features_dataframe(df, case_mode=case_mode)

    # 4. Fit semantic clustering model
    cluster_model, labels, cluster_metrics = fit_semantic_clusters(
        embeddings=embeddings,
        n_clusters=clusters,
        seed=seed,
    )
    df["family_id"] = labels.astype(int)

    # Load optional CWE lookup if available
    weakness_df = None
    weakness_lookup = {}
    try:
        weakness_df = load_weakness_types()
        weakness_lookup = dict(zip(weakness_df["cwe_id"], weakness_df["name"]))
    except Exception:
        logger.debug("Optional weakness_types.csv not loaded; proceeding without CWE names.")

    # 5. Inspect representatives & derive truthful human-readable family names
    family_name_map, cluster_details = derive_family_names_and_representatives(
        df=df,
        embeddings=embeddings,
        model=cluster_model,
        labels=labels,
        weakness_lookup=weakness_lookup,
    )
    df["family_name"] = df["family_id"].map(family_name_map)

    # Save fitted clustering model for benchmark stability
    model_save_path = c_dir / f"fitted_kmeans_k{clusters}_seed{seed}.pkl"
    save_cluster_model(
        model=cluster_model,
        family_name_map=family_name_map,
        save_path=model_save_path,
        metadata={
            "model_id": model_id,
            "n_clusters": clusters,
            "seed": seed,
            "train_records": len(df),
            "mean_cosine_cohesion": cluster_metrics["mean_cosine_cohesion"],
            "silhouette_cosine": cluster_metrics["silhouette_cosine"],
        },
    )

    # 6. Historical KEV & CWE Research Analysis
    kev_stats_df = pd.DataFrame()
    kev_meta = {}
    cwe_table = pd.DataFrame()
    cross_cwe_pairs = []
    baseline_df = pd.DataFrame()

    if kev_df is not None:
        try:
            kev_stats_df, kev_meta = compute_family_kev_statistics(
                df=df,
                kev_df=kev_df,
                cutoff_date="2025-12-31",
                exclude_published_after="2025-12-31",
            )
        except Exception as e:
            logger.warning(f"Could not compute historical KEV statistics: {e}")

    if run_research:
        logger.info("Running CWE vs. Semantic Family comparison & baseline evaluation...")
        cwe_out_path = out_dir / "cwe_semantic_analysis.csv"
        cwe_table = compute_cwe_semantic_table(
            df=df,
            weakness_df=weakness_df,
            output_path=cwe_out_path,
        )
        cross_cwe_pairs = find_cross_cwe_semantic_pairs(
            df=df,
            embeddings=embeddings,
            top_k=10,
        )
        if kev_df is not None and len(kev_stats_df) > 0:
            hist_mask = (
                df["published"].astype(str) <= "2025-12-31"
                if "published" in df.columns
                else pd.Series([True] * len(df))
            )
            if int(hist_mask.sum()) >= clusters * 2:
                baseline_df = evaluate_granite_vs_baselines(
                    df=df[hist_mask].reset_index(drop=True),
                    granite_labels=labels[hist_mask.to_numpy()],
                    kev_df=kev_df,
                    n_clusters=clusters,
                    seed=seed,
                )
                baseline_df.to_csv(out_dir / "baseline_comparison.csv", index=False)

            if "published" in df.columns:
                m24 = (df["published"].astype(str) >= "2024-01-01") & (df["published"].astype(str) <= "2024-12-31")
                m25 = (df["published"].astype(str) >= "2025-01-01") & (df["published"].astype(str) <= "2025-12-31")
                if int(m24.sum()) >= clusters * 2 and int(m25.sum()) >= clusters * 2:
                    temporal_df, temporal_meta = evaluate_leakage_free_temporal_split(
                        df_2024=df[m24].reset_index(drop=True),
                        emb_2024=embeddings[m24.to_numpy()],
                        df_2025=df[m25].reset_index(drop=True),
                        emb_2025=embeddings[m25.to_numpy()],
                        kev_df=kev_df,
                        n_clusters=clusters,
                        seed=seed,
                    )
                    temporal_df.to_csv(out_dir / "temporal_validation_2024_2025.csv", index=False)
                    kev_meta["temporal_validation_2024_2025"] = temporal_meta

    # 7. Build, validate, and export the three required CSV deliverables
    granite_features_df, families_df, family_summary_df = build_output_tables(
        df=df,
        family_name_map=family_name_map,
        cluster_details=cluster_details,
        kev_stats_df=kev_stats_df if len(kev_stats_df) > 0 else None,
    )
    exported_paths = export_deliverables(
        granite_features_df=granite_features_df,
        families_df=families_df,
        family_summary_df=family_summary_df,
        output_dir=out_dir,
    )

    # Save research summary JSON artifact if requested
    if run_research:
        research_report = {
            "embedding_metadata": {k: v for k, v in emb_meta.items() if k != "point_cosine_similarities"},
            "clustering_metrics": {
                k: v for k, v in cluster_metrics.items() if k != "point_cosine_similarities"
            },
            "kev_summary": kev_meta,
            "cluster_details": cluster_details,
            "cross_cwe_semantic_pairs": cross_cwe_pairs,
            "baseline_comparison": baseline_df.to_dict(orient="records") if len(baseline_df) > 0 else [],
        }
        with open(out_dir / "research_metrics.json", "w", encoding="utf-8") as f:
            json.dump(research_report, f, indent=2)

    # 8. Optional 2026 Benchmark Assignment using the saved clustering model (no refitting!)
    benchmark_result = None
    if benchmark_path is not None:
        logger.info(f"Processing 2026 target benchmark from {benchmark_path} using saved fitted cluster model...")
        sb_df = load_scoreboard_2026(benchmark_path)
        if benchmark_limit is not None and benchmark_limit > 0:
            sb_df = sb_df.head(benchmark_limit).copy()

        # Load full descriptions for benchmark CVEs from input_path
        bench_vulns = load_and_prepare_vulnerabilities(
            input_path=input_path,
            id_column=id_column,
            text_column=text_column,
            limit=None,
            filter_cve_ids=set(sb_df["cve_id"]),
        )
        # Preserve exact benchmark CVE order and handle any hypothetical missing descriptions
        merged_bench = pd.merge(
            sb_df[["cve_id"]],
            bench_vulns,
            on="cve_id",
            how="left",
        )
        merged_bench["description"] = merged_bench["description"].fillna("No description provided.")

        bench_emb, _ = generate_embeddings(
            cve_ids=merged_bench["cve_id"].tolist(),
            descriptions=merged_bench["description"].tolist(),
            model_id=model_id,
            batch_size=batch_size,
            cache_dir=c_dir,
            normalize_embeddings=True,
            device=device,
        )

        saved_bundle = load_cluster_model(model_save_path)
        fitted_km = saved_bundle["model"]
        saved_name_map = saved_bundle["family_name_map"]

        bench_labels, _ = predict_semantic_clusters(fitted_km, bench_emb)
        merged_bench = extract_features_dataframe(merged_bench, case_mode=case_mode)
        merged_bench["family_id"] = bench_labels.astype(int)
        merged_bench["family_name"] = merged_bench["family_id"].map(saved_name_map)

        _, bench_details = derive_family_names_and_representatives(
            df=merged_bench,
            embeddings=bench_emb,
            model=fitted_km,
            labels=bench_labels,
            weakness_lookup=weakness_lookup,
        )

        # Carry historical KEV rates from the fitted historical cohort into benchmark family_summary
        b_feat, b_fam, b_sum = build_output_tables(
            df=merged_bench,
            family_name_map=saved_name_map,
            cluster_details=bench_details,
            kev_stats_df=kev_stats_df if len(kev_stats_df) > 0 else None,
        )
        b_out_dir = Path(benchmark_output_dir) if benchmark_output_dir else (out_dir / "benchmark_2026")
        b_paths = export_deliverables(b_feat, b_fam, b_sum, output_dir=b_out_dir)
        benchmark_result = {
            "benchmark_rows": len(b_feat),
            "paths": {k: str(v) for k, v in b_paths.items()},
        }

    return {
        "records_processed": len(df),
        "n_clusters": clusters,
        "embedding_dim": emb_meta["embedding_dim"],
        "cache_hit": emb_meta["cache_hit"],
        "mean_cosine_cohesion": cluster_metrics["mean_cosine_cohesion"],
        "silhouette_cosine": cluster_metrics["silhouette_cosine"],
        "output_paths": {k: str(v) for k, v in exported_paths.items()},
        "model_save_path": str(model_save_path),
        "benchmark_result": benchmark_result,
    }


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ThreatRank Member 2 — IBM Granite Semantic Intelligence & Research Pipeline"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to vulnerability CSV (e.g., data/raw/vulnerabilities(4).csv)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory for generated CSV deliverables (default: outputs/granite)",
    )
    parser.add_argument(
        "--cache-dir",
        default=str(DEFAULT_CACHE_DIR),
        help="Directory for embedding and fitted model caches (default: .cache/granite)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of vulnerability records to process (use 0 or negative for all)",
    )
    parser.add_argument(
        "--clusters",
        type=int,
        default=5,
        help="Number of semantic vulnerability families (K-Means clusters)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="Batch size for IBM Granite embedding generation",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible clustering",
    )
    parser.add_argument(
        "--id-column",
        default="cve_id",
        help="Column name for CVE identifier",
    )
    parser.add_argument(
        "--text-column",
        default="description",
        help="Column name for vulnerability description text",
    )
    parser.add_argument(
        "--model-id",
        default=PRIMARY_MODEL_ID,
        help=f"Hugging Face model ID (default: {PRIMARY_MODEL_ID})",
    )
    parser.add_argument(
        "--published-after",
        default=None,
        help="Optional minimum publication date filter (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--published-before",
        default=None,
        help="Optional maximum publication date filter (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--research",
        action="store_true",
        help="Run extended CWE vs. semantic family and baseline value-add research analyses",
    )
    parser.add_argument(
        "--benchmark",
        default=None,
        help="Optional path to scoreboard_2026.csv to assign stable benchmark family IDs",
    )
    parser.add_argument(
        "--benchmark-limit",
        type=int,
        default=None,
        help="Optional limit on benchmark rows for fast testing",
    )
    parser.add_argument(
        "--benchmark-output-dir",
        default=None,
        help="Optional output directory for 2026 benchmark CSV outputs",
    )
    parser.add_argument(
        "--case-mode",
        choices=["lower", "upper"],
        default="lower",
        help="Case formatting for remote_local and auth_required ('lower' or 'upper')",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    eff_limit = args.limit if (args.limit is not None and args.limit > 0) else None
    summary = run_pipeline(
        input_path=args.input,
        output_dir=args.output_dir,
        cache_dir=args.cache_dir,
        limit=eff_limit,
        clusters=args.clusters,
        batch_size=args.batch_size,
        seed=args.seed,
        id_column=args.id_column,
        text_column=args.text_column,
        model_id=args.model_id,
        run_research=args.research,
        published_after=args.published_after,
        published_before=args.published_before,
        benchmark_path=args.benchmark,
        benchmark_limit=args.benchmark_limit,
        benchmark_output_dir=args.benchmark_output_dir,
        case_mode=args.case_mode,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
