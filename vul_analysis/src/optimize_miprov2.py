"""
MIPROv2 Optimization for SourceCodeCVEAgent.

Optimizes the CVE analysis agent using DSPy MIPROv2 teleprompter.
Includes all tools (NVD, WebSearch, SBOM, SourceCode, Reachability) via pre-built cache.
"""

import argparse
import json
import logging
import os
import sys
import io
import time
from datetime import datetime
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote
from tqdm import tqdm

import dspy
import mlflow
from dspy.teleprompt import MIPROv2

# Reuse from runner.py
from .runner import (
    configure_model,
    load_cases,
    stratify_and_split,
    evaluate_batch,
    resolve_sbom_path,
    clone_repo_at_ref,
    build_vdb,
    CallSourceCodeRetriever,
    VULHUB_DATASET,
    VULHUB_FP_DATASET,
    BASE_DIR,
    REPOS_DIR,
    VDB_CACHE_DIR,
)
from .agent import SourceCodeCVEAgent
from .metrics import composite_cve_metric
from .utils.mlflow_utils import setup_mlflow
from .utils.hybrid_vdb_creator import HybridVDBCreator, VDBConfig
from .tools import (
    NVDIntelTool,
    CVEWebSearchTool,
    SBOMPackageChecker,
    SourceCodeRetriever,
    CodeReachabilityAnalyzer,
)


CACHE_DIR = BASE_DIR / "vul_analysis" / ".cache" / "dspy_programs"


def _sanitize_dir_name(s: str) -> str:
    """Sanitize string for use in directory names."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def build_examples(rows: List[Dict[str, Any]]) -> List[dspy.Example]:
    """Build dspy.Example objects with full case data for tool building.
    
    Stores _case_data for tool creation but only cve_id is marked as input.
    """
    examples: List[dspy.Example] = []
    for r in rows:
        ex = dspy.Example(
            cve_id=r.get("CVE_ID", ""),
            csaf_vex_status=r.get("csaf_vex_status", ""),
            _case_data=r,  # Full case data for tool building
        ).with_inputs("cve_id")
        examples.append(ex)
    return examples


def create_tools_for_case(
    case: Dict[str, Any],
    logger: logging.Logger
) -> List[Any]:
    """Build all 5 tools for a specific CVE case.
    
    Uses cached VDB and repos - no clone/build overhead if already exists.
    """
    tools = [NVDIntelTool(), CVEWebSearchTool(logger=logger)]
    
    # SBOM Tool
    image = case.get("image", "")
    sbom_path = resolve_sbom_path(image, logger)
    if sbom_path:
        tools.append(SBOMPackageChecker(sbom_txt_path=str(sbom_path), logger=logger))
    
    # Source code tools require repo info
    repo_url = case.get("repository", "")
    repo_ref = case.get("vuln_ref", "")
    
    if repo_url and repo_ref:
        ref_clean = unquote(repo_ref)
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        dir_name = f"{_sanitize_dir_name(repo_name)}_{_sanitize_dir_name(ref_clean)}"
        repo_path = REPOS_DIR / dir_name
        
        # SourceCodeRetriever (uses cached VDB)
        def build_retriever():
            config = VDBConfig(
                repo_url=repo_url,
                repo_ref=repo_ref,
                cache_dir=VDB_CACHE_DIR,
                embedding_model="all-MiniLM-L6-v2",
            )
            creator = HybridVDBCreator(config)
            
            if creator.cache_exists():
                logger.info(f"VDB cache hit for {repo_ref}")
                vdb_engine = creator.create_or_load_vdb([], force_rebuild=False)
                return SourceCodeRetriever(vdb_engine=vdb_engine)
            
            # Need to build VDB - clone if needed
            cloned_path = clone_repo_at_ref(repo_url, repo_ref, logger)
            if not cloned_path:
                logger.warning(f"Clone failed for {repo_url}@{repo_ref}")
                return None
            vdb_engine = build_vdb(cloned_path, repo_url, repo_ref, logger)
            return SourceCodeRetriever(vdb_engine=vdb_engine)
        
        tools.append(CallSourceCodeRetriever(build_retriever, logger=logger))
        
        # CodeReachabilityAnalyzer
        reachability_analyzer = CodeReachabilityAnalyzer(
            retriever_func=None,
            repo_path=repo_path if repo_path.exists() else None,
            repo_ref=repo_ref,
            repo_url=repo_url
        )
        tools.append(reachability_analyzer.as_tool())
    
    return tools


def build_tools_cache(
    cases: List[Dict[str, Any]],
    logger: logging.Logger
) -> Dict[str, List[Any]]:
    """Pre-build tools for all cases. Uses cached VDB/repos."""
    cache = {}
    for i, case in enumerate(cases):
        cve_id = case.get("CVE_ID", "")
        logger.info(f"Building tools for {cve_id} ({i+1}/{len(cases)})")
        cache[cve_id] = create_tools_for_case(case, logger)
        logger.info(f"  -> {len(cache[cve_id])} tools ready")
    return cache


def main():
    parser = argparse.ArgumentParser(description="Optimize CVE ReAct agent with MIPROv2.")
    parser.add_argument("--auto", default=None, choices=["light", "medium", "heavy"], help="MIPROv2 auto mode")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--max-train", type=int, default=0, help="Max train examples (0=use DATASET_SPLITS)")
    parser.add_argument("--max-val", type=int, default=0, help="Max eval examples (0=use DATASET_SPLITS)")
    parser.add_argument("--num-threads", type=int, default=min(os.cpu_count() or 4, 8))
    parser.add_argument("--temperature", type=float, default=1)
    parser.add_argument("--model", default=None, help="Model name (prompts interactively if not set)")
    # Minibatch configuration for efficient Bayesian optimization
    parser.add_argument("--num-trials", type=int, default=None, choices=[15, 20, 25, 30], help="Number of MIPROv2 trials")
    parser.add_argument("--num-fewshot-candidates", type=int, default=None, choices=[6, 12, 18], help="Number of few-shot candidates")
    parser.add_argument("--num-instruct-candidates", type=int, default=None, choices=[3, 6, 9], help="Number of instruct candidates")
    parser.add_argument("--minibatch", type=bool, default=True, help="Use minibatch evaluation (reduces LLM calls)")
    parser.add_argument("--minibatch-size", type=int, default=15, help="Samples per trial (default: 5)")
    parser.add_argument("--minibatch-full-eval-steps", type=int, default=10, help="Full validation every N steps")
    # Grid search for hyperparameter tuning
    parser.add_argument("--grid-search", action="store_true", help="Enable grid search over init_temperature [0.9,1]")
    args = parser.parse_args()

    timestamp = time.strftime("%Y%m%d_%H%M%S")

    # Ensure stdout uses UTF-8 encoding on Windows
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    
    # Create StreamHandler with UTF-8 support
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[console_handler],
        force=True,
    )
    logger = logging.getLogger(__name__)

    #configure model
    _, model_name = configure_model(args.model, logger)
    safe_model_name = model_name.replace(".", "_").replace("-", "_")
    logger.info(f"Using model: {model_name}")
    
    # Setup save directory with model name
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    save_dir = CACHE_DIR / f"miprov2_{safe_model_name}_{timestamp}"
    save_dir.mkdir(parents=True, exist_ok=True)
    # Setup logging to save_dir
    log_path = save_dir / f"optimize_miprov2_{timestamp}.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logging.getLogger().addHandler(file_handler)  # Add to root logger, not just __main__
    logger.info(f"Logging to {log_path}")


    # Setup MLflow with optimizer tracking
    setup_mlflow(experiment_name="ContainerSecurity_MIPROv2_Optimize", log_optimizer=True)

    # Load datasets
    vulhub_cases = load_cases(VULHUB_DATASET)
    fp_cases = load_cases(VULHUB_FP_DATASET)
    
    if not vulhub_cases and not fp_cases:
        logger.error("No cases found in datasets")
        return

    logger.info(f"Loaded {len(vulhub_cases)} TP cases, {len(fp_cases)} FP cases")

    # Split data
    train_cases, eval_cases = stratify_and_split(
        vulhub_cases, fp_cases, model_name, seed=args.seed, eval_mode=True
    )
    
    # Apply max limits
    if args.max_train > 0:
        train_cases = train_cases[:args.max_train]
    if args.max_val > 0:
        eval_cases = eval_cases[:args.max_val]
    
    logger.info(f"Train examples: {len(train_cases)} | Eval examples: {len(eval_cases)}")

    # Pre-build tools cache for all cases
    logger.info("Pre-building tools cache for all cases...")
    all_cases = train_cases + eval_cases
    tools_cache = build_tools_cache(all_cases, logger)
    logger.info(f"Tools cache built for {len(tools_cache)} CVEs")
    
    # Default tools for unknown CVEs
    default_tools = [NVDIntelTool(), CVEWebSearchTool(logger=logger)]
    
    def get_tools_for_cve(cve_id: str) -> List[Any]:
        return tools_cache.get(cve_id, default_tools)

    # Build examples with case data
    trainset = build_examples(train_cases)
    devset = build_examples(eval_cases)

    # Custom metric that uses per-example tools
    def mipro_metric(example, pred=None, trace=None):
        """Metric that builds agent with case-specific tools and scores."""
        if pred is None:
            return 0.0  # MIPROv2 proposal phase
        
        cve_id = getattr(example, 'cve_id', '')
        tools = get_tools_for_cve(cve_id)
        
        # Create agent with case-specific tools
        agent = SourceCodeCVEAgent(tools=tools, logger=logger)
        actual_pred = agent(cve_id=cve_id)
        
        return composite_cve_metric(example, actual_pred)

    # Create initial agent for compilation (MIPROv2 needs a base agent)
    initial_tools = default_tools
    initial_agent = SourceCodeCVEAgent(tools=initial_tools, logger=logger)
    logger.info(f"Created initial agent with {len(initial_tools)} default tools")

    # Configure MIPROv2 with minibatch optimization
    # Minibatch reduces LLM calls by evaluating on small samples per trial
    # Full validation every N steps ensures quality selection
    minibatch_size = min(args.minibatch_size, len(trainset)) if args.minibatch else len(trainset)

    # Param grid for hyperparameter search (based on reference implementation)
    # max_bootstrapped_demos: 2 worked ~0.9% better than 0
    # init_temperature: higher temp adds exploration, 0.7-0.9 recommended
    # auto modes: medium consistently better than light (+1.3%)
    if args.grid_search:
        param_grid = {
            'max_bootstrapped_demos': [0, 2, 4],
            'init_temperature': [0.7, 1],
            'auto': ["light", "medium"],
        }
    else:
        param_grid = {
            'max_bootstrapped_demos': [2],
            'init_temperature': [args.temperature],
            'auto': [args.auto],
        }
    
    param_combinations = [
        dict(zip(param_grid.keys(), v)) 
        for v in product(*param_grid.values())
    ]
    
    logger.info(f"Param grid search: {len(param_combinations)} combinations")
    for p in param_combinations:
        logger.info(f"  - {p}")

    # Track best across param combinations
    best_score = 0.0
    best_params = None
    best_optimized = None
    best_run_id = None
    
    for params in tqdm(param_combinations, desc="Testing parameters"):
        run_name = f"miprov2_{model_name}_temp{params['init_temperature']}_{timestamp}"
        logger.info(f"\n{'='*50}")
        logger.info(f"Starting run: {run_name}")
        logger.info(f"Params: {params}")
        
        tp = MIPROv2(
            metric=mipro_metric,
            auto=params['auto'],
            num_threads=args.num_threads,
            max_bootstrapped_demos=params['max_bootstrapped_demos'],
            max_labeled_demos=0,
            init_temperature=params['init_temperature'],
        )

        with mlflow.start_run(run_name=run_name) as run:
            mlflow.log_params({
                "model": model_name,
                "auto_mode": params['auto'],
                "init_temperature": params['init_temperature'],
                "train_size": len(train_cases),
                "eval_size": len(eval_cases),
                "seed": args.seed,
                "num_threads": args.num_threads,
                "minibatch": args.minibatch,
                "minibatch_size": minibatch_size,
                "minibatch_full_eval_steps": args.minibatch_full_eval_steps,
            })
            
            try:
                optimized = tp.compile(
                    initial_agent,
                    trainset=trainset,
                    valset=devset,
                    # num_trials=args.num_trials,
                    # num_fewshot_candidates=args.num_fewshot_candidates,
                    # num_instruct_candidates=args.num_instruct_candidates,
                    minibatch=True,
                    minibatch_size=minibatch_size,
                    minibatch_full_eval_steps=args.minibatch_full_eval_steps,
                )
                logger.info("MIPROv2 compilation complete")

                # # Evaluate on devset
                # logger.info("Evaluating optimized agent on devset...")
                # evaluator = dspy.Evaluate(
                #     devset=devset,
                #     metric=mipro_metric,
                #     num_threads=args.num_threads,
                #     display_progress=True,
                #     display_table=5,
                # )
                # eval_score = evaluator(optimized)
                # score_value = float(getattr(eval_score, 'score', eval_score))
                # logger.info(f"Devset evaluation score: {score_value}")
                
                # mlflow.log_metric("eval_score", score_value)
                
                # # Track best
                # if score_value > best_score:
                #     best_score = score_value
                #     best_params = params.copy()
                #     best_optimized = optimized
                #     best_run_id = run.info.run_id
                #     logger.info(f"New best score: {best_score:.4f} with params: {best_params}")
                    
            except Exception as e:
                logger.error(f"Error with params {params}: {e}")
                mlflow.log_param("error", str(e))
                continue

    # Use best model (or last if no improvement)
    if best_optimized is None:
        logger.warning("No successful runs, using last optimized agent")
        best_optimized = optimized
        best_params = params
        # best_score = score_value

    logger.info(f"\n{'='*60}")
    logger.info(f"Best params: {best_params}")
    logger.info(f"Best score: {best_score:.4f}")

    
    state_file = save_dir / "state.json"
    best_optimized.save(str(state_file), save_program=False)
    logger.info(f"Saved JSON state to {state_file}")

    # Save optimization config
    config = {
        "model": model_name,
        "auto_mode": best_params['auto'],
        "init_temperature": best_params['init_temperature'],
        "train_size": len(trainset),
        "eval_size": len(devset),
        "eval_score": best_score,
        "seed": args.seed,
        "timestamp": timestamp,
        "tools_count": len(list(tools_cache.values())[0]) if tools_cache else 0,
        "minibatch": args.minibatch,
        "minibatch_size": minibatch_size,
        "minibatch_full_eval_steps": args.minibatch_full_eval_steps,
        "grid_search": args.grid_search,
        "best_run_id": best_run_id,
    }
    config_file = save_dir / "optimization_config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    logger.info(f"Saved config to {config_file}")

    # # Run full evaluation with best model
    # # Load the saved optimized agent to ensure evaluation uses the optimized program
    # logger.info("Loading saved optimized agent for final evaluation...")
    # loaded_agent = dspy.load(str(save_dir))
    # logger.info(f"Loaded optimized agent from {save_dir}")
    
    logger.info("Running full evaluation on eval_cases using evaluate_batch with optimized agent...")
    eval_results = evaluate_batch(cases=eval_cases, model_name=model_name, logger=logger, agent=best_optimized)
    
    eval_results_file = save_dir / "eval_results.json"
    with open(eval_results_file, "w", encoding="utf-8") as f:
        json.dump(eval_results, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved eval results to {eval_results_file}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"MIPRO Optimization Complete")
    print(f"{'='*60}")
    print(f"Model: {model_name}")
    print(f"Best params: {best_params}")
    print(f"Tools per CVE: {config['tools_count']}")
    print(f"Devset score: {best_score:.4f}")
    print(f"DHR: {eval_results['metadata']['DHR']}")
    print(f"F1-Score: {eval_results['predictions']['F1-Score']}")
    print(f"F2-Score: {eval_results['predictions']['F2-Score']}")
    print(f"{'='*60}")
    print(f"Saved to: {save_dir}")
    print(f"Log: {log_path}")
    print(f"{'='*60}\n")

    # Save best optimized agent
    best_optimized.save(str(save_dir), save_program=True)
    logger.info(f"Saved optimized program to {save_dir}")


if __name__ == "__main__":
    main()
