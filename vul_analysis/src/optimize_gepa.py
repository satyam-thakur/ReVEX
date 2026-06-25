"""
GEPA Optimization for SourceCodeCVEAgent.

Optimizes the CVE analysis agent using DSPy GEPA (Generative Expert Prompt Advisor).
GEPA is a reflective prompt optimizer that leverages rich textual feedback for 
sample-efficient optimization.

Includes all tools (NVD, WebSearch, SBOM, SourceCode, Reachability) via pre-built cache.
"""

import argparse
import json
import logging
import os
import sys
import io
import time
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Optional

import dspy
import mlflow
from dspy.teleprompt import GEPA
from gepa.utils.stop_condition import NoImprovementStopper
from tqdm import tqdm

# Reuse from runner.py and optimize_miprov2.py
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

# Reuse from optimize_miprov2.py
from .optimize_miprov2 import (
    _sanitize_dir_name,
    build_examples,
    create_tools_for_case,
    build_tools_cache,
)

from .agent import SourceCodeCVEAgent
from .metrics import (
    composite_cve_metric,
    VALID_JUSTIFICATIONS,
)
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


def gepa_feedback_metric(
    example: Any,
    prediction: Any = None,
    trace: Any = None,
    pred_name: Optional[str] = None,
    pred_trace: Optional[Any] = None
) -> dspy.Prediction:
    """
    GEPA-compatible feedback metric for CVE vulnerability analysis.
    
    Returns dspy.Prediction(score=..., feedback=...) with concise, actionable feedback
    focused on decision correctness and tool usage for GEPA's reflective optimization.
    
    Args:
        example: Ground truth with 'csaf_vex_status' attribute
        prediction: DSPy prediction object with agent outputs
        trace: Optional execution trace
        pred_name: Name of the prediction (used by GEPA)
        pred_trace: Prediction trace (used by GEPA)
    
    Returns:
        dspy.Prediction with 'score' (float 0-1) and 'feedback' (str) fields
    """
    if prediction is None:
        return dspy.Prediction(score=0.0, feedback="No prediction provided.")
    
    try:
        # Extract values
        expected = getattr(example, 'csaf_vex_status', 'not_affected')
        predicted = getattr(prediction, 'csaf_vex_status', 'not_affected')
        status_justification = getattr(prediction, 'status_justification', '')
        cve_id = getattr(example, 'cve_id', getattr(example, 'CVE_ID', 'Unknown'))
        trajectory = getattr(prediction, 'trajectory', {})
        
        # Normalize
        expected = str(expected).strip().lower()
        predicted = str(predicted).strip().lower()
        is_correct = (expected == predicted)
        
        # Get composite score
        score, metrics = composite_cve_metric(
            example, prediction, trace=trace, return_details=True
        )
        
        # Build concise feedback
        feedback_parts = []
        
        # 1. Decision outcome (essential)
        if is_correct:
            feedback_parts.append(f"✓ Correct: {cve_id} is '{predicted}'")
        else:
            error_type = 'False Positive' if predicted == 'affected' else 'False Negative'
            feedback_parts.append(
                f"✗ Incorrect: Predicted '{predicted}' but expected '{expected}' for {cve_id}. "
                f"This is a {error_type}. Review tool evidence to identify missed signals."
            )
        
        # 2. Justification validity (only if invalid)
        if predicted == 'not_affected':
            just_lower = status_justification.lower().replace(' ', '_') if status_justification else ''
            if just_lower not in VALID_JUSTIFICATIONS:
                feedback_parts.append(f"✗ Invalid justification: '{status_justification}'")
        
        # 3. Tool usage (concise - sequence + key issues only)
        tool_names = []
        for key in sorted(trajectory.keys()):
            if key.startswith('tool_name_'):
                name = trajectory.get(key, '').lower()
                if 'nvd' in name:
                    tool_names.append('NVD')
                elif 'sbom' in name or 'package' in name:
                    tool_names.append('SBOM')
                elif 'web' in name or 'search' in name:
                    tool_names.append('Web')
                elif 'source' in name or 'retriev' in name:
                    tool_names.append('Src')
                elif 'reachability' in name or 'check_code' in name:
                    tool_names.append('Reach')
        
        if tool_names:
            feedback_parts.append(f"Tools: {' → '.join(tool_names)} ({len(tool_names)} calls)")
            
            # Only flag critical tool issues
            used_set = set(tool_names)
            just_lower = status_justification.lower().replace(' ', '_') if status_justification else ''
            
            if just_lower == 'component_not_present' and 'SBOM' not in used_set:
                feedback_parts.append("→ Missing SBOM for 'component_not_present'")
            elif predicted == 'affected' and 'Reach' not in used_set and not is_correct:
                feedback_parts.append("→ Missing Reachability check for 'affected'")
        else:
            feedback_parts.append("Tools: None recorded")
        
        # 4. Only show low scores (<0.5) as issues
        issues = []
        for key in ['evidence_coherence', 'reasoning_quality']:
            if metrics.get(key, 1) < 0.5:
                issues.append(key.replace('_', ' '))
        if issues:
            feedback_parts.append(f"Low: {', '.join(issues)}")
        
        return dspy.Prediction(score=score, feedback=" | ".join(feedback_parts))
        
    except Exception as e:
        return dspy.Prediction(score=0.0, feedback=f"Error: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description="Optimize CVE ReAct agent with GEPA.")
    parser.add_argument("--auto", default=None, choices=["light", "medium", "heavy"], 
                        help="GEPA auto mode (controls optimization intensity). Mutually exclusive with --max-metric-calls and --max-full-evals")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--max-train", type=int, default=0, help="Max train examples (0=use all)")
    parser.add_argument("--max-val", type=int, default=0, help="Max eval examples (0=use all)")
    parser.add_argument("--num-threads", type=int, default=min(os.cpu_count() or 4, 8))
    parser.add_argument("--model", default=None, help="Model name (prompts interactively if not set)")
    # GEPA-specific parameters
    parser.add_argument("--reflection-minibatch-size", type=int, default=3, 
                        help="Samples per reflection iteration")
    parser.add_argument("--candidate-selection", default="pareto", 
                        choices=["pareto", "current_best"],
                        help="Candidate selection strategy")
    parser.add_argument("--max-metric-calls", type=int, default=350, 
                        help="Maximum total metric calls. Mutually exclusive with --auto and --max-full-evals")
    parser.add_argument("--max-full-evals", type=int, default=None,
                        help="Max full validation evaluations. Mutually exclusive with --auto and --max-metric-calls")
    parser.add_argument("--reflection-model", default="openai/gpt-5.2",
                        help="Separate model for GEPA reflections (default: gpt-4o-mini)")
    parser.add_argument("--use-mlflow", action="store_true", help="Enable MLflow logging in GEPA")
    # Grid search for hyperparameter tuning
    parser.add_argument("--grid-search", action="store_true", 
                        help="Enable grid search over GEPA parameters")
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

    # Configure model
    _, model_name = configure_model(args.model, logger)
    safe_model_name = model_name.replace(".", "_").replace("-", "_")
    logger.info(f"Using model: {model_name}")
    
    # Setup save directory with model name
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    save_dir = CACHE_DIR / f"gepa_{safe_model_name}_{timestamp}"
    save_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup logging to save_dir
    log_path = save_dir / f"optimize_gepa_{timestamp}.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logging.getLogger().addHandler(file_handler)
    logger.info(f"Logging to {log_path}")

    # Setup MLflow with optimizer tracking
    setup_mlflow(experiment_name="ContainerSecurity_GEPA_Optimize", log_optimizer=True)

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

    # # Split data for constant evaluation
    # _, eval_cases_im = stratify_and_split(
    #     vulhub_cases, fp_cases, model_name="test_split", seed=args.seed, eval_mode=True
    #     # vulhub_cases, fp_cases, model_name=model_name, seed=args.seed, eval_mode=True
    # )
    
    # Apply max limits
    if args.max_train > 0:
        train_cases = train_cases[:args.max_train]
    if args.max_val > 0:
        eval_cases = eval_cases[:args.max_val]
    
    logger.info(f"Train examples: {len(train_cases)} | Eval examples: {len(eval_cases)}")
    # logger.info(f"Eval (in-memory) examples: {len(eval_cases_im)}")

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
    valset = build_examples(eval_cases)
    # evalset = build_examples(eval_cases_im)

    # ==================== Context-Aware Tools (Thread-Safe + Picklable) ====================
    # Use dict keyed by thread ID - thread-safe AND picklable
    import threading
    _ctx_by_thread = {}  # {thread_id: cve_id} - picklable dict
    
    def _get_cve_id():
        return _ctx_by_thread.get(threading.current_thread().ident)
    
    def _set_cve_id(cve_id):
        _ctx_by_thread[threading.current_thread().ident] = cve_id
    
    def _clear_cve_id():
        _ctx_by_thread.pop(threading.current_thread().ident, None)
    
    class ContextAgent(SourceCodeCVEAgent):
        """Agent that stores CVE context per-thread."""
        def forward(self, cve_id):
            _set_cve_id(cve_id)
            try:
                return super().forward(cve_id)
            finally:
                _clear_cve_id()
    
    def make_proxy_tool(name: str, template: Any) -> callable:
        """Create a proxy that reads CVE from thread-keyed dict."""
        def proxy(*args, **kwargs):
            cve_id = _get_cve_id()
            tools = tools_cache.get(cve_id, default_tools) if cve_id else default_tools
            target = next((t for t in tools if getattr(t, 'name', t.__class__.__name__) == name), None)
            return target(*args, **kwargs) if target else json.dumps({"error": f"{name} unavailable"})
        proxy.__name__ = name
        proxy.name = name
        proxy.desc = getattr(template, 'desc', '')
        return proxy
    
    # Build proxy tools from first case's template
    first_cve = list(tools_cache.keys())[0] if tools_cache else None
    template_tools = tools_cache.get(first_cve, default_tools)
    proxy_tools = [make_proxy_tool(getattr(t, 'name', t.__class__.__name__), t) for t in template_tools]
    
    initial_agent = ContextAgent(tools=proxy_tools, logger=logger)
    logger.info(f"Created agent with {len(proxy_tools)} context-aware proxy tools (thread-safe)")

    # GEPA metric - uses prediction directly (tools already dispatched correctly)
    def gepa_metric_wrapper(example, pred=None, trace=None, pred_name=None, pred_trace=None):
        if pred is None:
            return dspy.Prediction(score=0.0, feedback="No prediction provided.")
        return gepa_feedback_metric(example, pred, trace, pred_name, pred_trace)

    # Parameter grid for hyperparameter search
    if args.grid_search:
        param_grid = {
            'max_metric_calls': [250, 500, 700, 1000],
            'reflection_minibatch_size': [3],
            'candidate_selection': ["pareto"],  #, "current_best"],
        }
    else:
        param_grid = {
            'reflection_minibatch_size': [args.reflection_minibatch_size],
            'candidate_selection': [args.candidate_selection],
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
    best_gepa_result = None
    
    # Configure reflection LM (strong GPT model for prompt optimization)
    reflection_lm = None
    if args.reflection_model:
        logger.info(f"Using reflection model: {args.reflection_model}")
        reflection_lm = dspy.LM(
            model=args.reflection_model,
            temperature=1.0,  # Higher temp for creative prompt suggestions
            max_tokens=10000,  # Limit tokens to reduce rate limit pressure
            cache=True,  # Enable caching to reduce redundant calls
            num_retries=15,  # Number of retries with exponential backoff
            api_key=os.environ.get("OPENAI_API_KEY"),
        )
    
    for params in tqdm(param_combinations, desc="Testing GEPA parameters"):
        run_name = f"gepa_{model_name}_{timestamp}"
        logger.info(f"\n{'='*50}")
        logger.info(f"Starting run: {run_name}")
        logger.info(f"Params: {params}")
        
        # Configure GEPA optimizer - GEPA requires exactly ONE of: auto, max_metric_calls, max_full_evals
        # Priority: max_metric_calls > max_full_evals > auto (default to 'light' if none specified)
        gepa_kwargs = {
            'metric': gepa_metric_wrapper,
            'num_threads': args.num_threads,
            'reflection_minibatch_size': params['reflection_minibatch_size'],
            'candidate_selection_strategy': params['candidate_selection'],
            'reflection_lm': reflection_lm,
            # 'use_merge': True,
            # 'track_stats': True,
            'log_dir': str(save_dir / "gepa_logs"),
            'enable_tool_optimization': True,  # Joint optimization of predictor instructions + tool desc
            'use_mlflow': args.use_mlflow,
            'gepa_kwargs': {
                'stop_callbacks': [NoImprovementStopper(max_iterations_without_improvement=5)],  # Stop if no improvement for 5 iterations
            },
        }
        
        # Set exactly one control parameter
        # Priority: grid_search params > CLI args > auto fallback
        if args.grid_search and 'max_metric_calls' in params:
            # Use max_metric_calls from grid search
            gepa_kwargs['max_metric_calls'] = params['max_metric_calls']
            control_mode = f"max_metric_calls={params['max_metric_calls']}"
        elif args.max_metric_calls is not None:
            gepa_kwargs['max_metric_calls'] = args.max_metric_calls
            control_mode = f"max_metric_calls={args.max_metric_calls}"
        elif args.max_full_evals is not None:
            gepa_kwargs['max_full_evals'] = args.max_full_evals
            control_mode = f"max_full_evals={args.max_full_evals}"
        else:
            # Use auto mode (default to 'light' if not specified)
            gepa_kwargs['auto'] = args.auto or 'light'
            control_mode = f"auto={gepa_kwargs['auto']}"
        
        logger.info(f"GEPA control mode: {control_mode}")
        gepa_optimizer = GEPA(**gepa_kwargs)

        with mlflow.start_run(run_name=run_name) as run:
            loggable_gepa_params = {
                k: v for k, v in gepa_kwargs.items() 
                if k not in ['metric', 'reflection_lm'] and isinstance(v, (str, int, float, bool, type(None)))
            }
            if args.reflection_model:
                loggable_gepa_params['reflection_model'] = args.reflection_model
            
            mlflow.log_params({
                "model": model_name,
                "optimizer": "GEPA",
                "train_size": len(train_cases),
                "eval_size": len(eval_cases),
                "seed": args.seed,
                **loggable_gepa_params,
            })
            
            try:
                # GEPA compile - note: uses valset instead of devset
                gepa_result = gepa_optimizer.compile(
                    initial_agent,
                    trainset=trainset,
                    valset=valset,
                )
                
                optimized = gepa_result
                    
                logger.info("GEPA compilation complete")

                # # Evaluate on validation set
                # logger.info("Evaluating optimized agent on valset...")
                # evaluator = dspy.Evaluate(
                #     devset=valset,
                #     # devset=evalset,
                #     metric=lambda ex, pred: gepa_feedback_metric(ex, pred).score,
                #     num_threads=args.num_threads,
                #     display_progress=True,
                #     display_table=5,
                # )
                # eval_score = evaluator(optimized)
                # score_value = float(getattr(eval_score, 'score', eval_score))
                # logger.info(f"Valset evaluation score: {score_value}")
                
                # mlflow.log_metric("eval_score", score_value)
                
                # # Log GEPA-specific stats if available
                # if hasattr(gepa_result, 'detailed_results'):
                #     best_idx = gepa_result.detailed_results.best_idx
                #     mlflow.log_metric("best_val_score", gepa_result.detailed_results.val_aggregate_scores[best_idx])
                #     mlflow.log_metric("num_candidates", len(gepa_result.detailed_results.candidates) if hasattr(gepa_result.detailed_results, 'candidates') else 0)
                # if hasattr(gepa_result, 'total_metric_calls'):
                #     mlflow.log_metric("total_metric_calls", gepa_result.total_metric_calls or 0)
                
                # # Track best
                # if score_value > best_score:
                #     best_score = score_value
                #     best_params = loggable_gepa_params.copy()  # Store actual GEPA params, not grid params
                #     best_optimized = optimized
                #     best_run_id = run.info.run_id
                #     best_gepa_result = gepa_result
                #     logger.info(f"New best score: {best_score:.4f} with params: {best_params}")
                    
            except Exception as e:
                logger.error(f"Error with params {params}: {e}")
                mlflow.log_param("error", str(e))
                import traceback
                logger.error(traceback.format_exc())
                continue

    # Use best model (or last if no improvement)
    if best_optimized is None:
        logger.warning("No successful runs, using last optimized agent")
        best_optimized = optimized
        best_params = loggable_gepa_params  # Use actual GEPA params, not grid params
        # best_score = score_value
        # Get best score using correct GEPA API
        if hasattr(best_optimized, 'detailed_results') and hasattr(best_optimized.detailed_results, 'best_idx'):
            best_idx = best_optimized.detailed_results.best_idx
            best_score = best_optimized.detailed_results.val_aggregate_scores[best_idx]
        else:
            best_score = 0.0

    logger.info(f"\n{'='*60}")
    logger.info(f"Best params: {best_params}")
    logger.info(f"Best score: {best_score:.4f}")

    # Save optimized prompts as JSON
    state_file = save_dir / "state.json"
    best_optimized.save(str(state_file), save_program=False)
    logger.info(f"Saved optimized prompts to {state_file}")


    # # Clean heavy VDB and repo references before saving full program
    # logger.info("Cleaning VDB and repository references from tools to reduce save size...")
    # cleaned_count = 0
    # # Heavy attributes to remove
    # heavy_attrs = [
    #     # VDB-related
    #     'vdb', 'vector_store', 'retriever', 'index', 'lexical_store', 
    #     'hybrid_retriever', '_vdb', '_vector_store', '_retriever',
    #     # Repository-related
    #     'repo_path', 'repo', 'source_repo', 'git_repo', 'clone_dir',
    #     'repo_dir', '_repo_path', '_repo', '_clone_dir', 'repository',
    #     # Other heavy objects
    #     'cache', 'embeddings', 'embedding_model'
    # ]
    
    # if hasattr(best_optimized, 'react_agent') and hasattr(best_optimized.react_agent, 'tools'):
    #     tools_source = best_optimized.react_agent.tools
    #     if isinstance(tools_source, dict):
    #         for tool_name, tool in tools_source.items():
    #             for attr in heavy_attrs:
    #                 if hasattr(tool, attr):
    #                     setattr(tool, attr, None)
    #                     cleaned_count += 1
    #     else:
    #         for tool in tools_source:
    #             for attr in heavy_attrs:
    #                 if hasattr(tool, attr):
    #                     setattr(tool, attr, None)
    #                     cleaned_count += 1
    
    # # Also clean direct tools attribute if present
    # if hasattr(best_optimized, 'tools') and best_optimized.tools:
    #     for tool in best_optimized.tools:
    #         for attr in heavy_attrs:
    #             if hasattr(tool, attr):
    #                 setattr(tool, attr, None)
    #                 cleaned_count += 1
    
    # logger.info(f"Cleaned {cleaned_count} heavy references (VDB, repos, etc.) from tools")
    
    # # Save program (now much smaller without VDB serialization)
    # program_file = save_dir / "program.pkl"
    # best_optimized.save(str(program_file), save_program=True)
    # logger.info(f"Saved full program to {program_file}")


    # # Save optimized tool descriptions (GEPA tool optimization)
    # # GEPA updates tools on ReAct modules - check react_agent.tools (dict) first, then fallback
    # optimized_tools_list = []
    
    # # Try to get tools from the ReAct module (where GEPA optimizes them)
    # if hasattr(best_optimized, 'react_agent') and hasattr(best_optimized.react_agent, 'tools'):
    #     tools_source = best_optimized.react_agent.tools
    #     if isinstance(tools_source, dict):
    #         # ReAct stores tools as dict {name: tool}
    #         for tool_name, tool in tools_source.items():
    #             if tool_name != 'finish':  # Skip built-in finish tool
    #                 optimized_tools_list.append({
    #                     'name': tool_name,
    #                     'desc': getattr(tool, 'desc', ''),
    #                     'args': getattr(tool, 'args', {}),
    #                 })
    #     else:
    #         # List of tools
    #         for tool in tools_source:
    #             tool_name = getattr(tool, 'name', tool.__name__ if hasattr(tool, '__name__') else str(tool))
    #             optimized_tools_list.append({
    #                 'name': tool_name,
    #                 'desc': getattr(tool, 'desc', ''),
    #                 'args': getattr(tool, 'args', {}),
    #             })
    # elif hasattr(best_optimized, 'tools') and best_optimized.tools:
    #     # Fallback to direct tools attribute
    #     for tool in best_optimized.tools:
    #         tool_name = getattr(tool, 'name', tool.__name__ if hasattr(tool, '__name__') else str(tool))
    #         optimized_tools_list.append({
    #             'name': tool_name,
    #             'desc': getattr(tool, 'desc', ''),
    #             'args': getattr(tool, 'args', {}),
    #         })
    
    # if optimized_tools_list:
    #     tools_file = save_dir / "optimized_tools.json"
    #     with open(tools_file, "w", encoding="utf-8") as f:
    #         json.dump(optimized_tools_list, f, indent=2, ensure_ascii=False)
    #     logger.info(f"Saved {len(optimized_tools_list)} optimized tool descriptions to {tools_file}")


    # Save optimization config
    config = {
        "model": model_name,
        "optimizer": "GEPA",
        "train_size": len(trainset),
        "eval_size": len(valset),
        "eval_score": best_score,
        "seed": args.seed,
        "timestamp": timestamp,
        "tools_count": len(list(tools_cache.values())[0]) if tools_cache else 0,
        "grid_search": args.grid_search,
        "best_run_id": best_run_id,
        **best_params,  # Include all actual GEPA parameters
    }

    # Add GEPA result stats if available
    if best_gepa_result and hasattr(best_gepa_result, 'detailed_results'):
        config["total_metric_calls"] = best_gepa_result.detailed_results.total_metric_calls if hasattr(best_gepa_result.detailed_results, 'total_metric_calls') else 0
        config["num_candidates"] = len(best_gepa_result.detailed_results.candidates) if hasattr(best_gepa_result.detailed_results, 'candidates') else 0
    
    config_file = save_dir / "optimization_config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    logger.info(f"Saved config to {config_file}")

    
    # Run full evaluation with in-memory optimized agent
    logger.info("Running full evaluation on eval_cases using evaluate_batch with in-memory optimized agent...")
    eval_results_im = evaluate_batch(cases=eval_cases, model_name=model_name, logger=logger, agent=best_optimized) # eval_cases_im
    
    eval_results_file_im = save_dir / "eval_results_im_agent.json"
    with open(eval_results_file_im, "w", encoding="utf-8") as f:
        json.dump(eval_results_im, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved eval results to {eval_results_file_im}")

    # # Run full evaluation with best model
    # logger.info("Reconstructing agent structure and loading optimized state...")
    # loaded_agent = ContextAgent(tools=proxy_tools, logger=logger)
    # loaded_agent.load(str(state_file))
    # logger.info(f"Loaded optimized state from {state_file}")
    
    # # Load optimized tool descriptions if available
    # tools_file = save_dir / "optimized_tools.json"
    # if tools_file.exists(): 
    #     with open(tools_file, "r", encoding="utf-8") as f:
    #         optimized_tools_data = json.load(f)
        
    #     # Build lookup maps (skip None/empty values - keep original)
    #     tool_desc_map = {t['name']: t['desc'] for t in optimized_tools_data if t.get('desc')}
    #     # Only include args if they have non-empty content
    #     tool_args_map = {
    #         t['name']: t['args'] 
    #         for t in optimized_tools_data 
    #         if t.get('args') and any(t['args'].values())  # Has args with non-empty values
    #     }
        
    #     # Update tools on react_agent (where GEPA optimizes them)
    #     tools_updated = 0
    #     if hasattr(loaded_agent, 'react_agent') and hasattr(loaded_agent.react_agent, 'tools'):
    #         tools_source = loaded_agent.react_agent.tools
    #         if isinstance(tools_source, dict):
    #             for tool_name, tool in tools_source.items():
    #                 if tool_name in tool_desc_map:
    #                     tool.desc = tool_desc_map[tool_name]
    #                     tools_updated += 1
    #                 # Update or create args entries with optimized descriptions
    #                 if tool_name in tool_args_map:
    #                     if not hasattr(tool, 'args') or tool.args is None:
    #                         tool.args = {}
    #                     for arg_name, arg_schema in tool_args_map[tool_name].items():
    #                         if arg_name in tool.args:
    #                             tool.args[arg_name].update(arg_schema)
    #                         else:
    #                             # Create new arg entry if it doesn't exist
    #                             tool.args[arg_name] = arg_schema
    #         else:
    #             for tool in tools_source:
    #                 tool_name = getattr(tool, 'name', tool.__name__ if hasattr(tool, '__name__') else None)
    #                 if tool_name in tool_desc_map:
    #                     tool.desc = tool_desc_map[tool_name]
    #                     tools_updated += 1
    #                 # Update args for list-based tools too
    #                 if tool_name in tool_args_map:
    #                     if not hasattr(tool, 'args') or tool.args is None:
    #                         tool.args = {}
    #                     for arg_name, arg_schema in tool_args_map[tool_name].items():
    #                         if arg_name in tool.args:
    #                             tool.args[arg_name].update(arg_schema)
    #                         else:
    #                             tool.args[arg_name] = arg_schema
        
    #     # Also update direct tools attribute if present
    #     if hasattr(loaded_agent, 'tools') and loaded_agent.tools:
    #         for tool in loaded_agent.tools:
    #             tool_name = getattr(tool, 'name', tool.__name__ if hasattr(tool, '__name__') else None)
    #             if tool_name in tool_desc_map:
    #                 tool.desc = tool_desc_map[tool_name]
        
    #     logger.info(f"Loaded {len(optimized_tools_data)} tool entries from {tools_file} (updated {tools_updated} tools with optimized descriptions)")

    # logger.info("Running full evaluation on eval_cases using evaluate_batch with optimized agent...")
    # eval_results = evaluate_batch(cases=eval_cases_im, model_name=model_name, logger=logger, agent=loaded_agent)
    
    # eval_results_file = save_dir / "eval_results_loaded_agent.json"
    # with open(eval_results_file, "w", encoding="utf-8") as f:
    #     json.dump(eval_results, f, indent=2, ensure_ascii=False)
    # logger.info(f"Saved eval results to {eval_results_file}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"GEPA Optimization Complete")
    print(f"{'='*60}")
    print(f"Model: {model_name}")
    print(f"Best params: {best_params}")
    print(f"Tools per CVE: {config['tools_count']}")
    print(f"Valset score: {best_score:.4f}")
    print(f"DHR: {eval_results_im['metadata']['DHR']}")
    print(f"F1-Score: {eval_results_im['predictions']['F1-Score']}")
    print(f"F2-Score: {eval_results_im['predictions']['F2-Score']}")
    print(f"{'='*60}")
    print(f"Saved to: {save_dir}")
    print(f"Log: {log_path}")
    print(f"{'='*60}\n")

    # # Save program (larger fil in GBs)
    # program_file = save_dir #/ "program.pkl"
    # best_optimized.save(str(program_file), save_program=True)
    # logger.info(f"Saved full program to {program_file}")

if __name__ == "__main__":
    main()
