import os
import json
import logging
import math
import random
import re
import subprocess
import argparse
import time
import shutil
from datetime import datetime
from getpass import getpass
from types import SimpleNamespace
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import unquote

import dspy

from .utils.source_code_loader import SourceCodeLoader
from .utils.hybrid_vdb_creator import HybridVDBCreator, VDBConfig
from .utils.mlflow_utils import setup_mlflow
from .tools import SBOMPackageChecker, SourceCodeRetriever, CVEWebSearchTool, NVDIntelTool, CodeReachabilityAnalyzer
from .agent import SourceCodeCVEAgent
from .utils.const import DATASET_SPLITS, TOKEN_COSTS, TOOLS_CONFIG
from .metrics import composite_cve_metric


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "vul_analysis" / "datasets"
SBOM_DIR = DATA_DIR / "syft_sbom"
VULHUB_DATASET = DATA_DIR / "vulhub_eval_2020_2025.json"
VULHUB_FP_DATASET = DATA_DIR / "vulhub_fp.json"
REPOS_DIR = BASE_DIR / "vul_analysis" / ".cache" / "repos"
VDB_CACHE_DIR = BASE_DIR / "vul_analysis" / ".cache" / "vdb"


class LoggingLM(dspy.BaseLM):
    """Wrapper for DSPy LM to log requests and responses."""

    def __init__(self, lm, logger):
        self.lm = lm
        self.logger = logger
        # Initialize BaseLM with attributes from the wrapped LM
        super().__init__(
            model=lm.model,
            model_type=getattr(lm, 'model_type', 'chat'),
            **lm.kwargs
        )
        self.history = lm.history

    def __call__(self, prompt=None, messages=None, **kwargs):
        if self.logger:
            log_msg = f"Prompt: {prompt}" if prompt else f"Messages: {messages}"
            self.logger.info(
                f"\\n{'='*40} [LLM REQUEST] {'='*40}\\n{log_msg}\\n{'='*95}")

        # Delegate to the wrapped LM
        response = self.lm(prompt=prompt, messages=messages, **kwargs)

        if self.logger:
            self.logger.info(
                f"\\n{'='*40} [LLM RESPONSE] {'='*40}\\n{response}\\n{'='*95}")

        # Sync history
        self.history = self.lm.history

        return response

    def forward(self, prompt=None, messages=None, **kwargs):
        return self.lm.forward(prompt=prompt, messages=messages, **kwargs)

    def __deepcopy__(self, memo):
        """Handle deepcopy for MIPROv2 optimizer.

        DSPy optimizers may deepcopy() the configured LM.
        During deepcopy, Python can create an uninitialized instance (without __init__),
        so we must avoid attribute-proxy recursion.
        """
        import copy
        copied_lm = self.lm.copy() if hasattr(
            self.lm, "copy") else copy.deepcopy(self.lm, memo)
        new_instance = type(self)(copied_lm, self.logger)
        memo[id(self)] = new_instance
        return new_instance

    def __getattr__(self, name):
        # Avoid recursion during deepcopy by checking if 'lm' exists
        lm = self.__dict__.get("lm")
        if lm is None:
            raise AttributeError(name)
        return getattr(lm, name)


def clear_dspy_cache(logger: logging.Logger = None):
    """Clear DSPy cache at the start of each run."""
    cache_path = os.path.expanduser("~/.dspy_cache")
    if os.path.exists(cache_path):
        try:
            # Close DSPy cache connection if it exists
            if hasattr(dspy, 'settings') and hasattr(dspy.settings, 'cachedir'):
                try:
                    # Close any active cache connections
                    if hasattr(dspy.settings, 'cache') and dspy.settings.cache is not None:
                        if hasattr(dspy.settings.cache, 'close'):
                            dspy.settings.cache.close()
                except Exception as cache_close_err:
                    if logger:
                        logger.debug(f"Could not close cache connection: {cache_close_err}")

            # Now remove the cache directory
            shutil.rmtree(cache_path)
            if logger:
                logger.info(f"Cleared DSPy cache at {cache_path}")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to clear DSPy cache at {cache_path}: {e}")

def configure_model(model_name: Optional[str] = None, logger: logging.Logger = None):
    """
    Configure DSPy with the specified model and API key.

    Args:
        model_name: Model name (default: gemini-2.0-flash)
        logger: Logger instance

    Returns:
        Configured DSPy language model
    """
    # LLM Models: Context Window | Price (In/Out per 1M)
    MODEL_SPECS = {
        # --- Tier 1: High-Volume Triage & Baseline (Cost-Optimized) ---
        "gemini-2.0-flash": "1M ctx, $0.10/$0.40, Cheap baseline for large experiment sweeps & SBOM parsing",
        "deepseek-chat":      "128K ctx, $0.27/$1.10, Cost-effective large-scale vulnerability scans & noise reduction",
        "gpt-4o-mini":        "128K ctx, $0.15/$0.60, Balanced Judge/Evaluator for academic benchmarks",
        "mistral-large-latest": "256K ctx, $2.00/$6.00, Fast analysis of Dockerfiles & Infrastructure-as-Code (IaC)",
        "phi-4":              "16K ctx, Low/Local, Edge scanning & developer-laptop pre-commit checks",
        # --- Tier 2: Deep Reasoning & Verification (Accuracy-Optimized) ---
        "deepseek-reasoner":  "128K ctx, $0.55/$2.19, Chain-of-Thought reasoning for code reachability analysis",
        "qwen-2.5-72b-instruct": "128K ctx, $0.40/$0.40, Structured JSON outputs for automated VEX pipelines",
        "o1-mini":            "200K ctx, $3.00/$12.00, Exploit logic verification & CTF-style constraint solving",
        "gpt-4o":             "128K ctx, $2.50/$10.00, Reliable CVE triage & high-confidence report generation",
        "claude-sonnet-4-5-20250929": "200K+ ctx, $3.00/$15.00, Precise patch diffing & secure-code reasoning",
		"claude-haiku-4-5-20251001": "200K+ ctx, $3.00/$15.00, Advanced patch analysis & vulnerability impact assessment",
        # --- Tier 3: The Frontier (Zero-Day & Complex Analysis) ---
        "o1":                 "200K ctx, $15.00/$60.00, Deep vulnerability reasoning & zero-day binary analysis",
        "gemini-2.0-pro-exp": "2M ctx, $1.25/$10.00, Supply-chain forensics across massive repo histories",
        # --- Tier 4: Specialized & Open Weights (Red Team/Privacy) ---
        "llama-3.3-70b-instruct": "128K ctx, Free (Open Weights), Private container analysis & reproducible research",
        "grok-2":             "128K ctx, $2.00/$10.00, Offensive security & PoC generation (low safety filters)",
        "starcoder2-15b":     "16K ctx, Free (Open Weights), Syntax-aware static analysis for Rust/Go binaries",
        "claude-opus-4-5-20251101": "200K ctx, $15.00/$75.00, Advanced reasoning for complex vulnerability analysis",
    }

    # Clear DSPy cache at the start of each run
    clear_dspy_cache(logger)
    # Get model name from environment or parameter or user input
    if not model_name:
        print("\n=== Available Models ===")
        for m, desc in MODEL_SPECS.items():
            print(f" {m:<20} : {desc}")
        model_name = input("\nEnter Model Name (default: gemini-2.0-flash): ").strip(
        ).lower() or os.environ.get('MODEL_NAME', 'gemini-2.0-flash')  # gpt-4.1-mini
        if logger:
            logger.info(f"Selected model: {model_name}")

    # # Configure API key based on model provider
    # if "openai" in model_name or "gpt" in model_name:
    #     provider, key_var = "openai", "OPENAI_API_KEY"
    # elif "gemini" in model_name:
    if "gemini" in model_name:
        provider, key_var = "gemini", "GEMINI_API_KEY"
    elif "claude" in model_name or "anthropic" in model_name:
        provider, key_var = "anthropic", "ANTHROPIC_API_KEY"
    # elif "deepseek" in model_name:
    #     provider, key_var = "deepseek", "DEEPSEEK_API_KEY"
    # elif "mistral" in model_name:
    #     provider, key_var = "mistral", "MISTRAL_API_KEY"
    # elif "groq" in model_name:
    #     provider, key_var = "groq", "GROQ_API_KEY"
    else:
        # Default fallback to compatible API
        provider, key_var = "openrouter", "OPENROUTER_API_KEY"
        logger.warning(
            f"Unknown model provider for '{model_name}', defaulting to OpenRouter")

    api_key = os.environ.get(key_var)
    if not api_key:
        provider = input(f'Enter {model_name} Provider: ')
        api_key = getpass(f'Enter {key_var}/Provider_API_KEY: ')
    os.environ[key_var] = api_key

    model = f"{provider}/{model_name}"
    lm = dspy.LM(
        model=model,
        temperature=1.0, max_tokens=20000, num_retries=15,
        api_key=api_key,
        cache=True,
      		# Strict Routing Configuration for Research experiment (Didn't Work with DSPy)
      		# extra_body={
      		# 	"provider": {
      		# 		"order": ["groq"],
      		# 		"allow_fallbacks": False
      		# 	}
      		# }
    )
    logger.info(f"Configured Model: {model}")

    # Wrap LM with logging if logger is provided
    if logger:
        lm = LoggingLM(lm, logger)

    # Configure DSPy
    dspy.configure(lm=lm, cache=True, track_usage=True)
    if logger:
        logger.info(f"Model configured: {model_name} (Provider: {provider})")

    return lm, model_name


def _sanitize_dir_name(value: str) -> str:
	return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def resolve_sbom_path(image: str, logger: logging.Logger = None) -> Optional[Path]:
	"""Resolve SBOM path for an image using vulhub naming rule."""
	file_base = image.replace("/", "+").replace(":", "@")
	for ext in [".txt", ".json"]:
		candidate = SBOM_DIR / f"{file_base}{ext}"
		if candidate.exists():
			if logger:
				logger.info(f"Using SBOM: {candidate}")
			return candidate
	if logger:
		logger.warning(f"No SBOM found for {image} under {SBOM_DIR}")
	return None


def clone_repo_at_ref(repo_url: str, ref: str, logger: logging.Logger = None) -> Optional[Path]:
	"""Clone repository at specific ref into a unique directory (repo_vuln_ref naming) shallow clone."""
	ref_clean = unquote(ref)
	repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
	# Create unique directory per repo+ref: e.g., django_v3.2.4
	dir_name = f"{_sanitize_dir_name(repo_name)}_{_sanitize_dir_name(ref_clean)}"
	clone_dir = REPOS_DIR / dir_name
	clone_dir.parent.mkdir(parents=True, exist_ok=True)

	# If already cloned at this ref, just reuse it
	if clone_dir.exists() and (clone_dir / ".git").exists():
		if logger:
			logger.info(f"Reusing existing clone at {clone_dir}")
		return clone_dir

	# Clone shallowly at the specific tag/ref (no history, just that state)
	if logger:
		logger.info(
		    f"Cloning {repo_url}@{ref_clean} (shallow, depth=1) -> {clone_dir}")
	try:
		subprocess.check_call([
			"git", "clone", "--depth", "1", "--branch", ref_clean, repo_url, str(
			    clone_dir)
		])
	except subprocess.CalledProcessError:
		# If --branch fails (e.g., for commit hashes), try alternate approach
		if logger:
			logger.info(
			    f"Direct branch clone failed, trying fetch approach for {ref_clean}")
		try:
			# Clone without checkout, then fetch the specific ref
			subprocess.check_call([
				"git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(
				    clone_dir)
			])
			subprocess.check_call([
				"git", "-C", str(clone_dir), "fetch", "--depth", "1", "origin", ref_clean
			])
			subprocess.check_call([
				"git", "-C", str(clone_dir), "checkout", "--detach", "FETCH_HEAD"
			])
		except subprocess.CalledProcessError as exc:
			if logger:
				logger.error(f"Clone failed for {repo_url}@{ref_clean}: {exc}")
			return None

	return clone_dir


def build_vdb(repo_path: Path, repo_url: str, repo_ref: str, logger: logging.Logger = None):
	"""Build or load hybrid VDB for a repo@ref checkout."""
	cache_dir = VDB_CACHE_DIR
	loader = SourceCodeLoader(
		languages=["python", "javascript", "typescript",
		    "go", "java", "c", "cpp", "php"],
		chunk_size=1500,
	)
	documents = loader.load_documents(repo_path)
	if logger:
		logger.info(f"Indexed {len(documents)} chunks for {repo_ref}")
	config = VDBConfig(
		repo_url=repo_url,
		repo_ref=repo_ref,
		cache_dir=cache_dir,
		embedding_model="all-MiniLM-L6-v2",
	)
	creator = HybridVDBCreator(config)
	return creator.create_or_load_vdb(documents, force_rebuild=False)


class CallSourceCodeRetriever:
	"""
	Tool for retrieving and analyzing relatable code from the source repository.
	Uses the DSPyHybridRetriever to find semantically similar and keyword-matching code."""

	def __init__(self, builder, logger: logging.Logger = None):
		self.builder = builder
		self.logger = logger or logging.getLogger(__name__)
		self._retriever = None

	def _ensure(self):
		if self._retriever is None:
			self._retriever = self.builder()
			if self.logger:
				self.logger.info("VDB initialized for source code retrieval")

	def __call__(self, query: str = None, k: int = 5, code_query: str = None, search_query: str = None, **kwargs):
		"""Retrieve code snippets. Accepts common LLM argument variations.
		
		Args:
			query: Primary search query (function names + security keywords)
			k: Number of results (default 5)
			code_query: Alias for query (LLM sometimes uses this)
			search_query: Alias for query (LLM sometimes uses this)
		"""
		# Accept common LLM argument name variations
		actual_query = query or code_query or search_query or kwargs.get('q') or kwargs.get('search')
		if not actual_query:
			return "Error: Missing query argument. Use query='function_name security_keyword' format."
		self._ensure()
		return self._retriever(actual_query, k=k)

	def retrieve_related_code(self, *args, **kwargs):
		self._ensure()
		return self._retriever.retrieve_related_code(*args, **kwargs)

	@property
	def ready(self) -> bool:
		return self._retriever is not None


def load_cases(dataset_path: Path) -> List[Dict[str, Any]]:
	with dataset_path.open("r", encoding="utf-8") as f:
		data = json.load(f)
	return data


def get_dataset_split(model_name: str) -> tuple:
	"""Get dataset split fractions for a given model.

	Args:
		model_name: Model name to lookup

	Returns:
		Tuple of (train_fraction, eval_fraction)
	"""
	return DATASET_SPLITS.get(model_name, (0.77, 0.23))  # Default to 77% train, 23% eval, change to (0.75, 0.25) when needed


def stratify_and_split(
	vulhub_cases: List[Dict[str, Any]],
	fp_cases: List[Dict[str, Any]],
	model_name: str,
	seed: int = 42,
	ratio: float = 0.75,
	max_cves: Optional[int] = None,
	eval_mode: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
	"""Stratify and split TP/FP datasets into train and eval sets.

	Two modes:
	1. eval_mode=True: Use DATASET_SPLITS for model-specific train/eval fractions
	2. eval_mode=False: Use max_cves for simple sampling (75% TP, 25% FP)

	Same seed ensures reproducibility across runs.

	Args:
		vulhub_cases: List of vulnerable (TP) cases
		fp_cases: List of false positive (FP) cases
		model_name: Model name to get split fractions from DATASET_SPLITS
		seed: Random seed for reproducibility
		ratio: Ratio of TP to FP cases (default 0.75 = 75% TP, 25% FP)
		max_cves: Max CVEs to return (only used when eval_mode=False)
		eval_mode: If True, use DATASET_SPLITS; if False, use max_cves

	Returns:
		Tuple of (train_cases, eval_cases)
		- In eval_mode: both are populated based on DATASET_SPLITS
		- In max_cves mode: train_cases is empty, eval_cases has max_cves samples
	"""
	rng = random.Random(seed)
	logger = logging.getLogger(__name__)

	# Shuffle each class with same seed for reproducibility
	tp_shuffled = vulhub_cases.copy()
	fp_shuffled = fp_cases.copy()
	rng.shuffle(tp_shuffled)
	rng.shuffle(fp_shuffled)

	if eval_mode:
		# Mode 1: Use DATASET_SPLITS for train/eval fractions
		train_frac, eval_frac = get_dataset_split(model_name)

		# Calculate sizes per class
		n_tp_train = max(1, int(len(vulhub_cases) * train_frac))
		n_fp_train = max(1, int(len(fp_cases) * train_frac))
		n_tp_eval = max(1, int(len(vulhub_cases) * eval_frac))
		n_fp_eval = max(1, int(len(fp_cases) * eval_frac))

		# Split each class
		tp_train = tp_shuffled[:n_tp_train]
		tp_eval = tp_shuffled[n_tp_train:n_tp_train + n_tp_eval]
		fp_train = fp_shuffled[:n_fp_train]
		fp_eval = fp_shuffled[n_fp_train:n_fp_train + n_fp_eval]

		# Combine and shuffle
		train_cases = tp_train + fp_train
		eval_cases = tp_eval + fp_eval
		rng.shuffle(train_cases)
		rng.shuffle(eval_cases)

		logger.info(
			f"Eval mode for {model_name}: train={len(train_cases)} (TP:{len(tp_train)}, FP:{len(fp_train)}), "
			f"eval={len(eval_cases)} (TP:{len(tp_eval)}, FP:{len(fp_eval)})"
		)
		return train_cases, eval_cases

	else:
		# Mode 2: Use max_cves for simple sampling
		if max_cves is None or max_cves <= 0:
			max_cves = 1  # Default to 1 if not specified

		target_tp = int(max_cves * ratio)
		target_fp = max_cves - target_tp

		sampled_tp = tp_shuffled[:min(target_tp, len(tp_shuffled))]
		sampled_fp = fp_shuffled[:min(target_fp, len(fp_shuffled))]

		eval_cases = sampled_tp + sampled_fp
		rng.shuffle(eval_cases)

		logger.info(
			f"Max CVEs mode: {len(eval_cases)} cases (TP:{len(sampled_tp)}, FP:{len(sampled_fp)})"
		)
		return [], eval_cases


def calculate_batch_metrics(
	results: List[Dict[str, Any]],
	model_name: str
) -> Dict[str, Any]:
	"""Calculate batch metrics from a list of CVE analysis results.

	Args:
		results: List of result dicts from run_case()
		model_name: Model name for cost calculation

	Returns:
		Dict with metadata and predictions sections
	"""
	cves_processed = len(results)
	if cves_processed == 0:
		return {"metadata": {}, "predictions": {}}

	# Count predictions
	True_count = sum(1 for r in results if r.get("csaf_vex_status") == "affected")
	False_count = sum(1 for r in results if r.get("csaf_vex_status") in [
	                  "not_affected", "fixed", "under_investigation"])
	csaf_matches = sum(1 for r in results if r.get("csaf_vex_match") is True)

	# TP/FP/TN/FN
	TP = sum(1 for r in results if r.get("expected_vex_status") ==
	         "affected" and r.get("csaf_vex_status") == "affected")
	FP = sum(1 for r in results if r.get("expected_vex_status") !=
	         "affected" and r.get("csaf_vex_status") == "affected")
	TN = sum(1 for r in results if r.get("expected_vex_status") !=
	         "affected" and r.get("csaf_vex_status") != "affected")
	FN = sum(1 for r in results if r.get("expected_vex_status") ==
	         "affected" and r.get("csaf_vex_status") != "affected")

	# Precision, Recall, F1, F2
	precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
	recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
	f1_score = round(2 * (precision * recall) / (precision + recall),
	                 4) if (precision + recall) > 0 else 0.0
	beta = 2
	f2_score = round((1 + beta**2) * precision * recall / (beta**2 *
	                 precision + recall), 4) if (beta**2 * precision + recall) > 0 else 0.0

	# Token/time stats
	total_time = sum(r.get("elapsed_sec", 0) for r in results)
	total_tokens = sum(r.get("token_usage", {}).get(
	    "total_tokens", 0) for r in results)
	total_prompt_tokens = sum(r.get("token_usage", {}).get(
	    "prompt_tokens", 0) for r in results)
	total_completion_tokens = sum(r.get("token_usage", {}).get(
	    "completion_tokens", 0) for r in results)

	input_cost_per_m, output_cost_per_m = TOKEN_COSTS.get(model_name, [0.0, 0.0])
	total_cost = (total_prompt_tokens * input_cost_per_m +
	              total_completion_tokens * output_cost_per_m) / 1_000_000

	# DHR and composite scores
	DHR = round(csaf_matches / cves_processed, 4) if cves_processed else 0.0
	composite_scores = [r.get("composite_score", 0.0) for r in results]
	batch_score_mean = round(sum(composite_scores) /
	                         len(composite_scores), 6) if composite_scores else 0.0
	positive_scores = [s for s in composite_scores if s > 0]
	batch_score_geomean = round(math.prod(
	    positive_scores) ** (1 / len(positive_scores)), 6) if positive_scores else 0.0

	# Aggregate component metrics (mean across all results) - uses internal metric_components
	component_keys = ['decision_correctness', 'evidence_coherence',
	    'tool_efficiency', 'calibration', 'reasoning_quality']
	batch_component_metrics = {}
	for key in component_keys:
		values = [r.get("metric_components", {}).get(key, 0.0) for r in results]
		batch_component_metrics[key] = round(
		    sum(values) / len(values), 4) if values else 0.0

	return {
		"metadata": {
			"analysis_date": datetime.now().isoformat(),
			"model": model_name,
			"total_cves_processed": cves_processed,
			"DHR": DHR,
			"batch_composite_metrics[mean/geomean]": f"{batch_score_mean}/{batch_score_geomean}",
			"component_metrics_keys[mean]": batch_component_metrics,
			"total_time/avg": f"{round(total_time, 2)}/{round(total_time / cves_processed, 2)}",
			"total_tokens/avg": f"{total_tokens}/{total_tokens // cves_processed}",
			"total_prompt_tokens/avg": f"{total_prompt_tokens}/{total_prompt_tokens // cves_processed}",
			"total_completion_tokens/avg": f"{total_completion_tokens}/{total_completion_tokens // cves_processed}",
			"token_cost/avg": f"{round(total_cost, 4)}/{round(total_cost / cves_processed, 4)}",
		},
		"predictions": {
			"affected/not_affected": f"{True_count}/{False_count}",
			"TP/FP/TN/FN": f"{TP}/{FP}/{TN}/{FN}",
			"precision": round(precision, 4),
			"recall": round(recall, 4),
			"F1-Score": f1_score,
			"F2-Score": f2_score,
		},
	}


def run_case(entry: Dict[str, Any], repo_url: str, repo_ref: str, sbom_tool: Optional[SBOMPackageChecker], logger: logging.Logger, agent: Optional["SourceCodeCVEAgent"] = None, tools_config: str = "full", optimized_state_path: Optional[str] = None):
	"""Run CVE analysis for a single case.

	Args:
		entry: Case dictionary with CVE_ID and other metadata
		repo_url: Repository URL
		repo_ref: Repository reference (tag/commit)
		sbom_tool: Optional SBOM checker tool
		logger: Logger instance
		agent: Optional pre-built agent (e.g., loaded from MIPROv2 optimization).
		       If provided, uses this agent instead of creating a new one.
		tools_config: Tool configuration key from TOOLS_CONFIG (default: full)
		optimized_state_path: Optional path to state.json from DSPy optimization.
		       Per DSPy docs: with save_program=False, reconstruct agent then call .load()
	"""
	# Resolve repo path for direct file access (matches clone_repo_at_ref naming)
	repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
	ref_clean = unquote(repo_ref)
	dir_name = f"{_sanitize_dir_name(repo_name)}_{_sanitize_dir_name(ref_clean)}"
	repo_path = REPOS_DIR / dir_name

	# Get enabled tools from config
	enabled_tools = TOOLS_CONFIG.get(tools_config, TOOLS_CONFIG["full"])

	# If no agent provided, build one with tools based on config
	if agent is None:
		def build_retriever():
			config = VDBConfig(
				repo_url=repo_url,
				repo_ref=repo_ref,
				cache_dir=VDB_CACHE_DIR,
				embedding_model="all-MiniLM-L6-v2",
			)
			creator = HybridVDBCreator(config)

			if creator.cache_exists():
				if logger:
					logger.info(f"VDB cache hit for {repo_ref}; skipping repo clone")
				vdb_engine = creator.create_or_load_vdb([], force_rebuild=False)
				return SourceCodeRetriever(vdb_engine=vdb_engine)

			cloned_path = clone_repo_at_ref(repo_url, repo_ref, logger)
			if not cloned_path:
				raise RuntimeError(f"Clone failed for {repo_url}@{repo_ref}")
			vdb_engine = build_vdb(cloned_path, repo_url, repo_ref, logger)
			return SourceCodeRetriever(vdb_engine=vdb_engine)

		tools = []

		# SBOM tool
		if "sbom" in enabled_tools and sbom_tool:
			tools.append(sbom_tool)

		# NVD Intel tool
		if "nvd" in enabled_tools:
			tools.append(NVDIntelTool())

		# Web Search tool
		if "web" in enabled_tools:
			tools.append(CVEWebSearchTool(logger=logger))

		# Source Code Retriever (RAG-based semantic search)
		if "source_code" in enabled_tools:
			source_code_retriever = CallSourceCodeRetriever(
			    build_retriever, logger=logger)
			tools.append(source_code_retriever)

		# Code Reachability Analyzer
		if "reachability" in enabled_tools:
			reachability_analyzer = CodeReachabilityAnalyzer(
				retriever_func=None,
				repo_path=repo_path if repo_path.exists() else None,
				repo_ref=repo_ref,
				repo_url=repo_url
			)
			tools.append(reachability_analyzer.as_tool())

		# RAG wrapped inside Reachability (special config)
		if "reachability_with_rag" in enabled_tools:
			source_code_retriever = CallSourceCodeRetriever(
			    build_retriever, logger=logger)
			reachability_analyzer = CodeReachabilityAnalyzer(
				retriever_func=source_code_retriever,  # Pass retriever to reachability
				repo_path=repo_path if repo_path.exists() else None,
				repo_ref=repo_ref,
				repo_url=repo_url
			)
			tools.append(reachability_analyzer.as_tool())

		logger.info(
		    f"Tools config '{tools_config}': {[t.__class__.__name__ if hasattr(t, '__class__') else str(t) for t in tools]}")
		agent = SourceCodeCVEAgent(
		    tools=tools, logger=logger, tools_config=tools_config)
		
		# Load optimized state if provided (per DSPy docs: reconstruct then .load())
		if optimized_state_path:
			agent.load(optimized_state_path)
			logger.info(f"Loaded optimized state from {optimized_state_path}")

	cve_id = entry.get("CVE_ID", "")

	start = time.time()
	pred = agent(cve_id=cve_id)
	elapsed = time.time() - start

	logger.info(f"=======Output from DSPy=================\n{pred}")

	# Track LM usage
	usage_stats = {"prompt_tokens": 0, "completion_tokens": 0,
	    "total_tokens": 0}  # , "cached_tokens": 0}
	try:
		if hasattr(pred, "get_lm_usage"):
			raw_usage = pred.get_lm_usage()
			for model_stats in raw_usage.values():
				usage_stats["prompt_tokens"] += model_stats.get("prompt_tokens", 0)
				usage_stats["completion_tokens"] += model_stats.get("completion_tokens", 0)
				usage_stats["total_tokens"] += model_stats.get("total_tokens", 0)
				# usage_stats["cached_tokens"] += model_stats.get("prompt_tokens_details", {}).get("cached_tokens", 0)

			if logger:
				logger.info(f"Token usage for {cve_id}: {usage_stats}")
	except Exception as e:
		if logger:
			logger.warning(f"Failed to track LM usage: {e}")

	# Calculate Metric Score
	metric_components = {}
	try:
		# Create a SimpleNamespace to mimic the example object with ground truth from entry
		example_obj = SimpleNamespace(**entry)
		# Pass return_details=True to get component metrics
		metric_score, metric_components = composite_cve_metric(
			example_obj, pred, llm_judge=False, return_details=True
		)
		logger.info(f"CVE {cve_id} => Score: {metric_score:.4f}")
	except Exception as e:
		logger.error(f"Failed to calculate metric: {e}")
		metric_score = 0.0

	logger.info(f"CVE {cve_id} => {pred.csaf_vex_status} in {elapsed:.2f}s")

	# Extract llm_judge_reasoning if present (only when llm_judge=True)
	llm_judge_reasoning = metric_components.pop('llm_judge_reasoning', None)

	result = {
		"cve": cve_id,
		"composite_score": round(metric_score, 8),
		# Internal, for aggregation only
		"metric_components": {k: round(v, 4) for k, v in metric_components.items() if isinstance(v, (int, float))},
		"csaf_vex_status": getattr(pred, "csaf_vex_status", ""),
		"status_justification": getattr(pred, "status_justification", ""),
		"csaf_vex_justification": getattr(pred, "csaf_vex_justification", ""),
		"confidence": getattr(pred, "confidence", "N/A"),
		"investigation_checklist": getattr(pred, "investigation_checklist", ""),
		"tool_reasoning": getattr(pred, "tool_reasoning", ""),
		"justification": getattr(pred, "justification", ""),
		"elapsed_sec": round(elapsed, 2),
		"token_usage": usage_stats,
		"language": getattr(pred, "language", ""),
	}

	# Include LLM judge reasoning only when llm_judge=True
	if llm_judge_reasoning:
		result["llm_judge_reasoning"] = llm_judge_reasoning

	return result


def evaluate_batch(
	cases: List[Dict[str, Any]],
	model_name: str,
	logger: logging.Logger,
	agent: Optional["SourceCodeCVEAgent"] = None,
	tools_config: str = "full",
	optimized_state_path: Optional[str] = None
) -> Dict[str, Any]:
	"""Evaluate a batch of CVE cases. Returns same format as main().

	Args:
		cases: List of CVE case dictionaries with keys: CVE_ID, repository, vuln_ref, image, csaf_vex_status
		model_name: Model name for cost calculation
		logger: Logger instance
		agent: Optional pre-built agent (e.g., loaded from MIPROv2 optimization).
		       If provided, uses this agent for all cases instead of creating new ones.
		optimized_state_path: Optional path to state.json from DSPy optimization.
		       Per DSPy docs: with save_program=False, agent is built then .load() is called.

	Returns:
		Dictionary with keys: metadata, predictions, results (same as main output)
	"""
	from urllib.parse import unquote

	results = []

	for idx, entry in enumerate(cases):
		cve_id = entry.get("CVE_ID", "")
		repo_url = entry.get("repository", "")
		repo_ref = entry.get("vuln_ref", "")
		image = entry.get("image", "")

		logger.info(f"Processing CVE {idx + 1}/{len(cases)}: {cve_id}")

		# Resolve SBOM
		sbom_path = resolve_sbom_path(image, logger)
		sbom_tool = SBOMPackageChecker(sbom_txt_path=str(
		    sbom_path), logger=logger) if sbom_path else None

		# Run case (pass agent or optimized_state_path if provided)
		result = run_case(entry, repo_url, unquote(repo_ref), sbom_tool,
		                  logger, agent=agent, tools_config=tools_config,
		                  optimized_state_path=optimized_state_path)
		result["repo"] = repo_url
		result["ref"] = repo_ref

		# Add expected vs predicted
		expected_status = entry.get("csaf_vex_status", "")
		predicted_status = result.get("csaf_vex_status", "")
		result["expected_vex_status"] = expected_status
		result["csaf_vex_match"] = (
			predicted_status == expected_status or
			(expected_status == "not_affected" and predicted_status in [
			 "fixed", "under_investigation"])
		)
		results.append(result)
		logger.info(f"Completed {cve_id} ({idx + 1}/{len(cases)})")

	# Use shared metric calculation
	summary = calculate_batch_metrics(results, model_name)
	# Strip internal metric_components before output
	clean_results = [{k: v for k, v in r.items() if not k.startswith('_')}
	                                           for r in results]
	summary["results"] = clean_results
	return summary


def main():

	parser = argparse.ArgumentParser(description="Run CSAF/VEX CVE analysis")
	parser.add_argument(
		"--max-cves",
		type=int,
		default=int(os.environ.get("MAX_CVES", "1")),
		help="Max CVEs to analyze (default: env MAX_CVES or 1). Ignored if --eval is set.",
	)
	parser.add_argument(
		"--eval",
		action="store_true",
		help="Use DATASET_SPLITS for model-specific eval fraction instead of --max-cves",
	)
	parser.add_argument(
		"--model",
		type=str,
		default=None,
		help="Model name ['gemini-2.0-flash','gpt-4.1-mini'] (prompts interactively if not set)",
	)
	parser.add_argument(
		"--seed",
		type=int,
		default=int(os.environ.get("SEED", "42")),
		help="Random seed for reproducibility (default: env SEED or 42)",
	)
	parser.add_argument(
		"--tools-config",
		type=str,
		default="full",
		choices=list(TOOLS_CONFIG.keys()),
		help="Tool configuration for ablation study (default: full)",
	)
	parser.add_argument(
		"--agent",
		type=str,
		default=None,
		help="Path to optimized agent directory (from MIPROv2 optimization)",
	)
	args = parser.parse_args()

	log_dir = BASE_DIR / "vul_analysis" / "logs"
	log_dir.mkdir(parents=True, exist_ok=True)
	log_path = log_dir / \
	    f"runner_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
		handlers=[
			logging.FileHandler(log_path, encoding="utf-8"),
			logging.StreamHandler(),
		],
		force=True,
	)
	logger = logging.getLogger(__name__)


	# Config model
	_, model_name = configure_model(args.model, logger)
	
	# Setup MLflow tracing
	setup_mlflow(experiment_name="ContainerSecurity-Analysis")

	# Load datasets
	vulhub_cases = load_cases(VULHUB_DATASET)
	fp_cases = load_cases(VULHUB_FP_DATASET)
	if not vulhub_cases and not fp_cases:
		logger.warning("No cases found in vulhub/FP datasets")
		return

	# Use unified stratify_and_split function
	_, cases = stratify_and_split(
		vulhub_cases, fp_cases, model_name, 
		seed=args.seed,
		max_cves=args.max_cves,
		eval_mode=args.eval
	)

	if not cases:
		logger.warning("No cases selected after stratification")
		return

	# Load optimized agent state if path provided
	# Per DSPy docs: With save_program=False, we store the state file path and 
	# load it after each agent is constructed with tools in run_case()
	optimized_state_path = None
	if args.agent:
		agent_path = Path(args.agent)
		if agent_path.is_dir():
			# If directory provided, look for state.json inside
			state_file = agent_path / "state.json"
			if state_file.exists():
				optimized_state_path = str(state_file)
				logger.info(f"Will load optimized state from {state_file}")
			else:
				logger.error(f"state.json not found in directory: {agent_path}")
				return
		elif agent_path.is_file():
			# Direct file path (state.json or .pkl)
			optimized_state_path = str(agent_path)
			logger.info(f"Will load optimized state from {agent_path}")
		else:
			logger.error(f"Agent path not found: {agent_path}")
			return

	# Run evaluation using shared function
	summary = evaluate_batch(cases, model_name, logger, tools_config=args.tools_config, optimized_state_path=optimized_state_path)
	summary["metadata"]["max_cves"] = len(cases)
	summary["metadata"]["tools_config"] = args.tools_config

	# Save results
	out_dir = log_dir
	out_dir.mkdir(parents=True, exist_ok=True)
	out_file = out_dir / f"runner_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
	
	with out_file.open("w", encoding="utf-8") as f:
		json.dump(summary, f, indent=2, ensure_ascii=False)

	logger.info(f"Analysis complete: {summary['metadata']['total_cves_processed']} CVEs processed")
	logger.info(f"Saved results to {out_file}")
	print(f"\nResults: {out_file}\nLogs: {log_path}\n")

if __name__ == '__main__':
    main()
