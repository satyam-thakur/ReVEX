# ReVEX: Vulnerability Analysis Module

This directory contains the core ReVEX agent — a DSPy-optimized ReAct agent for automated container vulnerability verification.

## Capabilities

| Capability | Description |
|---|---|
| **NVD Intelligence** | Retrieves CVE metadata, affected product enumerations, and vendor references |
| **SBOM Verification** | Confirms whether the vulnerable component is present in the target container image |
| **Code Reachability** | Performs RAG-based source code analysis to determine if vulnerable code paths are reachable |
| **VEX Generation** | Produces CSAF-aligned exploitability status: `affected` or `not_affected` |

## Directory Structure

```
vul_analysis/
├── src/
│   ├── runner.py             # Main CLI entrypoint
│   ├── agent.py              # DSPy ReAct agent definition
│   ├── optimize_miprov2.py   # MIPROv2 prompt optimizer
│   ├── optimize_gepa.py      # GEPA prompt optimizer
│   ├── metrics.py            # Evaluation metrics (DHR, F1, Composite)
│   ├── tools/                # Agent tools (NVD, SBOM, code retrieval)
│   └── utils/                # Helpers and constants
├── datasets/                 # Evaluation datasets (Vulhub, FP cases)
├── logs/                     # Execution logs and result JSONs
└── .cache/                   # Cached repositories and vector DBs
```

## Sample Data Availability

- `vul_analysis/datasets/` includes evaluation inputs (`vulhub_eval_2020_2025.json`, `vulhub_fp.json`) and sample SBOM text files.
- `datasets/reconciled_data/` (repo root) provides reconciled per-image vulnerability JSON records.
- `GithubActions/` (repo root) contains sample scanner outputs (Clair, Grype, Snyk, Trivy) and Syft SBOM exports.

## Double-Blind Note

This repository is prepared for double-blind review and intentionally avoids identity-revealing information in this module README.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r vul_analysis/src/requirements.txt
```

### 2. Configure Environment

Set API keys in `.env` or your shell:

```bash
# At least one LLM provider is required
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
OPENROUTER_API_KEY=...

# Recommended
NVD_API_KEY=...          # Avoids NVD rate limits
TAVILY_API_KEY=...       # Enables web search tool
```

### 3. Run Analysis

```bash
# Analyze a set of CVEs
python -m vul_analysis.src.runner --max-cves 5 --model gemini-2.0-flash

# Run in evaluation mode (uses predefined train/eval splits)
python -m vul_analysis.src.runner --eval --model gemini-2.0-flash

# Reproduce the default evaluation setting used in this repository
python -m vul_analysis.src.runner --eval --seed 42 --max-cves 5 --model gemini-2.0-flash
```

## Prompt Optimization

ReVEX supports two DSPy prompt optimization strategies:

```bash
# MIPROv2 — Bayesian search over prompt candidates
python -m vul_analysis.src.optimize_miprov2 --auto medium --model gemini-2.0-flash

# GEPA — Evolutionary, error-driven prompt refinement
python -m vul_analysis.src.optimize_gepa --max-rollouts 350 --model gemini-2.0-flash
```

Optimized programs are saved to `.cache/dspy_programs/`. For detailed GEPA configuration, see [`gepa_optimization.md`](src/gepa_optimization.md).

## CLI Reference

| Argument | Default | Description |
|----------|---------|-------------|
| `--max-cves` | `1` | Number of CVEs to analyze |
| `--eval` | `False` | Use evaluation dataset split |
| `--model` | interactive | LLM model identifier |
| `--seed` | `42` | Random seed for reproducibility |

## Outputs

Each run produces:

- **Results**: `logs/runner_test_results_{timestamp}.json`
- **Logs**: `logs/runner_test_{timestamp}.log`

Reported metrics include TP, FP, TN, FN, Precision, Recall, F1, F2, and token costs.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Import errors | Run via `python -m vul_analysis.src.runner` |
| NVD rate limits | Set `NVD_API_KEY` in environment |
| Web search disabled | Set `TAVILY_API_KEY` |
| Git not found | Install Git and ensure it is on `PATH` |
