# ReVEX: Automated Container Vulnerability Verification via DSPy-Optimized ReAct Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

Software Composition Analysis (SCA) scanners frequently produce false positives, creating noise that hinders timely remediation. **ReVEX** addresses this problem by automating vulnerability verification through a DSPy-optimized ReAct agent that determines whether a reported CVE is truly exploitable within a given container image.

The agent integrates NVD intelligence, SBOM verification, and code reachability analysis to produce a [VEX](https://ntia.gov/files/ntia/publications/vex_one_page_summary.pdf)-aligned exploitability assessment (`affected` or `not_affected`).

<!--
## Key Contributions

- **Noise Reduction**: Verifies exploitability with 94.3% recall, significantly reducing false positives from raw scanner output.
- **Prompt Optimization**: Systematic comparison of MIPROv2 (Bayesian) and GEPA (Grounded Exploration) prompt optimizers, with GEPA yielding a +41.6% improvement in Defect Hit Rate (DHR).
- **Cost Efficiency**: Optimized lightweight agents achieve frontier-model performance at reduced inference cost.
- **Scanner Disagreement Study**: Empirical evaluation of four industry-standard SCA scanners reveals 84% disagreement on critical vulnerabilities.
-->

## Architecture

ReVEX operates as an autonomous ReAct loop:

1. **Ingest** — Accepts a scanner report and SBOM for the target container image.
2. **Reason** — Iteratively gathers evidence via specialized tools (NVD lookup, package verification, code reachability).
3. **Optimize** — Applies DSPy prompt optimization (MIPROv2 or GEPA) to improve the agent's reasoning accuracy.
4. **Output** — Produces a VEX statement classifying each CVE as `affected` or `not_affected`.

## Repository Structure

```
ReVEX/
├── vul_analysis/        # Core ReAct agent, tools, and prompt optimization
│   ├── src/             # Agent, runner, optimizers, metrics, tools
│   ├── datasets/        # Evaluation datasets (Vulhub, FP cases)
│   ├── evals/           # Evaluation results
│   └── logs/            # Execution logs
├── SCA_analysis/        # Scanner disagreement study scripts
├── datasets/            # Curated ground truth datasets
├── config/              # Experiment configuration files
└── GithubActions/       # Pre-generated scan artifacts
```

For module-level details, see [`vul_analysis/README.md`](vul_analysis/README.md).

## Getting Started

### Prerequisites

- Python 3.9+
- At least one LLM API key (OpenAI, Gemini, or OpenRouter)

### Installation

```bash
git clone https://github.com/yourusername/ReVEX.git
cd ReVEX
pip install -r vul_analysis/src/requirements.txt
```

### Configuration

Set API keys in `.env` or your shell environment:

```bash
OPENAI_API_KEY=sk-...       # or GEMINI_API_KEY / OPENROUTER_API_KEY
NVD_API_KEY=...             # Recommended: avoids rate limits
```

### Running the Agent

```bash
# Analyze CVEs with a specified model
python -m vul_analysis.src.runner --max-cves 5 --model gemini-2.0-flash

# Run in evaluation mode
python -m vul_analysis.src.runner --eval --model gemini-2.0-flash
```

### Prompt Optimization

```bash
# MIPROv2 (Bayesian)
python -m vul_analysis.src.optimize_miprov2 --auto medium --model gemini-2.0-flash

# GEPA (Grounded Exploration)
python -m vul_analysis.src.optimize_gepa --max-rollouts 350 --model gemini-2.0-flash
```

See [`gepa_optimization.md`](vul_analysis/src/gepa_optimization.md) for detailed optimization configuration.

## Citation

If you use ReVEX in your research, please cite:

```bibtex
@inproceedings{thakur2026revex,
  title={ReVEX: DSPy-Optimized ReAct Agents for Exploitability Verification of Container Vulnerabilities},
  author={Thakur, Satyam and Asish, Sarker Monojit and Al Amiri, Wesam and Farmani, Mohammad and Sarker, Arijet},
  booktitle={2026 23rd Annual International Conference on Privacy, Security and Trust (PST)},
  year={2026},
  organization={IEEE}
}
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
