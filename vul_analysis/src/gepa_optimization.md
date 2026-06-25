# GEPA Optimization Guide

Grounded Exploration Program Authorization (GEPA) is a DSPy optimizer that uses an evolutionary approach with a fixed computational budget. Unlike Bayesian optimizers that explore a broad search space, GEPA iteratively refines agent prompts through reflection on validation feedback, producing targeted improvements with predictable cost.

## Key Concepts

### Controlled Budgeting

GEPA provides precise control over optimization cost:

- **`--max-metric-calls`**: Sets a hard limit on the total number of evaluation calls. This is the primary parameter for controlling computational budget.
- **`--auto`**: Presets (`light`, `medium`, `heavy`) that calculate a budget based on dataset size. Useful for quick experimentation but less precise than setting metric calls directly.

### Stratified Dataset Splitting

ReVEX applies stratified sampling to maintain the ratio of True Positives (TP) to False Positives (FP) across training and evaluation splits. Split ratios are model-specific (e.g., 25% train / 12.5% eval for Gemini Flash) to balance cost and representation.

### Reflection Loop

GEPA improves the agent through four iterative steps:

1. **Trial** — Run the agent on a batch of training examples.
2. **Reflection** — Analyze errors to identify reasoning failures.
3. **Evolution** — Generate revised instructions that address the identified failures.
4. **Selection** — Validate revised prompts against the evaluation set and retain only those that improve the Pareto frontier across multiple metrics.

## Usage

### Quick Experimentation

```bash
python -m vul_analysis.src.optimize_gepa \
  --model gemini-2.0-flash \
  --auto light \
  --max-train 10 \
  --max-val 5
```

### Production Optimization

```bash
python -m vul_analysis.src.optimize_gepa \
  --model gemini-2.0-flash \
  --max-metric-calls 500 \
  --num-threads 8
```

### Teacher–Student Configuration

The reflection model (teacher) can differ from the agent being optimized (student):

```bash
python -m vul_analysis.src.optimize_gepa \
  --model gemini-2.0-flash \
  --reflection-model openai/gpt-4o \
  --max-metric-calls 300
```

## GEPA vs. MIPROv2

| Feature | GEPA (Evolutionary) | MIPROv2 (Bayesian) |
| :--- | :--- | :--- |
| **Approach** | Error-driven refinement | Data-driven search |
| **Budget Control** | Precise (hard limit on evaluations) | Variable (depends on search space) |
| **Sample Efficiency** | High — learns from fewer examples | Lower — requires more samples for statistical significance |
| **Best Suited For** | Targeted improvements with fixed budgets | Broad exploration with large compute budgets |

## Parameters

| Parameter | Description |
| :--- | :--- |
| `--model` | LLM to optimize (student) |
| `--reflection-model` | LLM for critique and prompt generation (teacher); defaults to `--model` |
| `--max-metric-calls` | Total evaluation budget (recommended for precise control) |
| `--auto` | Preset budget: `light`, `medium`, or `heavy` |
| `--num-threads` | Parallel execution threads |
| `--grid-search` | Run grid search over hyperparameters |

## References

- [DSPy GEPA Documentation](https://dspy.ai/api/optimizers/GEPA)
- [ReVEX Core Module](../README.md)
