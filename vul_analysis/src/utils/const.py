# Model-specific dataset split configurations
# Each tuple represents (train_fraction, eval_fraction)
DATASET_SPLITS = {
    # "gpt-5.1-pro": (1/20, 1/20),  # 5% - Default
    # "gpt-4.1-nano": (1/4, 1/4),  # 20% - baseline (cheapest GPT model)
    # "gpt-4o-mini": (1/4, 1/4),  # 20% - baseline (cheapest GPT model)
    "gpt-4.1-mini": (0.77, 0.23),  # 16.6% - Moderate cost, good capabilities
    # "gpt-4.1": (1/15, 1/15),  # ~6.7% - expensive but more capable
    # "gpt-4o": (1/15, 1/15),  # ~6.7% - expensive but more capable
    # "o3-mini": (1/7, 1/7),   # ~14.3% - moderate cost, good capabilities
    # "claude-3-5-haiku-latest": (1/5, 1/5),  # 20% - baseline (cheapest Anthropic model)
    # "claude-3-7-sonnet": (1/20, 1/20),  # 5% - Default
    # "claude-3-7-sonnet-latest": (1/10, 1/10),  # 10% - higher cost per token
    # "claude-3-5-sonnet-latest": (1/10, 1/10),  # 10% - higher cost per token
    # "grok-2-latest": (1/15, 1/15),  # ~6.7% - expensive but more capable, request limit
    # "grok-3-latest": (1/10, 1/10),  # 10% - higher cost per token
    # "grok-3-mini": (1/6, 1/6),  # 16.6% - Moderate cost, good capabilities
    "gemini-2.0-flash": (0.77, 0.23),    #(1/5, 1/8),  # 16.6% - Higher cost, more specialized
    # "gemini-2.5-pro": (1/4, 1/4),  # 5% - Default
    # "gemini-2.5-pro-exp-03-25": (1/10, 1/10),  # 10% - higher cost per token
    # "deepseek-chat": (1/6, 1/6),  # 16.6% - Moderate cost, good capabilities
    # "deepseek-reasoner": (1/8, 1/8),  # 12.5% - Higher cost, more specialized
    # "deepseek-ai/DeepSeek-V3": (1/8, 1/8),  # 12.5% - moderate validation
    # "deepseek-ai/DeepSeek-R1": (1/10, 1/10),  # 10% - higher cost per token
    # "llama-4-maverick": (1/20, 1/20),  # 5% - Default
    # "mistral-large-3": (1/20, 1/20),  # 5% - Default
    # "mistralai/Mistral-7B-Instruct-v0.3": (1/6, 1/6),  # 16.6% - can afford larger validation
    # "meta-llama/Llama-3.3-70B-Instruct-Turbo": (1/8, 1/8),  # 12.5% - moderate validation
    # "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8": (1/6, 1/6),  # 16.6% - Moderate cost, good capabilities
    # "qwen-qwq-32b": (1/20, 1/20),  # 5% - Default
    # "Qwen/Qwen2.5-7B-Instruct-Turbo": (1/6, 1/6), # 16.6% - can afford larger validation
    # "Qwen/QwQ-32B": (1/8, 1/8),  # 12.5% - moderate validation
    # "Qwen/Qwen2.5-72B-Instruct-Turbo": (1/8, 1/8),  # 12.5% - moderate validation
    # "Qwen/Qwen3-235B-A22B-fp8-tput": (1/6, 1/6), # 16.6% - Moderate cost, good capabilities
    # "qwen/qwen3-8b": (1/4, 1/4),
    # "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B": (1/10, 1/10),  # 10% - smaller validation
    # "deepseek-ai/DeepSeek-R1-Distill-Llama-70B": (1/10, 1/10),  # 10% - smaller validation
    # "gpt-oss-120b": (1/20, 1/20),  # 5% - Default
    "test_split:": (0.77, 0.23)  # 50% - For testing purposes
}

TOKEN_COSTS = {
    # --- OpenAI (Strictly aligned to your provided table) ---
    # 'gpt-5.1-pro' mapped to 'gpt-5-pro' pricing from your list ($15/$120) 
    # as 5.2-pro was $21/$168 and 5.1-base was $1.25/$10.
    "gpt-5.1-pro": [15.00, 120.00], 
    "gpt-5-mini": [0.25, 2],
    "gpt-4.1-nano": [0.10, 0.40],
    "gpt-4o-mini": [0.15, 0.60],
    "gpt-4.1-mini": [0.40, 1.60],
    "gpt-4.1": [2.00, 8.00],
    "gpt-4o": [2.50, 10.00],
    
    # 'o3-mini' was not in your table, using current standard reasoning price
    "o3-mini": [1.10, 4.40],

    # --- Anthropic (Standard Pricing) ---
    "claude-3-5-haiku-latest": [0.80, 4.00], 
    "claude-3-7-sonnet": [3.00, 15.00],
    "claude-3-7-sonnet-latest": [3.00, 15.00],
    "claude-3-5-sonnet-latest": [3.00, 15.00],
    "claude-haiku-4-5-20251001": [1.00, 5.00],
    "claude-sonnet-4-5-20250929": [3.00, 15.00],

    # --- xAI (Grok) ---
    "grok-2-latest": [2.00, 10.00],
    "grok-3-latest": [3.00, 12.00],
    "grok-3-mini": [0.20, 0.80],

    # --- Google (Gemini) ---
    "gemini-2.0-flash": [0.10, 0.40],
    "gemini-2.5-pro": [2.50, 10.00],
    "gemini-2.5-pro-exp-03-25": [2.50, 10.00],
    "gemini-3-pro": [2.00, 12.00],
    "gemini-3-flash-preview": [0.5, 3.00],

    # --- DeepSeek (Standard API) ---
    "deepseek/deepseek-chat": [0.30, 1.20],        # V3
    "deepseek-reasoner": [0.55, 2.19],    # R1
    "deepseek-ai/DeepSeek-V3": [0.14, 0.28], 
    "deepseek-ai/DeepSeek-R1": [0.55, 2.19],

    # --- Open Weights / Hosted Providers ---
    # Prices reflect typical 3rd party hosting (e.g., Together/Fireworks/Groq)
    # Input often equals Output for hosted open weights
    "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B": [0.20, 0.20],
    "deepseek-ai/DeepSeek-R1-Distill-Llama-70B": [0.70, 0.70],

    "llama-4-maverick": [2.50, 2.50],     # Est. Large Model
    "meta-llama/Llama-3.3-70B-Instruct-Turbo": [0.80, 0.80], 
    "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8": [0.20, 0.20],
    "meta-llama/llama-4-maverick": [0.15, 0.6],

    "mistral-large-3": [2.00, 6.00],
    "mistralai/Mistral-7B-Instruct-v0.3": [0.2, 0.2],
    "mistralai/mistral-large-2512": [0.5, 1.5],

    "qwen-qwq-32b": [0.50, 0.50],
    "Qwen/Qwen2.5-7B-Instruct-Turbo": [0.10, 0.10],
    "Qwen/QwQ-32B": [0.50, 0.50],
    "Qwen/Qwen2.5-72B-Instruct-Turbo": [0.80, 0.80],
    "Qwen/Qwen3-235B-A22B-fp8-tput": [1.50, 1.50], # Est. Huge MoE
    "qwen/qwen3-8b": [0.20, 0.20],

    "openai/gpt-oss-120b": [0.039, 0.19]
}

# Tool configurations for ablation study (TABLE VIII)
TOOLS_CONFIG = {
    "baseline": ["sbom", "reachability"],                          # Row 1: Baseline
    "with_intel": ["sbom", "reachability", "nvd", "web"],         # Row 2: +External Intel
    "source_only": ["sbom", "reachability", "nvd", "web", "source_code"],       # Row 3: +SourceCode
    "rag_wrapped": ["sbom", "reachability_with_rag", "nvd", "web"],             # Row 4: RAG inside Reachability
    "full": ["sbom", "nvd", "web", "source_code", "reachability"],# Row 5: Full Pipeline
}
