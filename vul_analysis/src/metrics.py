"""
Composite Metrics for CVE Vulnerability Analysis. Multi-dimensional metric system for DSPy optimization of CVE triage agents.

Key Components:
- Decision Correctness: Classification accuracy + justification validation
- Evidence Coherence: Anti-hallucination via trajectory verification  
- Tool Efficiency: Penalizes wasteful tool usage
- Calibration: Confidence vs correctness alignment (always [0,1])
- Reasoning Quality: Heuristic or LLM-as-Judge evaluation
"""

import re
from typing import Any, Optional, Dict

import dspy


# =============================================================================
# CONFIGURATION
# =============================================================================

# Metric weights - sum to 1.0
WEIGHTS = {
    'decision_correctness': 0.40,  # Classification + justification validation
    'evidence_coherence': 0.25,    # Anti-hallucination (trace verification)
    'tool_efficiency': 0.15,       # Optimal tool usage
    'calibration': 0.10,           # Confidence alignment
    'reasoning_quality': 0.10      # Quality of reasoning
}

# Confidence value mapping
CONFIDENCE_VALUES = {
    'high': 0.9,
    'medium': 0.6,
    'low': 0.3
}

# Valid justifications for not_affected status
VALID_JUSTIFICATIONS = {
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'vulnerable_code_not_in_execute_path',
    'inline_mitigations_already_exist'
}

# Security-specific terms for reasoning quality
SECURITY_TERMS = {
    'version', 'package', 'vulnerable', 'sbom', 'component', 
    'cve', 'patch', 'fixed', 'affected', 'exploit'
}


# =============================================================================
# DECISION CORRECTNESS (Weight: 0.40)
# =============================================================================

def decision_correctness_score(
    expected: str, 
    predicted: str, 
    status_justification: str
) -> float:
    """
    Score based on classification correctness + justification validity.
    
    Binary classification: 'affected' vs 'not_affected'
    For 'not_affected', validates that status_justification is provided and valid.
    
    Scoring:
    - Correct + valid justification: 1.0
    - Correct + non-standard justification: 0.8
    - Correct + missing justification: 0.6
    - False positive (predicted affected when not): 0.2 (safe but wasteful)
    - False negative (predicted not_affected when affected): 0.0 (dangerous)
    
    Args:
        expected: Ground truth label ('affected' or 'not_affected')
        predicted: Model prediction ('affected' or 'not_affected')
        status_justification: Justification string (required for not_affected)
    
    Returns:
        Score in [0.0, 1.0]
    """
    expected = str(expected).strip().lower().replace(' ', '_')
    predicted = str(predicted).strip().lower().replace(' ', '_')
    justification = str(status_justification).strip().lower().replace(' ', '_')
    
    is_correct = (expected == predicted)
    
    if is_correct:
        if predicted == 'not_affected':
            # Validate justification for not_affected
            if justification in VALID_JUSTIFICATIONS:
                return 1.0  # Correct + valid justification
            elif justification:
                return 0.8  # Correct but non-standard justification
            else:
                return 0.6  # Correct but missing justification
        else:
            return 1.0  # Correct affected prediction
    else:
        # Incorrect classification
        if expected == 'affected' and predicted == 'not_affected':
            return 0.0  # False negative - dangerous
        else:
            return 0.2  # False positive - wasteful but safe


# =============================================================================
# EVIDENCE COHERENCE (Weight: 0.25)
# =============================================================================

class TraceVerifier:
    """Verifies that cited evidence exists in tool execution trajectory."""
    
    @staticmethod
    def verify(tool_reasoning: str, trajectory: Dict[str, Any]) -> float:
        """
        Check if cited evidence lines exist in tool execution trajectory.
        Prevents hallucinated evidence citations.
        
        Args:
            tool_reasoning: Text with E1, E2, etc. evidence citations
            trajectory: Dictionary of tool calls/observations from ReAct
        
        Returns:
            Score in [0.0, 1.0] based on evidence validity
        """
        if not tool_reasoning:
            return 0.0
        
        # Handle missing trajectory gracefully
        if not trajectory:
            return 0.5
        
        # Check for evidence citations (E1, E2, etc.)
        if not re.search(r'E\d+', tool_reasoning):
            return 0.3  # No citations to verify
        
        # Gather all observations from trajectory
        observations = []
        for key, val in trajectory.items():
            if key.startswith('observation'):
                observations.append(str(val).lower())
        
        if not observations:
            return 0.4
        
        full_obs_text = " ".join(observations)
        
        # Extract quoted content after E#: pattern
        # Improved regex to handle "it's" inside double quotes or 'said "hello"' inside single quotes
        regex_matches = re.findall(
            r'E\d+:\s*[^:]+:\s*(?:"([^"]+)"|\'([^\']+)\'|([^"\']+))', 
            tool_reasoning
        )
        evidence_quotes = [m[0] or m[1] or m[2] for m in regex_matches if any(m)]
        evidence_quotes = [e.strip() for e in evidence_quotes if e.strip()]
        
        if not evidence_quotes:
            # Fallback: check if any evidence keywords appear in observations
            keywords_found = sum(
                1 for term in SECURITY_TERMS 
                if term in tool_reasoning.lower() and term in full_obs_text
            )
            return min(1.0, 0.4 + (0.1 * keywords_found))
        
        # Verify each quoted evidence exists in observations
        matches = 0
        evaluated = 0  # Track how many quotes were actually checked
        for quote in evidence_quotes:
            clean = quote.strip().lower()
            if len(clean) < 5:
                continue
            
            evaluated += 1
            if clean in full_obs_text:
                matches += 1
            else:
                # Fuzzy match: 80% of words present
                words = clean.split()
                if words:
                    hits = sum(1 for w in words if w in full_obs_text)
                    if hits / len(words) > 0.8:
                        matches += 1
        
        if evaluated == 0:
            # All quotes were too short, fall back to keyword check
            keywords_found = sum(
                1 for term in SECURITY_TERMS 
                if term in tool_reasoning.lower() and term in full_obs_text
            )
            return min(1.0, 0.4 + (0.1 * keywords_found))
        
        return matches / evaluated


# =============================================================================
# TOOL EFFICIENCY (Weight: 0.15)
# =============================================================================

def tool_efficiency_score(
    trajectory: Dict[str, Any], 
    final_status: str, 
    status_justification: str
) -> float:
    """
    Rewards efficient tool usage based on decision type.
    
    Optimal tool call ranges:
    - component_not_present: 2-4 calls (NVD + SBOM checks sufficient)
    - Other not_affected reasons: 3-5 calls (need some code analysis)
    - affected: 3-6 calls (thorough verification needed)
    
    Args:
        trajectory: Dictionary of tool calls from ReAct agent
        final_status: 'affected' or 'not_affected'
        status_justification: Justification for not_affected decisions
    
    Returns:
        Score in [0.0, 1.0]
    """
    # Count tool calls
    tool_calls = sum(1 for k in trajectory if k.startswith('tool_name_'))
    
    # Determine optimal range based on decision
    final_status = str(final_status).strip().lower()
    justification = str(status_justification).strip().lower().replace(' ', '_')
    
    if final_status == 'not_affected':
        if justification == 'component_not_present':
            min_calls, max_calls = 2, 4
        else:
            min_calls, max_calls = 3, 5
    else:  # affected
        min_calls, max_calls = 3, 6
    
    # Score based on range
    if min_calls <= tool_calls <= max_calls:
        return 1.0
    elif tool_calls < min_calls:
        return 0.6  # Too quick
    else:
        excess = tool_calls - max_calls
        return max(0.3, 1.0 - (0.1 * excess))


# =============================================================================
# CALIBRATION (Weight: 0.10)
# =============================================================================

def calibration_score(is_correct: bool, confidence_str: str) -> float:
    """
    Calibration score always in [0.0, 1.0].
    
    Rewards well-calibrated confidence:
    - High confidence + correct = 0.9 (good)
    - Low confidence + wrong = 0.7 (honest uncertainty)
    - Low confidence + correct = 0.3 (underconfident)
    - High confidence + wrong = 0.1 (overconfident, bad)
    
    Args:
        is_correct: Whether prediction matches ground truth
        confidence_str: 'High', 'Medium', or 'Low'
    
    Returns:
        Score in [0.0, 1.0]
    """
    conf = CONFIDENCE_VALUES.get(str(confidence_str).lower(), 0.5)
    
    if is_correct:
        return conf  # High conf + correct = high score
    else:
        return 1.0 - conf  # Low conf + wrong = higher score (honest)


# =============================================================================
# REASONING QUALITY (Weight: 0.10)
# =============================================================================

def reasoning_quality_heuristic(tool_reasoning: str, justification: str) -> float:
    """
    Simple heuristic for reasoning quality.
    
    Evaluates:
    1. Evidence citations (E1, E2, etc.) - 40%
    2. Security-specific terms - 30%
    3. Reasonable length - 30%
    
    Args:
        tool_reasoning: Tool evidence text
        justification: Final justification text
    
    Returns:
        Score in [0.0, 1.0]
    """
    combined = f"{tool_reasoning or ''} {justification or ''}".lower()
    score = 0.0
    
    # 1. Evidence citations (0.4)
    citations = len(re.findall(r'E\d+', combined))
    score += 0.4 * min(1.0, citations / 4)
    
    # 2. Security terms (0.3)
    term_hits = sum(1 for t in SECURITY_TERMS if t in combined)
    score += 0.3 * min(1.0, term_hits / 4)
    
    # 3. Reasonable length (0.3)
    words = len(combined.split())
    if 20 <= words <= 200:
        score += 0.3
    elif 10 <= words < 20 or 200 < words <= 300:
        score += 0.15
    
    return min(1.0, score)


# =============================================================================
# LLM-AS-JUDGE (Optional, disabled by default)
# =============================================================================

class ReasoningQualityJudge(dspy.Signature):
    """
    Expert evaluation of CVE vulnerability analysis reasoning quality.
    
    You are a senior security engineer evaluating the quality of an AI agent's
    CVE vulnerability analysis. Your task is to assess whether the agent's
    reasoning is logically sound, properly grounded in evidence, and reaches
    a defensible conclusion.
    
    Scoring Guidelines:
    - 0.9-1.0: Excellent - Clear evidence chain, all claims supported, correct conclusion
    - 0.7-0.8: Good - Solid reasoning with minor gaps, mostly supported claims
    - 0.5-0.6: Acceptable - Basic reasoning present, some unsupported claims
    - 0.3-0.4: Poor - Weak reasoning, significant gaps, questionable conclusions
    - 0.0-0.2: Failed - No clear reasoning, hallucinated claims, wrong methodology
    """
    
    # Input: CVE context
    cve_id: str = dspy.InputField(desc="The CVE identifier being analyzed (e.g., CVE-2024-1234)")
    # Input: Ground truth
    expected_status: str = dspy.InputField(desc="Expected classification: 'affected' or 'not_affected'")
    # Input: Agent's prediction
    predicted_status: str = dspy.InputField(desc="Agent's prediction: 'affected' or 'not_affected'")
    # Input: Agent's evidence
    tool_reasoning: str = dspy.InputField(
        desc=(
            "Agent's tool evidence in format: 'E1: ToolName: evidence text'. "
            "Each line should cite specific tool observations. "
            "Evaluate if citations are relevant and support the conclusion."
        )
    )
    # Input: Agent's justification
    justification: str = dspy.InputField(
        desc=(
            "Agent's final justification for stakeholders. Should include: "
            "(1) Evidence summary (2) Confidence assessment (3) Key reasoning "
            "(4) Risk level (5) Recommended action"
        )
    )
    # Input: Status justification for not_affected
    status_justification: str = dspy.InputField(
        desc=(
            "If predicted='not_affected', the specific reason: "
            "component_not_present / vulnerable_code_not_present / "
            "vulnerable_code_cannot_be_controlled_by_adversary / "
            "vulnerable_code_not_in_execute_path / inline_mitigations_already_exist"
        )
    )
    # Output: Score
    relevance_score: float = dspy.OutputField(
        desc=(
            "Float between 0.0 and 1.0 evaluating overall reasoning quality. "
            "Consider: (1) Evidence-conclusion alignment (2) Logical coherence "
            "(3) Appropriate caution for security context (4) Completeness"
        )
    )
    # Output: Explanation
    evaluation_reasoning: str = dspy.OutputField(
        desc=(
            "2-3 sentence explanation of the score. Cite specific strengths "
            "or weaknesses in the agent's reasoning."
        )
    )
    # # RAG Triad Metrics (optional, for TABLE III evaluation)
    # context_relevance: float = dspy.OutputField(
    #     desc="0.0-1.0: Is retrieved code relevant to the CVE vulnerability?"
    # )
    # answer_faithfulness: float = dspy.OutputField(
    #     desc="0.0-1.0: Is the VEX conclusion grounded in cited evidence?"
    # )
    # answer_relevance: float = dspy.OutputField(
    #     desc="0.0-1.0: Does the response directly address exploitability?"
    # )
    # evidence_completeness: float = dspy.OutputField(
    #     desc="0.0-1.0: Are all necessary evidence sources consulted?"
    # )


def reasoning_quality_llm_judge(
    cve_id: str,
    expected_status: str,
    predicted_status: str,
    tool_reasoning: str,
    justification: str,
    status_justification: str,
    return_reasoning: bool = False
) -> float | tuple[float, str]:
    """
    Use LLM (GPT-4.1-mini) to evaluate reasoning quality.
    
    This provides more nuanced evaluation than heuristics but is slower
    and requires API calls. Use for final evaluation, not optimization loops.
    
    Args:
        cve_id: CVE identifier
        expected_status: Ground truth classification
        predicted_status: Agent's prediction
        tool_reasoning: Agent's evidence citations
        justification: Agent's stakeholder justification
        status_justification: Reason for not_affected (if applicable)
        return_reasoning: If True, return (score, reasoning) tuple
    
    Returns:
        If return_reasoning=False: Score in [0.0, 1.0]
        If return_reasoning=True: Tuple of (score, evaluation_reasoning)
    """
    try:
        # Use GPT-4.1-mini as judge
        judge_lm = dspy.LM("openai/gpt-4.1-mini", max_tokens=5000)
        
        with dspy.context(lm=judge_lm):
            judge = dspy.Predict(ReasoningQualityJudge)
            response = judge(
                cve_id=str(cve_id),
                expected_status=str(expected_status),
                predicted_status=str(predicted_status),
                tool_reasoning=str(tool_reasoning or ''),
                justification=str(justification or ''),
                status_justification=str(status_justification or '')
            )
            
            # Parse and clamp score
            score = float(response.relevance_score)
            score = max(0.0, min(1.0, score))
            evaluation_reasoning = getattr(response, 'evaluation_reasoning', '')
            
            if return_reasoning:
                return score, evaluation_reasoning
            return score
            
    except Exception:
        # Fallback to heuristic on any error
        fallback_score = reasoning_quality_heuristic(tool_reasoning, justification)
        if return_reasoning:
            return fallback_score, ''
        return fallback_score


# =============================================================================
# MAIN METRIC FUNCTION
# =============================================================================

def composite_cve_metric(
    example: Any,
    prediction: Any,
    trace: Optional[Any] = None,
    llm_judge: bool = False,
    return_details: bool = False
):
    """
    Optimized multi-dimensional metric for CVE vulnerability analysis.
    
    Designed for DSPy MIPROv2 optimization. All component scores are in [0, 1]
    and the final weighted sum is also in [0, 1].
    
    Args:
        example: Ground truth with 'csaf_vex_status' attribute
        prediction: DSPy prediction object with agent outputs
        trace: Optional execution trace (not currently used)
        llm_judge: If True, use LLM for reasoning quality (slower, more accurate)
        return_details: If True, return tuple of (score, metrics_dict)
    
    Returns:
        If return_details=False: Weighted score in [0.0, 1.0]
        If return_details=True: Tuple of (score, metrics_dict)
    
    Component Weights:
        - decision_correctness: 0.40
        - evidence_coherence: 0.25
        - tool_efficiency: 0.15
        - calibration: 0.10
        - reasoning_quality: 0.10
    """
    try:
        # Extract values from example and prediction
        expected = getattr(example, 'csaf_vex_status', 'not_affected')
        predicted = getattr(prediction, 'csaf_vex_status', 'not_affected')
        status_justification = getattr(prediction, 'status_justification', '')
        trajectory = getattr(prediction, 'trajectory', {})
        confidence = getattr(prediction, 'confidence', 'medium')
        tool_reasoning = getattr(prediction, 'tool_reasoning', '')
        justification = getattr(prediction, 'justification', '')
        cve_id = getattr(example, 'CVE_ID', getattr(example, 'cve_id', ''))
        
        # Normalize
        expected = str(expected).strip().lower()
        predicted = str(predicted).strip().lower()
        is_correct = (expected == predicted)
        
        # Calculate component scores
        metrics = {}
        
        # 1. Decision Correctness (0.40)
        metrics['decision_correctness'] = decision_correctness_score(
            expected, predicted, status_justification
        )
        
        # 2. Evidence Coherence (0.25)
        metrics['evidence_coherence'] = TraceVerifier.verify(
            tool_reasoning, trajectory
        )
        
        # 3. Tool Efficiency (0.15)
        metrics['tool_efficiency'] = tool_efficiency_score(
            trajectory, predicted, status_justification
        )
        
        # 4. Calibration (0.10)
        metrics['calibration'] = calibration_score(is_correct, confidence)
        
        # 5. Reasoning Quality (0.10)
        llm_judge_reasoning = ''
        if llm_judge:
            score, llm_judge_reasoning = reasoning_quality_llm_judge(
                cve_id=cve_id,
                expected_status=expected,
                predicted_status=predicted,
                tool_reasoning=tool_reasoning,
                justification=justification,
                status_justification=status_justification,
                return_reasoning=True
            )
            metrics['reasoning_quality'] = score
        else:
            metrics['reasoning_quality'] = reasoning_quality_heuristic(
                tool_reasoning, justification
            )
        
        # Weighted sum
        final_score = sum(
            metrics[key] * WEIGHTS[key]
            for key in WEIGHTS
        )
        
        final_score = float(max(0.0, min(1.0, final_score)))
        
        if return_details:
            if llm_judge and llm_judge_reasoning:
                metrics['llm_judge_reasoning'] = llm_judge_reasoning
            return final_score, metrics
        return final_score
        
    except Exception:
        if return_details:
            return 0.0, {}
        return 0.0
