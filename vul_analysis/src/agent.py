import dspy
import logging
import json

from .utils.prompts import SIGNATURE_DOCSTRINGS, FEW_SHOT_EXAMPLES


def create_security_expert_signature(tools_config: str = "full"):
    """Factory function to create SecurityExpertAnalysis with dynamic docstring.
    
    Args:
        tools_config: One of 'baseline', 'with_intel', 'source_only', 'rag_wrapped', 'full'
    
    Returns:
        SecurityExpertAnalysis class with the appropriate docstring for the config
    """
    doc = SIGNATURE_DOCSTRINGS.get(tools_config, SIGNATURE_DOCSTRINGS["full"])
    # doc += "\n\nHere are some Sample examples of the analysis for your reference:\n\n"
    # doc += json.dumps(FEW_SHOT_EXAMPLES, indent=2) + "\n================================================================================\n"
    
    class SecurityExpertAnalysis(dspy.Signature):
        __doc__ = doc

        # Input fields - Information from vulnerability scanner
        cve_id: str = dspy.InputField(
            desc="CVE identifier (e.g., CVE-2024-1234)"
        )

        # Output fields - Your expert analysis results
        investigation_checklist: str = dspy.OutputField(
            desc="Exactly 6 lines: '1. [x] ...' through '6. [x] ...'. Mark only definitive items as [x] else []."
        )
        tool_reasoning: str = dspy.OutputField(
            desc='4-8 lines of tool evidence, each line: E#: <ToolName>: "<exact quote>". Include exact versions/ranges/paths/commands when present. Then tie conclusions to E# lines. Address: presence, version match, reachability, exploitability, mitigations.'
        )
        csaf_vex_status: str = dspy.OutputField(
            desc="CSAF VEX status: 'affected' | 'not_affected'. Here affected (Vulnerable) and all other label (if not vulnerable)"
        )
        status_justification: str = dspy.OutputField(
            desc="If csaf_vex_status='not_affected': one of (component_not_present/vulnerable_code_not_present/vulnerable_code_cannot_be_controlled_by_adversary/vulnerable_code_not_in_execute_path/inline_mitigations_already_exist). Else: empty."
        )
        csaf_vex_justification: str = dspy.OutputField(
            desc="CSAF justification (2-4 sentences) tied to E# evidence; if 'not_affected', cite the justification reason; if 'fixed', cite fix evidence."
        )
        confidence: str = dspy.OutputField(
            desc="'High' (>80% - strong multi-tool evidence) | 'Medium' (50-80% - good but some gaps) | 'Low' (<50% - limited/conflicting, should be not_affected)"
        )
        justification: str = dspy.OutputField(
            desc="For stakeholders: (1) Evidence summary with citations (2) Confidence assessment (3) Key reasoning (4) Risk level (5) Action: upgrade/investigate/accept. Explain why confidence is >50% for affected or ≤50% for not_affected."
        )
        language: str = dspy.OutputField(
            desc="Programming language of the repository/code analyzed (e.g., 'Python', 'Java', 'JavaScript', 'Go', 'C/C++', 'Ruby', 'PHP', 'Mixed', 'Unknown'). Used for language-based CVE detection capability analysis."
        )
    
    return SecurityExpertAnalysis


class SourceCodeCVEAgent(dspy.Module):
    """DSPy ReAct agent for CVE analysis with tool access."""
    def __init__(self, tools=None, logger=None, tools_config: str = "full"):
        super().__init__()
        
        # Create signature with dynamic docstring based on tools_config
        signature_class = create_security_expert_signature(tools_config)
        
        self.react_agent = dspy.ReAct(signature=signature_class, tools=tools or [], max_iters=8)
        self.logger = logger or logging.getLogger(__name__)
        self.logger.info(f"Config: {tools_config}, Tools: {[getattr(t, 'name', t.__class__.__name__) for t in tools]}")

    def forward(self, cve_id):
        # Log agent invocation
        if self.logger:
            self.logger.info(f"ReAct Agent called for {cve_id}")
        
        result = self.react_agent(cve_id=cve_id)
        
        # Avoid logging chain-of-thought; only log trace availability/size.
        if self.logger and hasattr(result, '_trace'):
            try:
                self.logger.info(f"ReAct trace captured (steps={len(result._trace)})")
            except Exception:
                self.logger.info("ReAct trace captured")

        return result
