import dspy
import logging
import re
import subprocess
from difflib import get_close_matches
from pathlib import Path
from typing import List, Optional, Any, Dict, Union
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Cache directory for repos (same as runner.py)
BASE_DIR = Path(__file__).resolve().parents[3]
REPOS_DIR = BASE_DIR / "vul_analysis" / ".cache" / "repos"

# File extensions to scan
CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.c', '.cpp', '.h', '.hpp',
    '.php', '.rb', '.rs', '.cs', '.swift', '.kt', '.scala', '.sh', '.bash'
}

# ==============================================================================
# DSPy Signatures
# ==============================================================================

class QueryPlanner(dspy.Signature):
    """Generate search parameters for CVE code analysis."""
    cve_id = dspy.InputField(desc="CVE identifier")
    description = dspy.InputField(desc="CVE description")
    
    lexical_keywords = dspy.OutputField(desc="Function names, API calls to grep")
    semantic_query = dspy.OutputField(desc="Technical sentence for semantic search")
    likely_file_paths = dspy.OutputField(desc="Likely vulnerable file paths (e.g., auth/login.py, api/handler.go)")


class VulnerabilityVerdict(dspy.Signature):
    """Determine if vulnerable code exists and is reachable."""
    cve_description = dspy.InputField()
    code_context = dspy.InputField(desc="Code snippets with file paths")
    
    reasoning = dspy.OutputField(desc="Source -> Sink -> Sanitizer chain")
    label = dspy.OutputField(desc="VULNERABLE | SAFE | UNKNOWN")
    confidence: float = dspy.OutputField()

# ==============================================================================
# DSPy Module
# ==============================================================================

class CodeReachabilityAnalyzer(dspy.Module):
    """
    Phase 3: Chain of Verification module for code reachability.
    
    Implements the 'Analyst-in-the-Loop' pattern:
    1. Plan: Generate search queries from CVE description.
    2. Retrieve: Fetch relevant code using the provided retriever or from previous tools output (SourceCodeRetriever).
    3. Direct File Access: Read actual files from repo for detailed analysis.
    4. Context Expansion: 'Code Walker' to find callers/usages.
    5. Verdict: Analyze the code to determine reachability.
    """
    def __init__(self, retriever_func, repo_path: Optional[Path] = None, repo_ref: Optional[str] = None, repo_url: Optional[str] = None):
        """
        Args:
            retriever_func: Callable or dspy.Retrieve that takes a query string and returns code context.
                            Should return List[dspy.Prediction] with 'long_text', 'file_path', 'lines'.
            repo_path: Path to the cloned repository for direct file access.
            repo_ref: Git ref (tag/branch) to checkout before reading files.
            repo_url: Git repository URL for cloning if repo doesn't exist.
        """
        super().__init__()
        self.retrieve = retriever_func
        self.repo_path = Path(repo_path) if repo_path else None
        self.repo_ref = repo_ref
        self.repo_url = repo_url
        self.planner = dspy.ChainOfThought(QueryPlanner)
        self.judge = dspy.ChainOfThought(VulnerabilityVerdict)
        self._checkout_done = False
    
    @staticmethod
    def _sanitize_dir_name(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", value)

    def _extract_file_paths(self, code_hints: str) -> List[str]:
        """Extract file paths from code_hints string."""
        if not code_hints:
            return []
        # Pattern: matches paths like src/main.py, lib/utils/foo.java, etc.
        path_pattern = r'(?:^|[\s,\'"(])([a-zA-Z0-9_./\\-]+\.(py|js|ts|java|go|c|cpp|php|rb|rs))(?:[\s,\'")]|$|:|#)'
        matches = re.findall(path_pattern, code_hints)
        return [m[0] for m in matches if len(m[0]) > 3]

    def _resolve_paths_fuzzy(self, hints: List[str]) -> List[str]:
        """Match hint paths to actual files using fuzzy matching."""
        if not self.repo_path or not self.repo_path.exists():
            return hints
        
        # Get available files in repo
        available_files = []
        for f in self.repo_path.rglob('*'):
            if f.is_file() and f.suffix in CODE_EXTENSIONS:
                if not any(p in f.parts for p in ['.git', 'node_modules', '__pycache__']):
                    available_files.append(str(f.relative_to(self.repo_path)))
        
        resolved = []
        for hint in hints:
            hint_clean = hint.strip().replace('\\', '/')
            # Exact match
            if hint_clean in available_files:
                resolved.append(hint_clean)
            else:
                # Fuzzy match on basename
                hint_basename = Path(hint_clean).name
                basenames = [Path(f).name for f in available_files]
                matches = get_close_matches(hint_basename, basenames, n=1, cutoff=0.6)
                if matches:
                    for f in available_files:
                        if Path(f).name == matches[0]:
                            resolved.append(f)
                            break
        return resolved[:5]

    # Common sink patterns that indicate vulnerability
    SINK_PATTERNS = {
        'exec', 'eval', 'system', 'popen', 'subprocess', 'ProcessBuilder',
        'Runtime.getRuntime', 'shell_exec', 'os.system', 'cmd.exe',
        'deserialize', 'pickle.loads', 'yaml.load', 'unserialize'
    }

    def _deduplicate_passages(self, passages: List) -> List:
        """Remove duplicate passages by file path, keeping highest scoring."""
        seen_files = {}
        for p in passages:
            file_path = getattr(p, 'file_path', 'unknown')
            if file_path not in seen_files:
                seen_files[file_path] = p
            else:
                # Keep the one with more content
                existing_len = len(getattr(seen_files[file_path], 'long_text', ''))
                new_len = len(getattr(p, 'long_text', ''))
                if new_len > existing_len:
                    seen_files[file_path] = p
        
        deduped = list(seen_files.values())
        if len(deduped) < len(passages):
            logger.info(f"Deduplicated {len(passages)} -> {len(deduped)} passages")
        return deduped

    def _prioritize_snippets(self, passages: List, plan) -> List:
        """Score and sort snippets by relevance to vulnerability. Keep top 5."""
        # First deduplicate by file path
        passages = self._deduplicate_passages(passages)
        
        if len(passages) <= 5:
            return passages
        
        # Extract keywords from plan
        keywords = []
        if hasattr(plan, 'lexical_keywords'):
            kw_str = str(plan.lexical_keywords).lower()
            keywords = [k.strip().strip("'\"[]") for k in kw_str.split(',')]
        
        scored = []
        for p in passages:
            text = getattr(p, 'long_text', '').lower()
            score = 0
            
            # Score by keyword matches
            for kw in keywords:
                if kw and len(kw) > 2 and kw in text:
                    score += 2
            
            # Bonus for sink patterns (never cut these)
            for sink in self.SINK_PATTERNS:
                if sink.lower() in text:
                    score += 10  # High priority
            
            scored.append((score, p))
        
        # Sort by score descending, take top 5
        scored.sort(key=lambda x: -x[0])
        selected = [p for _, p in scored[:3]]
        
        if len(passages) > 3:
            logger.info(f"Prioritized {len(selected)} of {len(passages)} snippets")
            logger.info(f"=================Selected snippets===========\n{selected}\n==========")
        
        return selected

    def _ensure_correct_ref(self):
        """Ensure repo exists at the correct ref. Clone if missing.
        
        Each repo+ref combination gets its own shallow clone directory (e.g., django_v3.2.4).
        If the repo doesn't exist and we have repo_url, clone it.
        """
        if self._checkout_done:
            return
        
        # If no repo_path set but we have url and ref, compute the expected path
        if not self.repo_path and self.repo_url and self.repo_ref:
            ref_clean = unquote(self.repo_ref)
            repo_name = self.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            dir_name = f"{self._sanitize_dir_name(repo_name)}_{self._sanitize_dir_name(ref_clean)}"
            self.repo_path = REPOS_DIR / dir_name
        
        if not self.repo_path:
            return
        
        # If repo exists and has .git, we're done
        if self.repo_path.exists() and (self.repo_path / ".git").exists():
            self._checkout_done = True
            logger.info(f"Using existing repo at {self.repo_path}")
            return
        
        # Clone if we have the URL and ref
        if self.repo_url and self.repo_ref:
            ref_clean = unquote(self.repo_ref)
            REPOS_DIR.mkdir(parents=True, exist_ok=True)
            logger.info(f"Cloning {self.repo_url}@{ref_clean} -> {self.repo_path}")
            
            try:
                # Try direct shallow clone at the tag
                subprocess.check_call([
                    "git", "clone", "--depth", "1", "--branch", ref_clean,
                    self.repo_url, str(self.repo_path)
                ])
                self._checkout_done = True
                logger.info(f"Cloned successfully to {self.repo_path}")
                return
            except subprocess.CalledProcessError:
                # Fallback: clone without checkout, then fetch+checkout
                logger.info(f"Direct branch clone failed, trying fetch approach")
                try:
                    subprocess.check_call([
                        "git", "clone", "--filter=blob:none", "--no-checkout",
                        self.repo_url, str(self.repo_path)
                    ])
                    subprocess.check_call([
                        "git", "-C", str(self.repo_path), "fetch", "--depth", "1", "origin", ref_clean
                    ])
                    subprocess.check_call([
                        "git", "-C", str(self.repo_path), "checkout", "--detach", "FETCH_HEAD"
                    ])
                    self._checkout_done = True
                    logger.info(f"Cloned via fetch to {self.repo_path}")
                    return
                except subprocess.CalledProcessError as e:
                    logger.error(f"Clone failed for {self.repo_url}@{ref_clean}: {e}")
                    return
        
        logger.warning(f"Repo path does not exist and cannot clone: {self.repo_path}")

    def _grep_files(self, pattern: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """Search files in repo for pattern using regex."""
        # Ensure repo is cloned first (this may set self.repo_path if not set)
        self._ensure_correct_ref()
        
        if not self.repo_path or not self.repo_path.exists():
            return []
        
        results = []
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            # Fallback to literal search if pattern is invalid regex
            regex = re.compile(re.escape(pattern), re.IGNORECASE)
        
        for file_path in self.repo_path.rglob('*'):
            if len(results) >= max_results:
                break
            if not file_path.is_file() or file_path.suffix not in CODE_EXTENSIONS:
                continue
            # Skip common non-code directories
            if any(p in file_path.parts for p in ['.git', 'node_modules', 'vendor', '__pycache__', 'dist', 'build']):
                continue
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                matches = list(regex.finditer(content))
                if matches:
                    # Get context around first match
                    lines = content.split('\n')
                    for m in matches[:2]:  # Max 2 matches per file
                        line_num = content[:m.start()].count('\n') + 1
                        start_line = max(0, line_num - 5)
                        end_line = min(len(lines), line_num + 15)
                        snippet = '\n'.join(lines[start_line:end_line])
                        rel_path = file_path.relative_to(self.repo_path)
                        results.append({
                            'file_path': str(rel_path),
                            'lines': f"{start_line+1}-{end_line}",
                            'code_snippet': snippet,
                            'match': m.group(0)
                        })
            except Exception as e:
                logger.debug(f"Failed to read {file_path}: {e}")
        return results

    def _read_file_context(self, file_path: str, around_line: int = None, context_lines: int = 50) -> str:
        """Read file content from repo, optionally around a specific line."""
        # Ensure repo is cloned first (this may set self.repo_path if not set)
        self._ensure_correct_ref()
        
        if not self.repo_path or not self.repo_path.exists():
            return ""
        
        full_path = self.repo_path / file_path
        # If path is a directory, search for first code file inside
        if full_path.exists() and full_path.is_dir():
            code_files = []
            for ext in CODE_EXTENSIONS:
                code_files.extend(full_path.rglob(f"*{ext}"))
            if code_files:
                full_path = code_files[0]
            else:
                return ""
        elif not full_path.exists() or not full_path.is_file():
            # Try to find file by name
            matches = list(self.repo_path.rglob(Path(file_path).name))
            if matches:
                full_path = matches[0]
            else:
                return ""
        
        try:
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            if around_line:
                lines = content.split('\n')
                start = max(0, around_line - context_lines)
                end = min(len(lines), around_line + context_lines)
                return '\n'.join(lines[start:end])
            # Return first 200 lines if no specific line
            return '\n'.join(content.split('\n')[:200])
        except Exception as e:
            logger.warning(f"Failed to read {full_path}: {e}")
            return ""

    def forward(self, cve_id: str, description: str, code_hints: str = ""):
        """
        Args:
            cve_id: CVE identifier
            description: CVE description from NVD/web search (agent provides from prior tool calls)
            code_hints: Optional file paths, function names, or code snippets to guide search
        """
        # 1. Plan - include code_hints in description for better query planning
        enriched_desc = description
        if code_hints:
            enriched_desc = f"{description}\n\nRelevant code context/hints:\n{code_hints}"
        
        plan = self.planner(cve_id=cve_id, description=enriched_desc)
        
        # 2. Retrieve - use both semantic query and code_hints for targeted search
        logger.info(f"Searching for: {plan.semantic_query}")
        passages = []
        
        # First search with planned query (only if retriever is available)
        # Use retrieve_related_code if available (returns dicts with metadata), else fallback to __call__
        if self.retrieve is not None:
            try:
                if hasattr(self.retrieve, 'retrieve_related_code'):
                    raw_results = self.retrieve.retrieve_related_code(plan.semantic_query, k=3, min_relevance=0.0)
                    # Convert dict results to Prediction-like objects
                    passages = [dspy.Prediction(
                        long_text=r.get('code_snippet', ''),
                        file_path=r.get('file_path', 'unknown'),
                        lines=r.get('lines', 'unknown')
                    ) for r in raw_results]
                else:
                    passages = self.retrieve(plan.semantic_query, k=3)
            except Exception as e:
                logger.error(f"Retrieval failed: {e}")
        
        # Additional targeted search if code_hints provided (e.g., file paths, function names)
        if code_hints and self.retrieve is not None:
            try:
                if hasattr(self.retrieve, 'retrieve_related_code'):
                    hint_results = self.retrieve.retrieve_related_code(code_hints[:500], k=3, min_relevance=0.0)
                    hint_passages = [dspy.Prediction(
                        long_text=r.get('code_snippet', ''),
                        file_path=r.get('file_path', 'unknown'),
                        lines=r.get('lines', 'unknown')
                    ) for r in hint_results]
                else:
                    hint_passages = self.retrieve(code_hints[:500], k=3)
                if isinstance(hint_passages, list):
                    passages = (passages or []) + hint_passages
            except Exception as e:
                logger.warning(f"Hint-based retrieval failed: {e}")

        # Handle if passages is not a list of Predictions (e.g. if using basic retriever)
        # But we assume it is compatible with the "Code Walker" logic below which expects objects.
        # If it returns a string, we might need to wrap it.
        if isinstance(passages, str):
             # Fallback for string return
             passages = [dspy.Prediction(long_text=passages, file_path="unknown", lines="unknown")]
        elif isinstance(passages, list) and len(passages) > 0 and isinstance(passages[0], str):
             passages = [dspy.Prediction(long_text=p, file_path="unknown", lines="unknown") for p in passages]

        # 2b. Direct file grep using lexical_keywords from plan
        # First ensure repo is cloned if needed (this also computes repo_path if not set)
        self._ensure_correct_ref()
        
        if self.repo_path and hasattr(plan, 'lexical_keywords'):
            keywords = str(plan.lexical_keywords).replace('[', '').replace(']', '').replace("'", "").split(',')
            for kw in keywords[:5]:  # Limit to 5 keywords
                kw = kw.strip()
                if len(kw) > 2:
                    grep_results = self._grep_files(kw, max_results=3)
                    for gr in grep_results:
                        # Read more context from the file
                        file_content = self._read_file_context(gr['file_path'], context_lines=30)
                        if file_content:
                            passages.append(dspy.Prediction(
                                long_text=file_content,
                                file_path=gr['file_path'],
                                lines=gr['lines']
                            ))
                        else:
                            passages.append(dspy.Prediction(
                            long_text=gr['code_snippet'],
                            file_path=gr['file_path'],
                            lines=gr['lines']
                        ))

        # 2c. Direct file read for paths mentioned in code_hints (with fuzzy matching)
        if code_hints:
            hint_paths = self._extract_file_paths(code_hints)
            resolved_paths = self._resolve_paths_fuzzy(hint_paths)
            for path in resolved_paths:
                file_content = self._read_file_context(path, context_lines=50)
                if file_content:
                    passages.append(dspy.Prediction(
                        long_text=file_content,
                        file_path=path,
                        lines="context"
                    ))
        
        # 2d. Also read likely_file_paths from plan (with fuzzy matching)
        if hasattr(plan, 'likely_file_paths') and plan.likely_file_paths:
            plan_paths = self._extract_file_paths(str(plan.likely_file_paths))
            resolved_plan_paths = self._resolve_paths_fuzzy(plan_paths)
            for path in resolved_plan_paths:
                file_content = self._read_file_context(path, context_lines=50)
                if file_content:
                    passages.append(dspy.Prediction(
                        long_text=file_content,
                        file_path=path,
                        lines="context"
                    ))

        # 3. Prioritize snippets by relevance (reduces token usage)
        prioritized = self._prioritize_snippets(passages, plan)
        
        # 4. Context Expansion - format passages for verdict
        expanded_context = []
        for p in prioritized:
            p_text = getattr(p, 'long_text', str(p))
            p_file = getattr(p, 'file_path', 'unknown')
            p_lines = getattr(p, 'lines', 'unknown')
            
            header = f"File: {p_file} | Lines: {p_lines}"
            expanded_context.append(f"[{header}]\n{p_text}")

        context_str = "\n\n".join(expanded_context)
        
        # Cap total context length (reduced for token efficiency)
        MAX_CONTEXT_CHARS = 6000
        if len(context_str) > MAX_CONTEXT_CHARS:
            context_str = context_str[:MAX_CONTEXT_CHARS] + "\n\n[...truncated]"
        
        if not context_str.strip():
             return dspy.Prediction(
                plan=plan,
                context="No code found.",
                verdict=dspy.Prediction(label="UNKNOWN", confidence=0.0, reasoning="No relevant code found in index."),
                summary="Verdict: UNKNOWN (No Code Found)\nReasoning: The retriever did not return any matching code snippets."
            )

        # 4. Verdict
        verdict = self.judge(cve_description=description, code_context=context_str)
        
        summary = f"Verdict: {verdict.label} (Conf: {verdict.confidence})\nReasoning: {verdict.reasoning}"

        return dspy.Prediction(
            plan=plan,
            context=expanded_context,
            verdict=verdict,
            summary=summary
        )

    def as_tool(self):
        """Returns a dspy.Tool wrapper for use in ReAct agents."""
        def _check_reachability(cve_id: str, description: str, code_hints: Union[str, List[str]] = "") -> str:
            """Analyze if CVE vulnerability is reachable in source code.
            
            Args:
                cve_id: CVE identifier (e.g., CVE-2024-1234)
                description: CVE description from NVD or web search explaining the vulnerability
                code_hints: Optional - file paths, function names, or code snippets from prior tool calls to guide search
            
            Returns:
                Verdict summary with label (VULNERABLE/SAFE/UNKNOWN), confidence, and reasoning chain
            """
            # Handle list input by converting to comma-separated string
            if isinstance(code_hints, list):
                code_hints = ", ".join(str(h) for h in code_hints)
            return self(cve_id, description, code_hints).summary
        
        return dspy.Tool(
            func=_check_reachability,
            name="check_code_reachability",
            desc="Performs Chain-of-Thought code analysis to verify if a CVE is reachable in the source repository. Call after getting CVE description from NVD/web search. Args: cve_id (str), description (str), code_hints (str or list, optional - pass file paths or function names from SourceCodeRetriever or other tools to guide search)."
        )
