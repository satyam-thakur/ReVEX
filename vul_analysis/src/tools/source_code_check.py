from typing import Optional, List, Any, Dict
import logging
import re
from ..utils.local_vdb import DSPyHybridRetriever
from ..utils import HybridVDB, load_vdb

# Setup logging
logger = logging.getLogger(__name__)

# Constants
DEFAULT_MIN_RELEVANCE = 0.015

# ==============================================================================
# 1. Source Code Retriver Tool
# ==============================================================================

class SourceCodeRetriever:
    """
    Tool for retrieving and analyzing relatable vulnerable code from the source repository.
    Uses the DSPyHybridRetriever to find semantically similar and keyword-matching code.
    """
    def __init__(self, vdb_engine: Optional[HybridVDB] = None):
        """
        Initialize the SourceCodeCheckTool.
        
        Args:
            vdb_engine: Optional pre-initialized HybridVDB. If None, loads from cache.
        """
        if vdb_engine is None:
            logger.info("Loading VDB from cache...")
            self.vdb = load_vdb()
        else:
            self.vdb = vdb_engine
        
        self.retriever = DSPyHybridRetriever(self.vdb, k=5)  # Fetch 5 candidates
        logger.info("SourceCodeCheckTool initialized successfully")

    def __call__(self, query: str = None, k: int = 3, code_query: str = None, search_query: str = None, **kwargs) -> str:
        """
        Retrieve code snippets related to a given query.
        
        Args:
            query: Search query (vulnerability description, code pattern, etc.)
            k: Number of results to return
            code_query: Alias for query (LLM sometimes uses this)
            search_query: Alias for query (LLM sometimes uses this)
            
        Returns:
            Formatted markdown string of relatable code snippets
        """
        # Accept common LLM argument name variations
        actual_query = query or code_query or search_query or kwargs.get('q') or kwargs.get('search')
        if not actual_query:
            return "# Related Code Snippets\n\nError: Missing query argument. Use query='function_name security_keyword' format."
        
        results = self.retrieve_related_code(actual_query, k=k, min_relevance=DEFAULT_MIN_RELEVANCE)
        output = self.format_results_as_markdown(results)
        
        # Log compact summary of top 3 results sent to LLM
        result_summary = [f"{r['file_path']} (score: {r['relevance_score']:.4f})" for r in results[:3]]
        logger.info(f"\n{'='*40} [TOOL OUTPUT: SourceCodeRetriever] {'='*40}\nTop {len(results)} snippets: {result_summary}\n{'='*95}")
        
        return output

    def retrieve_related_code(self, query: str, k: int = 3, min_relevance: float = 0.015) -> List[Dict[str, Any]]:
        """
        Retrieve code snippets related to a given query.
        
        Args:
            query: Search query (vulnerability description, code pattern, etc.)
            k: Number of results to return
            min_relevance: Minimum relevance score threshold (0.0-1.0). Results below this are filtered out.
            
        Returns:
            List of dictionaries containing relatable code snippets and metadata
        """
        query = (query or "").strip()
        if len(query) < 2:
            # Too-short queries tend to return noise from the hybrid retriever.
            logger.warning("Query too short for retrieval")
            return []

        # Preprocess: Strip CVE-XXXX patterns for better semantic matching
        clean_query = re.sub(r'CVE-\d{4}-\d+', '', query, flags=re.IGNORECASE).strip()
        if clean_query:
            query = clean_query
            logger.info(f"Query preprocessed (CVE stripped): {query}")

        logger.info(f"Retrieving related code for: {query}")

        try:
            predictions = self.retriever.forward(query, k=k)
        except Exception as e:
            logger.error(f"Error retrieving related code for query '{query}': {str(e)}", exc_info=True)
            return []

        if not isinstance(predictions, list):
            predictions = [predictions]

        results: List[Dict[str, Any]] = []
        for pred in predictions:
            code_snippet = getattr(pred, 'long_text', '')
            if not code_snippet.strip():
                continue

            relevance_score = float(getattr(pred, 'score', 0.0))
            if relevance_score < min_relevance:
                continue

            results.append({
                'code_snippet': code_snippet,
                'file_path': getattr(pred, 'file_path', 'unknown'),
                'lines': getattr(pred, 'lines', 'unknown'),
                'relevance_score': relevance_score,
                # Optional metadata (may not exist on all prediction objects)
                'function_name': getattr(pred, 'function_name', None),
                'class_name': getattr(pred, 'class_name', None),
                'language': getattr(pred, 'language', None),
                'context_before': getattr(pred, 'context_before', None),
                'context_after': getattr(pred, 'context_after', None),
            })

        # Sort by relevance score and return top 3
        results.sort(key=lambda x: x['relevance_score'], reverse=True)
        top_results = results[:3]
        
        if len(results) > 3:
            logger.info(f"Selected top 3 of {len(results)} snippets by relevance")
        
        return top_results


    def format_results_as_markdown(self, results: List[Dict[str, Any]]) -> str:
        """
        Format retrieval results as markdown for better readability.
        
        Args:
            results: Results from retrieve_related_code or similar methods
            
        Returns:
            Formatted markdown string
        """
        if not results:
            return "# Related Code Snippets\n\nNo relevant code snippets found for the query."
        
        markdown = "# Related Code Snippets\n\n"
        
        for i, result in enumerate(results, 1):
            markdown += f"## Result {i}\n"
            markdown += f"**File:** `{result['file_path']}`\n"
            markdown += f"**Lines:** {result['lines']}\n"
            markdown += f"**Relevance Score:** {result['relevance_score']:.4f}\n"
            
            if result.get('function_name'):
                markdown += f"**Function:** `{result['function_name']}`\n"
            if result.get('class_name'):
                markdown += f"**Class:** `{result['class_name']}`\n"
            if result.get('language'):
                markdown += f"**Language:** {result['language']}\n"
            
            markdown += "\n### Code Snippet\n"
            markdown += "```\n"
            markdown += result['code_snippet']
            markdown += "\n```\n\n"
        
        return markdown
