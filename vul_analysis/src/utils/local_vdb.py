"""
Phase 3: Query-Time Retrieval and Analysis using DSPy
=====================================================

This module implements the "Chain of Verification" pipeline using DSPy.
It wraps the Phase 2 Hybrid VDB and defines the DSPy signatures and modules
for vulnerability analysis.

Usage:
    python local_vdb.py --cve "CVE-2024-XXXX" --desc "Description..."
"""

import os
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
import dspy
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# Import Phase 2 components
# Assuming these are in the same utils package
from .hybrid_vdb_creator import HybridVDBCreator, VDBConfig, HybridVDB
from .types import Document

# Setup logging
logger = logging.getLogger(__name__)

# ==============================================================================
# 1. VDB Loading Logic
# ==============================================================================

def load_vdb(cache_base_dir: Path = Path('../../.cache/vdb_fabric')) -> HybridVDB:
    """
    Load the existing Hybrid VDB from cache by inspecting metadata.
    """
    # Resolve absolute path to avoid CWD issues
    # Path(__file__).parent is 'utils'
    # Path(__file__).parent.parent is 'fabric_src'
    if not cache_base_dir.is_absolute():
        cache_base_dir = (Path(__file__).parent.parent / cache_base_dir).resolve()

    if not cache_base_dir.exists():
        raise FileNotFoundError(f"Cache directory {cache_base_dir} not found.")

    # Find the cache subdirectory (hash)
    # We look for a directory that contains metadata.json
    cache_dir = None
    for item in cache_base_dir.iterdir():
        if item.is_dir() and item.name != 'embeddings':
            if (item / 'metadata.json').exists():
                cache_dir = item
                break
    
    if not cache_dir:
        raise FileNotFoundError(f"No valid VDB cache found in {cache_base_dir}")
    
    logger.info(f"Found VDB cache at {cache_dir}")
    
    # Load metadata to reconstruct config
    with open(cache_dir / 'metadata.json', 'r') as f:
        metadata = json.load(f)
    
    config_dict = metadata['config']
    
    # Reconstruct VDBConfig
    # We need to be careful with Path objects
    config = VDBConfig(
        repo_url=config_dict['repo_url'],
        repo_ref=config_dict['repo_ref'],
        embedding_model=config_dict['embedding_model'],
        ast_parser_version=config_dict['ast_parser_version'],
        use_hnsw=config_dict['use_hnsw'],
        hnsw_m=config_dict.get('hnsw_m', 16),
        hnsw_ef_construction=config_dict.get('hnsw_ef_construction', 200),
        use_bm25=config_dict.get('use_bm25', True),
        bm25_k1=config_dict.get('bm25_k1', 1.5),
        bm25_b=config_dict.get('bm25_b', 0.75),
        cache_dir=cache_base_dir, # Point to the base dir, the creator appends hash
    )
    
    # Verify the hash matches (optional, but good for sanity)
    if config.get_cache_signature() != cache_dir.name:
        logger.warning(
            f"Config signature {config.get_cache_signature()} does not match "
            f"directory name {cache_dir.name}. Loading might fail or create new cache."
        )
    
    creator = HybridVDBCreator(config)
    # We pass empty documents list because we expect to load from cache
    return creator.create_or_load_vdb([], force_rebuild=False)


# ==============================================================================
# 2. Helper Functions for Code Retrieval
# ==============================================================================

def get_similar_code(vdb_engine: HybridVDB, query: str, k: int = 5, rrf_k: int = 60) -> List[Dict[str, Any]]:
    """
    Retrieve similar code snippets from the VDB.
    
    Args:
        vdb_engine: HybridVDB instance
        query: Search query
        k: Number of results to return
        rrf_k: RRF parameter for hybrid search
        
    Returns:
        List of dictionaries with code and metadata
    """
    logger.info(f"Retrieving similar code for: {query}")
    
    # Execute hybrid search
    results = vdb_engine.hybrid_search(query, k=k, rrf_k=rrf_k)
    
    # Format results
    similar_code = []
    for doc, score in results:
        similar_code.append({
            'code': doc.page_content,
            'file_path': doc.metadata.get('file_path', 'unknown'),
            'lines': doc.metadata.get('lines', 'unknown'),
            'score': score,
            'function_name': doc.metadata.get('function_name'),
            'class_name': doc.metadata.get('class_name'),
            'language': doc.metadata.get('language'),
            'context_before': doc.metadata.get('context_before'),
            'context_after': doc.metadata.get('context_after')
        })
    
    logger.info(f"Retrieved {len(similar_code)} similar code snippets")
    logger.info(similar_code)
    return similar_code


# ==============================================================================
# 3. DSPy Hybrid Retriever
# ==============================================================================

class DSPyHybridRetriever(dspy.Retrieve):
    """
    Wraps the Phase 2 SecurityHybridVDB for DSPy.
    Provides efficient hybrid search combining BM25 and semantic embeddings.
    Returns results in DSPy-compatible format.
    """
    def __init__(self, vdb_engine: HybridVDB, k: int = 5, rrf_k: int = 45):  # rrf_k=45 for better security keyword matching
        super().__init__(k=k)
        self.vdb = vdb_engine
        self.rrf_k = rrf_k
        logger.info(f"Initialized DSPyHybridRetriever with k={k}, rrf_k={rrf_k}")

    def forward(self, query_or_queries: Union[str, List[str]], k: Optional[int] = None) -> List[dspy.Prediction]:
        """
        Retrieve similar code and return DSPy-compatible predictions.
        
        Args:
            query_or_queries: Query string or list of queries
            k: Override default k parameter
            
        Returns:
            List of DSPy Predictions with code snippets and metadata
        """
        k = k if k is not None else self.k
        
        # Normalize query
        if isinstance(query_or_queries, list):
            query = " ".join(query_or_queries)
        else:
            query = str(query_or_queries)

        logger.info(f"Forward pass: query='{query}', k={k}")
        
        # Get similar code using helper function
        similar_code = get_similar_code(self.vdb, query, k=k, rrf_k=self.rrf_k)
        
        # Convert to DSPy Predictions
        predictions = []
        for code_result in similar_code:
            # Create DSPy-compatible Prediction
            pred = dspy.Prediction(
                long_text=code_result['code'],
                file_path=code_result['file_path'],
                lines=code_result['lines'],
                score=code_result['score'],
                function_name=code_result['function_name'],
                class_name=code_result['class_name'],
                language=code_result['language'],
                context_before=code_result['context_before'],
                context_after=code_result['context_after']
            )
            predictions.append(pred)
        
        logger.info(f"Retrieved {len(predictions)} DSPy predictions")
        logger.info(predictions)
        return predictions
