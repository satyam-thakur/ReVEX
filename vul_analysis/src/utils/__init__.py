"""
Utility modules for source code preprocessing and analysis.
"""

from .const import DATASET_SPLITS, TOKEN_COSTS, TOOLS_CONFIG

try:
    from .ast_chunker import CoalescingASTSplitter, CodeChunk
    from .source_code_loader import SourceCodeLoader
    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False
    CoalescingASTSplitter = None
    CodeChunk = None
    SourceCodeLoader = None
from .local_vdb import load_vdb
from .hybrid_vdb_creator import HybridVDB, VDBConfig, HybridVDBCreator

__all__ = [
    'CoalescingASTSplitter',
    'CodeChunk',
    'SourceCodeLoader',
    'AST_AVAILABLE',
    'load_vdb',
    'HybridVDB',
    'VDBConfig',
    'HybridVDBCreator',
    'DATASET_SPLITS',
    'TOKEN_COSTS',
    'TOOLS_CONFIG',
]
