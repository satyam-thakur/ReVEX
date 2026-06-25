"""
Hybrid Vector Database Creator (Raw Python Implementation)
========================================================

Creates a dual-index retrieval system WITHOUT LangChain dependencies:
1. Semantic Index (Raw FAISS with HNSW)
2. Lexical Index (Raw rank_bm25)

Implements Reciprocal Rank Fusion (RRF) for hybrid retrieval.

Architecture:
------------
.cache/vdb/0x7a3f.../
├── vector_store/
│   ├── index.faiss        # HNSW Graph (FAISS binary)
│   └── docstore.json      # Metadata (List of Document dicts)
├── lexical_store/
│   ├── bm25_index.pkl     # BM25 Index object
│   └── corpus.pkl         # Tokenized corpus
└── metadata.json          # Cache signature & config
"""

import os
import json
import hashlib
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from functools import lru_cache
import logging
import numpy as np

# Raw library imports
import faiss
from rank_bm25 import BM25Okapi
from tqdm import tqdm

from .code_tokenizer import CodeTokenizer
from .embedding_wrapper import EmbeddingModelWrapper
from .types import Document

logger = logging.getLogger(__name__)


@dataclass
class VDBConfig:
    """Configuration for VDB creation"""
    # Source configuration
    repo_url: str
    repo_ref: str  # Git commit SHA
    
    # Model configuration
    embedding_model: str = 'all-MiniLM-L6-v2'
    
    # Parser configuration
    ast_parser_version: str = 'v1.0'  # Track chunking logic version
    
    # Index configuration
    use_hnsw: bool = True  # Use HNSW instead of Flat index
    hnsw_m: int = 16  # HNSW parameter (neighbors per node)
    hnsw_ef_construction: int = 200  # HNSW build-time search depth
    
    # Lexical index configuration
    use_bm25: bool = True
    bm25_k1: float = 1.5  # BM25 term frequency saturation
    bm25_b: float = 0.75  # BM25 length normalization
    
    # Cache configuration
    cache_dir: Path = Path('.cache/vdb')
    
    def get_cache_signature(self) -> str:
        """
        Generate unique cache signature.
        """
        components = [
            self.repo_url,
            self.repo_ref,
            self.embedding_model,
            self.ast_parser_version,
        ]
        content = '||'.join(components)
        hash_obj = hashlib.sha256(content.encode('utf-8'))
        return hash_obj.hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['cache_dir'] = str(d['cache_dir'])
        return d


class HybridVDBCreator:
    """
    Creates and manages hybrid vector + lexical search indices.
    """
    
    def __init__(self, config: VDBConfig):
        self.config = config
        self.cache_signature = config.get_cache_signature()
        self.cache_path = config.cache_dir / self.cache_signature
        
        # Initialize components
        self.embedding_model = None
        self.tokenizer = CodeTokenizer()
        
        logger.info(f"VDB Cache Signature: {self.cache_signature}")
        logger.info(f"VDB Cache Path: {self.cache_path}")
    
    def create_or_load_vdb(
        self,
        documents: List[Document],
        force_rebuild: bool = False,
    ) -> 'HybridVDB':
        """
        Create new VDB or load from cache.
        """
        # Check cache
        if not force_rebuild and self.cache_exists():
            logger.info("Loading VDB from cache...")
            return self._load_from_cache()
        
        # Build new VDB
        logger.info("Building new VDB...")
        return self._build_vdb(documents)
    
    def cache_exists(self) -> bool:
        """Check if valid cache exists"""
        if not self.cache_path.exists():
            return False
        
        metadata_file = self.cache_path / 'metadata.json'
        vector_index = self.cache_path / 'vector_store' / 'index.faiss'
        docstore = self.cache_path / 'vector_store' / 'docstore.json'
        lexical_index = self.cache_path / 'lexical_store' / 'bm25_index.pkl'
        
        return (
            metadata_file.exists() and
            vector_index.exists() and
            docstore.exists() and
            lexical_index.exists()
        )
    
    def _build_vdb(self, documents: List[Document]) -> 'HybridVDB':
        """
        Build vector and lexical indices from scratch.
        """
        logger.info(f"Building VDB for {len(documents)} documents")
        
        # Create directories
        vector_path = self.cache_path / 'vector_store'
        lexical_path = self.cache_path / 'lexical_store'
        vector_path.mkdir(parents=True, exist_ok=True)
        lexical_path.mkdir(parents=True, exist_ok=True)
        
        # Step 1: Build Vector Index (FAISS)
        logger.info("Step 1/3: Building FAISS vector index...")
        vector_index = self._build_vector_index(documents, vector_path)
        
        # Step 2: Build Lexical Index (BM25)
        logger.info("Step 2/3: Building BM25 lexical index...")
        bm25_index, tokenized_corpus = self._build_lexical_index(
            documents, lexical_path
        )
        
        # Step 3: Save metadata
        logger.info("Step 3/3: Saving metadata...")
        self._save_metadata(len(documents))
        
        logger.info("VDB creation complete!")
        
        return HybridVDB(
            vector_index=vector_index,
            bm25_index=bm25_index,
            tokenized_corpus=tokenized_corpus,
            documents=documents,
            tokenizer=self.tokenizer,
            embedding_model=self.embedding_model,
            config=self.config,
        )
    
    def _build_vector_index(
        self,
        documents: List[Document],
        save_path: Path,
    ) -> faiss.Index:
        """
        Build raw FAISS vector index.
        """
        # Initialize embedding model
        if self.embedding_model is None:
            self.embedding_model = EmbeddingModelWrapper(
                model_name=self.config.embedding_model,
                cache_dir=self.config.cache_dir / 'embeddings',
                batch_size=128,
                show_progress=True,
            )
        
        # Generate embeddings
        texts = [doc.page_content for doc in documents]
        logger.info(f"Generating embeddings for {len(texts)} documents...")
        
        if len(texts) == 0:
            logger.warning("No documents to index!")
            dim = 384  # Default for all-MiniLM-L6-v2
            index = faiss.IndexFlatL2(dim)
            faiss.write_index(index, str(save_path / 'index.faiss'))
            with open(save_path / 'docstore.json', 'w') as f:
                json.dump([], f)
            return index

        embeddings = self.embedding_model.embed_documents(texts, prefix="[CODE] ")
        
        # Convert to numpy float32 for FAISS
        embeddings_np = np.array(embeddings).astype('float32')
        dim = embeddings_np.shape[1]
        
        # Create FAISS index
        if self.config.use_hnsw:
            # HNSW index
            index = faiss.IndexHNSWFlat(dim, self.config.hnsw_m)
            index.hnsw.efConstruction = self.config.hnsw_ef_construction
            logger.info(f"Created HNSW index (dim={dim}, m={self.config.hnsw_m})")
        else:
            # Flat index (L2 distance)
            index = faiss.IndexFlatL2(dim)
            logger.info(f"Created Flat L2 index (dim={dim})")
        
        # Train (if needed) and Add
        # HNSWFlat and FlatL2 don't require training for float vectors
        index.add(embeddings_np)
        
        # Save index to disk
        faiss.write_index(index, str(save_path / 'index.faiss'))
        
        # Save docstore (mapping ID -> Document)
        # FAISS IDs are 0..N-1, matching the list index
        docstore = [doc.to_dict() for doc in documents]
        with open(save_path / 'docstore.json', 'w') as f:
            json.dump(docstore, f, indent=2)
            
        logger.info(f"FAISS index saved to {save_path}")
        return index
    
    def _build_lexical_index(
        self,
        documents: List[Document],
        save_path: Path,
    ) -> Tuple[BM25Okapi, List[List[str]]]:
        """
        Build BM25 lexical index.
        """
        logger.info("Tokenizing corpus for BM25...")
        
        # Handle empty documents case to prevent ZeroDivisionError in BM25
        if len(documents) == 0:
            logger.warning("No documents to index for BM25!")
            # Create minimal BM25 with a single empty token list to avoid division by zero
            tokenized_corpus = [[]]
            bm25_index = BM25Okapi(
                tokenized_corpus,
                k1=self.config.bm25_k1,
                b=self.config.bm25_b,
            )
            # Save empty indices
            with open(save_path / 'bm25_index.pkl', 'wb') as f:
                pickle.dump(bm25_index, f)
            with open(save_path / 'corpus.pkl', 'wb') as f:
                pickle.dump([], f)  # Save actual empty corpus
            return bm25_index, []
        
        # Tokenize all documents
        tokenized_corpus = []
        for doc in tqdm(documents, desc="Tokenizing"):
            tokens = self.tokenizer.tokenize(doc.page_content)
            tokenized_corpus.append(tokens)
        
        # Build BM25 index
        logger.info("Building BM25 index...")
        bm25_index = BM25Okapi(
            tokenized_corpus,
            k1=self.config.bm25_k1,
            b=self.config.bm25_b,
        )
        
        # Save to disk
        with open(save_path / 'bm25_index.pkl', 'wb') as f:
            pickle.dump(bm25_index, f)
        
        with open(save_path / 'corpus.pkl', 'wb') as f:
            pickle.dump(tokenized_corpus, f)
        
        logger.info(f"BM25 index saved to {save_path}")
        
        return bm25_index, tokenized_corpus
    
    def _save_metadata(self, doc_count: int) -> None:
        """Save VDB metadata"""
        metadata = {
            'config': self.config.to_dict(),
            'cache_signature': self.cache_signature,
            'document_count': doc_count,
            'created_at': str(Path(__file__).stat().st_mtime),
        }
        
        metadata_file = self.cache_path / 'metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _load_from_cache(self) -> 'HybridVDB':
        """Load VDB from cache"""
        # Load metadata
        with open(self.cache_path / 'metadata.json', 'r') as f:
            metadata = json.load(f)
        
        logger.info(f"Loading VDB with {metadata['document_count']} documents")
        
        # Initialize embedding model
        if self.embedding_model is None:
            self.embedding_model = EmbeddingModelWrapper(
                model_name=self.config.embedding_model,
                cache_dir=self.config.cache_dir / 'embeddings',
            )
        
        # Load FAISS index
        vector_path = self.cache_path / 'vector_store'
        vector_index = faiss.read_index(str(vector_path / 'index.faiss'))
        
        # Load Docstore
        with open(vector_path / 'docstore.json', 'r') as f:
            doc_dicts = json.load(f)
            documents = [Document.from_dict(d) for d in doc_dicts]
        
        # Load BM25 index
        lexical_path = self.cache_path / 'lexical_store'
        with open(lexical_path / 'bm25_index.pkl', 'rb') as f:
            bm25_index = pickle.load(f)
        
        with open(lexical_path / 'corpus.pkl', 'rb') as f:
            tokenized_corpus = pickle.load(f)
        
        return HybridVDB(
            vector_index=vector_index,
            bm25_index=bm25_index,
            tokenized_corpus=tokenized_corpus,
            documents=documents,
            tokenizer=self.tokenizer,
            embedding_model=self.embedding_model,
            config=self.config,
        )


class HybridVDB:
    """
    Hybrid retrieval system combining vector and lexical search.
    """
    
    def __init__(
        self,
        vector_index: faiss.Index,
        bm25_index: BM25Okapi,
        tokenized_corpus: List[List[str]],
        documents: List[Document],
        tokenizer: CodeTokenizer,
        embedding_model: EmbeddingModelWrapper,
        config: VDBConfig,
    ):
        self.vector_index = vector_index
        self.bm25_index = bm25_index
        self.tokenized_corpus = tokenized_corpus
        self.documents = documents
        self.tokenizer = tokenizer
        self.embedding_model = embedding_model
        self.config = config

        # self._embed_query_cached = lru_cache(maxsize=1024)(self._embed_query_raw)
        self._embed_query_cached = self._embed_query_raw
    
    def hybrid_search(
        self,
        query: str,
        k: int = 10,
        rrf_k: int = 45,
    ) -> List[Tuple[Document, float]]:
        """
        Perform hybrid search with RRF.
        """
        # Get results from both indices
        # Fetch more candidates (2*k) for fusion
        vector_results = self._vector_search(query, k=k*2)
        lexical_results = self._lexical_search(query, k=k*2)
        
        # Apply RRF
        rrf_scores = self._reciprocal_rank_fusion(
            vector_results,
            lexical_results,
            k=rrf_k,
        )
        
        # Sort and return top-k
        ranked_results = sorted(
            rrf_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:k]
        
        return [(self.documents[doc_id], score) for doc_id, score in ranked_results]
    
    def _vector_search(self, query: str, k: int) -> Dict[int, int]:
        """
        Vector search using raw FAISS.
        Returns: Dict mapping doc_id -> rank (1-indexed)
        """
        # Embed query with caching
        query_emb_np = np.array([self._embed_query_cached(query)]).astype('float32')
        
        # Search
        distances, indices = self.vector_index.search(query_emb_np, k)
        
        # Map to doc IDs and ranks
        doc_ranks = {}
        # indices[0] contains the IDs of the nearest neighbors
        for rank, doc_id in enumerate(indices[0], start=1):
            if doc_id != -1:  # FAISS returns -1 if not enough neighbors
                doc_ranks[int(doc_id)] = rank
        
        return doc_ranks

    def _embed_query_raw(self, query: str) -> np.ndarray:
        """Compute raw query embedding (cached by wrapper)."""
        return np.array(
            self.embedding_model.embed_query(query, prefix="[QUERY] "),
            dtype='float32',
        )
    
    def _lexical_search(self, query: str, k: int) -> Dict[int, int]:
        """
        Lexical search using BM25.
        Returns: Dict mapping doc_id -> rank (1-indexed)
        """
        # Tokenize query
        query_tokens = self.tokenizer.tokenize(query)
        
        # Get BM25 scores
        scores = self.bm25_index.get_scores(query_tokens)
        
        # Get top-k indices
        top_indices = sorted(
            range(len(scores)),
            key=lambda i: scores[i],
            reverse=True,
        )[:k]
        
        # Map to ranks
        doc_ranks = {}
        for rank, doc_id in enumerate(top_indices, start=1):
            doc_ranks[doc_id] = rank
        
        return doc_ranks
    
    def _reciprocal_rank_fusion(
        self,
        vector_ranks: Dict[int, int],
        lexical_ranks: Dict[int, int],
        k: int = 60,
    ) -> Dict[int, float]:
        """
        Combine rankings using Reciprocal Rank Fusion.
        Formula: RRF_score(d) = Σ(1 / (k + rank(d)))
        """
        rrf_scores = {}
        
        # Combine all doc IDs
        all_doc_ids = set(vector_ranks.keys()) | set(lexical_ranks.keys())
        
        for doc_id in all_doc_ids:
            score = 0.0
            
            # Add vector contribution
            if doc_id in vector_ranks:
                score += 1.0 / (k + vector_ranks[doc_id])
            
            # Add lexical contribution
            if doc_id in lexical_ranks:
                score += 1.0 / (k + lexical_ranks[doc_id])
            
            rrf_scores[doc_id] = score
        
        return rrf_scores
    
    def get_stats(self) -> Dict[str, Any]:
        """Get VDB statistics"""
        return {
            'document_count': len(self.documents),
            'embedding_model': self.config.embedding_model,
            'index_type': 'HNSW' if self.config.use_hnsw else 'Flat',
            'cache_signature': self.config.get_cache_signature(),
            'vector_dim': self.vector_index.d,
        }


if __name__ == "__main__":
    print("Hybrid VDB Creator - Demo mode not available")
    print("Use demo_vdb_creation.py for testing")
