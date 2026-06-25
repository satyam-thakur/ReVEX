"""
Embedding Model Wrapper
=======================

Provides a unified interface for embedding models with caching and batching.

Supports:
- sentence-transformers models (all-MiniLM-L6-v2, etc.)
- Task-specific prefixes for code embeddings

Citation:
---------
Karpukhin, V., et al. (2020). "Dense Passage Retrieval for Open-Domain Question Answering."
EMNLP 2020. (Dense retrieval for semantic search)
"""

import os
import hashlib
import pickle
from typing import List, Optional, Dict, Any
from pathlib import Path
import logging

from sentence_transformers import SentenceTransformer
from tqdm import tqdm

logger = logging.getLogger(__name__)


class EmbeddingModelWrapper:
    """
    Wrapper for embedding models with caching and optimizations.
    
    Features:
    - Automatic batching
    - Disk caching for expensive embeddings
    - Task-specific prefixes (e.g., "passage: " for code)
    - Progress tracking
    """
    
    # Default model configurations
    DEFAULT_MODEL = 'all-MiniLM-L6-v2'
    
    MODEL_CONFIGS = {
        'all-MiniLM-L6-v2': {
            'dimension': 384,
            'max_seq_length': 256,
            'best_for': 'general purpose, fast',
        },
        'all-mpnet-base-v2': {
            'dimension': 768,
            'max_seq_length': 384,
            'best_for': 'higher quality, slower',
        },
        'multi-qa-MiniLM-L6-cos-v1': {
            'dimension': 384,
            'max_seq_length': 512,
            'best_for': 'question answering',
        },
    }
    
    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        cache_dir: Optional[Path] = None,
        device: str = 'cpu',
        batch_size: int = 128,
        show_progress: bool = True,
    ):
        """
        Initialize embedding model.
        
        Args:
            model_name: Name of the sentence-transformers model
            cache_dir: Directory for caching embeddings
            device: 'cpu' or 'cuda'
            batch_size: Batch size for encoding
            show_progress: Show progress bar during encoding
        """
        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size
        self.show_progress = show_progress
        
        # Initialize cache
        self.cache_dir = cache_dir or Path('.cache/embeddings')
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load model
        logger.info(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name, device=device)
        
        # Get model config
        self.config = self.MODEL_CONFIGS.get(model_name, {
            'dimension': self.model.get_sentence_embedding_dimension(),
            'max_seq_length': self.model.max_seq_length,
        })
        
        logger.info(
            f"Model loaded: {model_name} "
            f"(dim={self.config['dimension']}, device={device})"
        )
    
    def embed_documents(
        self,
        texts: List[str],
        prefix: str = "[CODE] ",
        use_cache: bool = True,
    ) -> List[List[float]]:
        """
        Generate embeddings for a list of documents.
        
        Args:
            texts: List of text strings to embed
            prefix: Prefix to add to each text (task-specific)
            use_cache: Whether to use disk cache
            
        Returns:
            List of embedding vectors (each is a list of floats)
        """
        if not texts:
            return []
        
        # Add prefix to texts
        prefixed_texts = [f"{prefix}{text}" for text in texts]
        
        # Check cache
        if use_cache:
            cache_key = self._get_cache_key(prefixed_texts)
            cached_embeddings = self._load_from_cache(cache_key)
            if cached_embeddings is not None:
                logger.info(f"Loaded {len(cached_embeddings)} embeddings from cache")
                return cached_embeddings
        
        # Generate embeddings
        logger.info(f"Generating embeddings for {len(texts)} documents...")
        
        embeddings = self.model.encode(
            prefixed_texts,
            batch_size=self.batch_size,
            show_progress_bar=self.show_progress,
            convert_to_numpy=True,
        )
        
        # Convert to list of lists (for serialization)
        embeddings_list = embeddings.tolist()
        
        # Save to cache
        if use_cache:
            self._save_to_cache(cache_key, embeddings_list)
        
        return embeddings_list
    
    def embed_query(self, query: str, prefix: str = "[QUERY] ") -> List[float]:
        """
        Generate embedding for a single query.
        
        Args:
            query: Query string
            prefix: Query prefix (different from document prefix)
            
        Returns:
            Embedding vector as list of floats
        """
        prefixed_query = f"{prefix}{query}"
        embedding = self.model.encode(
            prefixed_query,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        return embedding.tolist()
    
    def _get_cache_key(self, texts: List[str]) -> str:
        """
        Generate a cache key for a list of texts.
        
        Uses hash of (model_name + concatenated_texts)
        """
        content = self.model_name + '||' + '||'.join(texts)
        hash_obj = hashlib.sha256(content.encode('utf-8'))
        return hash_obj.hexdigest()[:16]
    
    def _load_from_cache(self, cache_key: str) -> Optional[List[List[float]]]:
        """Load embeddings from cache if available"""
        cache_file = self.cache_dir / f"{cache_key}.pkl"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
                return None
        
        return None
    
    def _save_to_cache(self, cache_key: str, embeddings: List[List[float]]) -> None:
        """Save embeddings to cache"""
        cache_file = self.cache_dir / f"{cache_key}.pkl"
        
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(embeddings, f)
            logger.debug(f"Saved embeddings to cache: {cache_file}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def get_embedding_dimension(self) -> int:
        """Get the dimensionality of embeddings"""
        return self.config['dimension']
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        return {
            'model_name': self.model_name,
            'dimension': self.config['dimension'],
            'max_seq_length': self.config.get('max_seq_length'),
            'device': self.device,
            'batch_size': self.batch_size,
        }


def create_embedding_model(
    model_name: str = EmbeddingModelWrapper.DEFAULT_MODEL,
    cache_dir: Optional[Path] = None,
    device: str = 'cpu',
    **kwargs
) -> EmbeddingModelWrapper:
    """
    Factory function to create an embedding model.
    
    Args:
        model_name: Model name
        cache_dir: Cache directory
        device: Device ('cpu' or 'cuda')
        **kwargs: Additional arguments for EmbeddingModelWrapper
        
    Returns:
        Initialized embedding model
    """
    return EmbeddingModelWrapper(
        model_name=model_name,
        cache_dir=cache_dir,
        device=device,
        **kwargs
    )


if __name__ == "__main__":
    # Demo
    print("Embedding Model Demo")
    print("=" * 60)
    
    # Initialize model
    embedder = EmbeddingModelWrapper(
        model_name='all-MiniLM-L6-v2',
        batch_size=32,
    )
    
    # Test documents
    docs = [
        "def get_user_data(user_id): return database.query(user_id)",
        "class VulnerabilityScanner: pass",
        "exec(user_input)  # Dangerous code",
    ]
    
    # Generate embeddings
    print(f"\nEmbedding {len(docs)} documents...")
    embeddings = embedder.embed_documents(docs)
    
    print(f"Generated {len(embeddings)} embeddings")
    print(f"Embedding dimension: {len(embeddings[0])}")
    print(f"First embedding (first 5 dims): {embeddings[0][:5]}")
    
    # Test query
    query = "SQL injection vulnerability"
    query_emb = embedder.embed_query(query)
    print(f"\nQuery embedding dimension: {len(query_emb)}")
    print(f"Query embedding (first 5 dims): {query_emb[:5]}")
