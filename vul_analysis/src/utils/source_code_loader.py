"""
Optimized source code loader with sparse git operations.

Improvements over standard cloning:
- Shallow clones (--depth 1): No commit history
- Blobless clones (--filter=blob:none): Lazy file download
- Sparse checkout: Only specified directories
- Multi-language support with AST parsing
"""

import os
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import logging
import subprocess
import shutil
import os

from .types import Document
from .ast_chunker import CoalescingASTSplitter

logger = logging.getLogger(__name__)


class SourceCodeLoader:
    """
    Optimized source code loader with shallow blobless cloning.
    
    Features:
    - Shallow clone (--depth 1)
    - Blobless clone (--filter=blob:none)
    - Language-specific filtering
    - AST-based chunking
    """
    
    def __init__(
        self,
        languages: List[str] = ['python', 'go'],
        chunk_size: int = 1500,
        temp_dir: Path = Path('.temp_repos'),
    ):
        self.languages = languages
        self.chunk_size = chunk_size
        self.temp_dir = temp_dir
        self.splitter = CoalescingASTSplitter(
            max_chunk_size=chunk_size
        )
        
    def load_documents(
        self,
        repo_path: Path,
        file_extensions: List[str] = None,
    ) -> List[Document]:
        """
        Load and chunk documents from a local repository path.
        
        Args:
            repo_path: Path to the repository
            file_extensions: List of extensions to include (e.g. ['.py', '.go'])
            
        Returns:
            List of Document objects
        """
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
            
        source_files = self._collect_source_files(repo_path, file_extensions)
        logger.info(f"Found {len(source_files)} source files in {repo_path}")
        
        documents = []
        for file_path in source_files:
            try:
                file_docs = self._process_file(file_path)
                documents.extend(file_docs)
            except Exception as e:
                logger.warning(f"Failed to process {file_path}: {e}")
                
        return documents
    
    def _collect_source_files(self, repo_path: Path, file_extensions: List[str] = None) -> List[Path]:
        """
        Collect source files matching language filters.
        """
        # Get all extensions we care about
        if file_extensions:
            extensions = file_extensions
        else:
            extensions = []
            # Map languages to extensions
            LANGUAGE_EXTENSIONS = {
                'python': ['.py'],
                'go': ['.go'],
                'c': ['.c', '.h'],
                'cpp': ['.cpp', '.hpp', '.cc', '.cxx', '.hh'],
                'java': ['.java'],
                'javascript': ['.js', '.jsx'],
                'typescript': ['.ts', '.tsx'],
            }
            for lang in self.languages:
                extensions.extend(LANGUAGE_EXTENSIONS.get(lang, []))
        
        source_files = []
        
        # Directories to exclude
        EXCLUDE_PATTERNS = [
            'test', 'tests', '__test__', '__tests__', 'unit-test',
            'doc', 'docs', 'documentation',
            'vendor', 'node_modules', 'node_modules/.cache', '.pnpm', 'pnpm-store', '.yarn', '.yarn_cache', 'third_party',
            '.git', '.github', '.vscode',
            'examples', 'sample', 'samples', 'sampleconfig',
            'mock', 'mocks', 'fixtures',
            'integration', 'scripts', 'images', 'testdata',
            'dist', 'build', 'target', '.next', 'out', 'compiled', 'static',
            '.venv', 'venv', 'env', '_build', 'deps', '.tox', '.pytest_cache', '.mypy_cache', 'coverage', '.cache',
            '__pycache__', '.idea', '.gradle', '.mvn', '.settings', 'logs', 'tmp', 'charts', 'helm',
        ]

        # File-level exclusions to avoid bundled/minified/wasm artifacts
        EXCLUDE_FILE_SUFFIXES = {
            '.min.js', '.min.css', '.bundle.js', '.chunk.js', '.map', '.wasm', '.wasm.js',
            '.jar', '.war', '.ear', '.class', '.o', '.so', '.a', '.dll', '.exe', '.dylib', '.obj', '.pyc',
            '.whl', '.egg', '.log', '.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.xz',
            '.rpm', '.deb', '.apk', '.msi', '.spdx', '.sbom.json', '.cdx.json'
        }
        
        # Walk the repository
        for root, dirs, files in os.walk(repo_path):
            # Filter out excluded directories IN-PLACE
            dirs[:] = [d for d in dirs if not any(p in d.lower() for p in EXCLUDE_PATTERNS)]
            
            # Collect matching files
            for file in files:
                file_path = Path(root) / file
                suffix = file_path.suffix

                if suffix in EXCLUDE_FILE_SUFFIXES:
                    continue

                if suffix in extensions:
                    # Exclude test files and generated files
                    if file.endswith('_test.go') or file.endswith('.pb.go'):
                        continue
                    if 'mock' in file.lower():
                        continue

                    # Skip obvious compiled bundles/minified artifacts
                    lowered = file.lower()
                    if any(token in lowered for token in ['bundle', 'minified', 'compiled', 'webpack']):
                        continue

                    source_files.append(file_path)
        
        return source_files
    
    def _process_file(self, file_path: Path) -> List[Document]:
        """Process a single source file into chunks."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Detect language
            language = self._detect_language(file_path)
            
            # Use AST splitter if available
            if self.splitter:
                rel_path = str(file_path.relative_to(self.temp_dir if self.temp_dir.exists() else file_path.parent))
                # Try to get relative path from repo root if possible
                try:
                    # Find repo root by looking for .git
                    current = file_path.parent
                    while current != current.parent:
                        if (current / '.git').exists():
                            rel_path = str(file_path.relative_to(current))
                            break
                        current = current.parent
                except:
                    pass
                    
                chunks = self.splitter.split_file(rel_path, content, language)
            else:
                # Fallback to simple chunking
                chunks = self._simple_chunk(file_path, content, language)
            
            # Convert CodeChunks to Documents
            documents = []
            for chunk in chunks:
                doc = Document(
                    page_content=chunk.content,
                    metadata={
                        'file_path': chunk.file_path,
                        'start_line': chunk.start_line,
                        'end_line': chunk.end_line,
                        'language': chunk.language,
                        'chunk_type': chunk.node_type,
                        'functions': chunk.function_names,
                        'dependencies': chunk.dependencies,
                        'has_comments': chunk.has_comments,
                    }
                )
                documents.append(doc)
            return documents
            
        except Exception as e:
            logger.error(f"Failed to process {file_path}: {e}")
            return []
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension."""
        ext = file_path.suffix.lower()
        LANGUAGE_EXTENSIONS = {
            'python': ['.py'],
            'go': ['.go'],
            'c': ['.c', '.h'],
            'cpp': ['.cpp', '.hpp', '.cc', '.cxx', '.hh'],
            'java': ['.java'],
            'javascript': ['.js', '.jsx'],
            'typescript': ['.ts', '.tsx'],
        }
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if ext in exts:
                return lang
        return 'unknown'
    
    def _simple_chunk(self, file_path: Path, content: str, language: str) -> List[Any]:
        """Fallback simple line-based chunking."""
        # Return simple objects that mimic CodeChunk for compatibility
        from collections import namedtuple
        SimpleChunk = namedtuple('SimpleChunk', ['content', 'file_path', 'start_line', 'end_line', 'language', 'node_type', 'function_names', 'dependencies', 'has_comments'])
        
        lines = content.split('\n')
        chunks = []
        
        chunk_lines = []
        chunk_start = 1
        current_size = 0
        
        # Try to get relative path
        try:
            # Find repo root by looking for .git
            current = file_path.parent
            rel_path = str(file_path)
            while current != current.parent:
                if (current / '.git').exists():
                    rel_path = str(file_path.relative_to(current))
                    break
                current = current.parent
        except:
            rel_path = str(file_path)
        
        for i, line in enumerate(lines, 1):
            chunk_lines.append(line)
            current_size += len(line)
            
            if current_size >= self.chunk_size:
                chunks.append(SimpleChunk(
                    content='\n'.join(chunk_lines),
                    file_path=rel_path,
                    start_line=chunk_start,
                    end_line=i,
                    language=language,
                    node_type='text',
                    function_names=[],
                    dependencies=[],
                    has_comments='#' in '\n'.join(chunk_lines) or '//' in '\n'.join(chunk_lines),
                ))
                chunk_lines = []
                chunk_start = i + 1
                current_size = 0
        
        if chunk_lines:
            chunks.append(SimpleChunk(
                content='\n'.join(chunk_lines),
                file_path=rel_path,
                start_line=chunk_start,
                end_line=len(lines),
                language=language,
                node_type='text',
                function_names=[],
                dependencies=[],
                has_comments='#' in '\n'.join(chunk_lines) or '//' in '\n'.join(chunk_lines),
            ))
        
        return chunks
