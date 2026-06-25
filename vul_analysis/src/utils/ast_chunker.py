"""
AST-based code chunker with semantic boundaries.

Optimal architecture for vulnerability analysis:
- Preserves comments (critical for security context)
- Never splits functions mid-way (maintains logical flow)
- Coalesces small functions (reduces noise)
- Enriched metadata (dependencies, scope, line ranges)
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass

try:
    from tree_sitter import Language, Parser, Node, Query, QueryCursor
    import tree_sitter_python as tspython
    import tree_sitter_go as tsgo
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    # Define placeholder types for type hints when tree-sitter is not available
    Node = None  # type: ignore
    Query = None  # type: ignore
    QueryCursor = None  # type: ignore
    logging.warning("tree-sitter not available, falling back to text-based chunking")


@dataclass
class CodeChunk:
    """Represents a semantically complete code chunk."""
    content: str
    file_path: str
    start_line: int
    end_line: int
    language: str
    node_type: str  # 'function', 'class', 'method', 'struct'
    function_names: List[str]
    dependencies: List[str]  # Imports/includes detected in this chunk
    has_comments: bool
    chunk_size: int
    
    def to_document(self) -> Dict[str, Any]:
        """Convert to LangChain-style Document format."""
        return {
            "page_content": self.content,
            "metadata": {
                "file_path": self.file_path,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "language": self.language,
                "node_type": self.node_type,
                "function_names": self.function_names,
                "dependencies": self.dependencies,
                "has_comments": self.has_comments,
                "chunk_size": self.chunk_size,
            }
        }


class CoalescingASTSplitter:
    """
    AST-based code splitter that respects semantic boundaries.
    
    Key principles:
    1. Never split a function in the middle
    2. Preserve comments (critical for security analysis)
    3. Coalesce small functions to provide context
    4. Extract rich metadata (dependencies, scope, etc.)
    """
    
    # Language-specific query patterns
    QUERIES = {
        'python': """
(function_definition) @func
(class_definition) @class
(decorated_definition) @decorated
(import_statement) @import
(import_from_statement) @import
(comment) @comment
""",
        'go': """
(function_declaration) @func
(method_declaration) @method
(type_declaration) @type
(import_declaration) @import
(comment) @comment
"""
    }
    
    def __init__(self, max_chunk_size: int = 1500, logger: Optional[logging.Logger] = None):
        """
        Initialize AST splitter.
        
        Args:
            max_chunk_size: Target character limit per chunk (soft limit)
            logger: Optional logger instance
        """
        if not TREE_SITTER_AVAILABLE:
            raise ImportError("tree-sitter is required. Install: pip install tree-sitter tree-sitter-python tree-sitter-go")
        
        self.max_chunk_size = max_chunk_size
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize parsers for supported languages
        self.parsers = {}
        self.languages = {}
        
        try:
            self.languages['python'] = Language(tspython.language())
            self.parsers['python'] = Parser(self.languages['python'])
            self.logger.info("Initialized Python parser")
        except Exception as e:
            self.logger.warning(f"Failed to initialize Python parser: {e}")
        
        try:
            self.languages['go'] = Language(tsgo.language())
            self.parsers['go'] = Parser(self.languages['go'])
            self.logger.info("Initialized Go parser")
        except Exception as e:
            self.logger.warning(f"Failed to initialize Go parser: {e}")
    
    def split_file(self, file_path: str, file_content: str, language: str = None) -> List[CodeChunk]:
        """
        Split a source file into semantic chunks.
        
        Args:
            file_path: Path to the source file
            file_content: Content of the file
            language: Programming language ('python', 'go', or auto-detect)
        
        Returns:
            List of CodeChunk objects
        """
        if language is None:
            language = self._detect_language(file_path)
        
        if language not in self.parsers:
            self.logger.warning(f"No parser for {language}, using fallback text chunking")
            return self._fallback_chunking(file_path, file_content, language)
        
        try:
            chunks = self._ast_based_chunking(file_path, file_content, language)
            if not chunks:
                self.logger.warning(f"AST chunking produced no chunks for {file_path}, falling back")
                return self._fallback_chunking(file_path, file_content, language)
            return chunks
        except Exception as e:
            self.logger.error(f"AST parsing failed for {file_path}: {e}")
            return self._fallback_chunking(file_path, file_content, language)
    
    def _detect_language(self, file_path: str) -> str:
        """Detect language from file extension."""
        ext = Path(file_path).suffix.lower()
        mapping = {
            '.py': 'python',
            '.go': 'go',
            '.cpp': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.hpp': 'cpp',
            '.java': 'java',
        }
        return mapping.get(ext, 'unknown')
    
    def _ast_based_chunking(self, file_path: str, content: str, language: str) -> List[CodeChunk]:
        """Perform AST-based semantic chunking."""
        parser = self.parsers[language]
        tree = parser.parse(bytes(content, "utf8"))
        root = tree.root_node
        
        # Extract atomic units (functions, classes, methods)
        atomic_units = self._extract_atomic_units(root, content, language)
        
        # Extract imports/dependencies
        dependencies = self._extract_dependencies(root, content, language)
        
        # Coalesce units into chunks
        chunks = self._coalesce_units(atomic_units, dependencies, file_path, language)
        
        self.logger.debug(f"Split {file_path} into {len(chunks)} semantic chunks")
        return chunks
    
    def _extract_atomic_units(self, root_node: Node, content: str, language: str) -> List[Dict[str, Any]]:
        """Extract functions, classes, and methods as atomic units."""
        query_str = self.QUERIES.get(language, "")
        if not query_str:
            return []
        
        lang_obj = self.languages[language]
        
        try:
            # Create Query object (new API: Query(language, query_string))
            query = Query(lang_obj, query_str.strip())
            
            # Get captures using QueryCursor (new API: QueryCursor(query))
            cursor = QueryCursor(query)
            captures = []
            
            # Execute query and collect captures
            for match in cursor.matches(root_node):
                for capture_name, nodes in match[1].items():
                    # match[1] is a dict of {capture_name: nodes}
                    if isinstance(nodes, list):
                        for node in nodes:
                            captures.append((node, capture_name))
                    else:
                        captures.append((nodes, capture_name))
        
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return []
        
        # Track seen ranges to avoid duplicates (decorated_definition contains function_definition)
        seen_ranges = set()
        units = []
        
        for node, capture_name in captures:
            # Skip comments for now, we'll preserve them in content
            if capture_name == 'comment' or capture_name == 'import':
                continue
            
            # Check if nested inside another captured node
            is_nested = any(
                node.start_byte >= start and node.end_byte <= end
                for start, end in seen_ranges
                if (start, end) != (node.start_byte, node.end_byte)
            )
            
            if is_nested:
                continue
            
            seen_ranges.add((node.start_byte, node.end_byte))
            
            # Extract node content
            node_content = content[node.start_byte:node.end_byte]
            
            # Detect function/class names
            func_names = self._extract_function_names(node, content, language)
            
            # Check for comments
            has_comments = '//' in node_content or '#' in node_content or '/*' in node_content
            
            units.append({
                "type": capture_name,
                "content": node_content,
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "start_byte": node.start_byte,
                "end_byte": node.end_byte,
                "size": node.end_byte - node.start_byte,
                "function_names": func_names,
                "has_comments": has_comments,
            })
        
        # Sort by position
        units.sort(key=lambda u: u['start_byte'])
        return units
    
    def _extract_function_names(self, node: Node, content: str, language: str) -> List[str]:
        """Extract function/method/class names from a node."""
        names = []
        
        if language == 'python':
            # Look for 'name' child in function_definition or class_definition
            for child in node.children:
                if child.type == 'identifier':
                    names.append(content[child.start_byte:child.end_byte])
        
        elif language == 'go':
            # For Go: function_declaration has 'name' field
            for child in node.children:
                if child.type == 'identifier':
                    names.append(content[child.start_byte:child.end_byte])
        
        return names
    
    def _extract_dependencies(self, root_node: Node, content: str, language: str) -> List[str]:
        """Extract imports and dependencies."""
        query_str = self.QUERIES.get(language, "")
        if not query_str:
            return []
        
        lang_obj = self.languages[language]
        
        try:
            query = Query(lang_obj, query_str.strip())
            cursor = QueryCursor(query)
            captures = []
            
            for match in cursor.matches(root_node):
                for capture_name, nodes in match[1].items():
                    # match[1] is a dict of {capture_name: nodes}
                    if isinstance(nodes, list):
                        for node in nodes:
                            captures.append((node, capture_name))
                    else:
                        captures.append((nodes, capture_name))
        except Exception as e:
            self.logger.debug(f"Dependency extraction failed: {e}")
            return []
        
        deps = []
        for node, capture_name in captures:
            if capture_name == 'import':
                import_text = content[node.start_byte:node.end_byte]
                # Extract package names
                if language == 'python':
                    # "import X" or "from X import Y"
                    parts = import_text.replace('import', '').replace('from', '').strip().split()
                    deps.extend([p.strip() for p in parts if p and not p.startswith('import')])
                elif language == 'go':
                    # Extract quoted strings from import
                    import re
                    matches = re.findall(r'"([^"]+)"', import_text)
                    deps.extend(matches)
        
        return list(set(deps))  # Deduplicate
    
    def _coalesce_units(self, units: List[Dict[str, Any]], dependencies: List[str], 
                        file_path: str, language: str) -> List[CodeChunk]:
        """Merge small units into chunks while respecting size limits."""
        chunks = []
        current_units = []
        current_size = 0
        
        for unit in units:
            # Decision logic:
            # 1. If adding this unit exceeds limit AND we have units -> seal current chunk
            # 2. If unit alone is massive -> give it its own chunk
            # 3. Otherwise, accumulate
            
            if current_size + unit['size'] > self.max_chunk_size and current_units:
                # Seal current chunk
                chunks.append(self._finalize_chunk(current_units, dependencies, file_path, language))
                current_units = []
                current_size = 0
            
            current_units.append(unit)
            current_size += unit['size']
        
        # Finalize remaining units
        if current_units:
            chunks.append(self._finalize_chunk(current_units, dependencies, file_path, language))
        
        return chunks
    
    def _finalize_chunk(self, units: List[Dict[str, Any]], dependencies: List[str],
                        file_path: str, language: str) -> CodeChunk:
        """Convert grouped units into a CodeChunk."""
        # Join content with spacing
        combined_content = "\n\n".join([u['content'] for u in units])
        
        # Aggregate metadata
        start_line = units[0]['start_line']
        end_line = units[-1]['end_line']
        all_func_names = []
        for u in units:
            all_func_names.extend(u['function_names'])
        
        has_comments = any(u['has_comments'] for u in units)
        node_types = list(set(u['type'] for u in units))
        node_type = node_types[0] if len(node_types) == 1 else 'mixed'
        
        return CodeChunk(
            content=combined_content,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
            node_type=node_type,
            function_names=all_func_names,
            dependencies=dependencies,
            has_comments=has_comments,
            chunk_size=len(combined_content),
        )
    
    def _fallback_chunking(self, file_path: str, content: str, language: str) -> List[CodeChunk]:
        """Fallback to simple line-based chunking when AST fails."""
        lines = content.split('\n')
        chunks = []
        
        chunk_lines = []
        chunk_start = 1
        current_size = 0
        
        for i, line in enumerate(lines, 1):
            chunk_lines.append(line)
            current_size += len(line)
            
            if current_size >= self.max_chunk_size:
                chunks.append(CodeChunk(
                    content='\n'.join(chunk_lines),
                    file_path=file_path,
                    start_line=chunk_start,
                    end_line=i,
                    language=language,
                    node_type='text',
                    function_names=[],
                    dependencies=[],
                    has_comments='#' in '\n'.join(chunk_lines) or '//' in '\n'.join(chunk_lines),
                    chunk_size=current_size,
                ))
                chunk_lines = []
                chunk_start = i + 1
                current_size = 0
        
        if chunk_lines:
            chunks.append(CodeChunk(
                content='\n'.join(chunk_lines),
                file_path=file_path,
                start_line=chunk_start,
                end_line=len(lines),
                language=language,
                node_type='text',
                function_names=[],
                dependencies=[],
                has_comments='#' in '\n'.join(chunk_lines) or '//' in '\n'.join(chunk_lines),
                chunk_size=current_size,
            ))
        
        return chunks
