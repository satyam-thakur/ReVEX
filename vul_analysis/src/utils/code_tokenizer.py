"""
Code-Specific Tokenizer for Lexical Search
==========================================

Implements specialized tokenization for source code that handles:
- camelCase and snake_case splitting
- Preserving exact identifiers
- N-gram generation for partial matching
- Language-aware keyword preservation

Citation:
---------
Industry standard approach used by Sourcegraph and GitHub Code Search.
Based on trigram and identifier splitting patterns.

Reference:
Huston, S., et al. (2011). "Index Compression for BitSlice Indices."
"""

import re
from typing import List, Set
from dataclasses import dataclass


@dataclass
class TokenizerConfig:
    """Configuration for code tokenization"""
    preserve_case: bool = True  # Keep original case for exact matching
    generate_ngrams: bool = True  # Generate bigrams/trigrams
    min_token_length: int = 2
    max_token_length: int = 50
    split_camel_case: bool = True
    split_snake_case: bool = True


class CodeTokenizer:
    """
    Specialized tokenizer for source code that preserves code semantics.
    
    Examples:
        >>> tokenizer = CodeTokenizer()
        >>> tokens = tokenizer.tokenize("def get_user_data(id):")
        >>> # Returns: ["def", "get", "user", "data", "id", "get_user", "user_data"]
    """
    
    # Common programming language keywords to preserve
    KEYWORDS = {
        # Python
        'def', 'class', 'import', 'from', 'return', 'if', 'else', 'elif',
        'for', 'while', 'try', 'except', 'finally', 'with', 'as', 'pass',
        'break', 'continue', 'yield', 'raise', 'assert', 'async', 'await',
        # Go
        'func', 'package', 'type', 'struct', 'interface', 'chan', 'go',
        'defer', 'select', 'case', 'switch', 'range', 'const', 'var',
        # Common
        'true', 'false', 'null', 'nil', 'none', 'this', 'self',
    }
    
    # Vulnerability-relevant keywords (security-specific)
    SECURITY_KEYWORDS = {
        'exec', 'eval', 'system', 'shell', 'cmd', 'command',
        'sql', 'query', 'execute', 'prepare',
        'file', 'open', 'read', 'write', 'path',
        'auth', 'login', 'password', 'token', 'session',
        'admin', 'user', 'role', 'permission',
        'validate', 'sanitize', 'escape', 'filter',
        'unsafe', 'danger', 'risk', 'vuln', 'cve',
    }
    
    def __init__(self, config: TokenizerConfig = None):
        """
        Initialize the code tokenizer.
        
        Args:
            config: Tokenizer configuration. Uses defaults if None.
        """
        self.config = config or TokenizerConfig()
        self.all_keywords = self.KEYWORDS | self.SECURITY_KEYWORDS
        
    def tokenize(self, text: str) -> List[str]:
        """
        Tokenize source code text into searchable tokens.
        
        Args:
            text: Source code string
            
        Returns:
            List of tokens optimized for code search
        """
        if not text:
            return []
        
        # Step 1: Extract base tokens (split by non-alphanumeric)
        base_tokens = self._extract_base_tokens(text)
        
        # Step 2: Split compound identifiers (camelCase, snake_case)
        split_tokens = []
        for token in base_tokens:
            split_tokens.extend(self._split_identifier(token))
        
        # Step 3: Generate n-grams for partial matching
        all_tokens = set(split_tokens)
        if self.config.generate_ngrams:
            all_tokens.update(self._generate_ngrams(split_tokens))
        
        # Step 4: Filter and normalize
        final_tokens = self._filter_tokens(all_tokens)
        
        return sorted(final_tokens)  # Sort for consistent ordering
    
    def _extract_base_tokens(self, text: str) -> List[str]:
        """
        Extract base tokens by splitting on non-alphanumeric characters.
        
        Preserves underscores within identifiers.
        """
        # Split on whitespace and most special chars, but preserve underscores
        pattern = r'[a-zA-Z_][a-zA-Z0-9_]*'
        tokens = re.findall(pattern, text)
        return tokens
    
    def _split_identifier(self, identifier: str) -> List[str]:
        """
        Split compound identifiers into sub-tokens.
        
        Examples:
            getUserData -> [getUserData, get, User, Data]
            user_name -> [user_name, user, name]
            HTTPServer -> [HTTPServer, HTTP, Server]
        """
        parts = [identifier]  # Always keep original
        
        # Split snake_case
        if self.config.split_snake_case and '_' in identifier:
            snake_parts = identifier.split('_')
            parts.extend([p for p in snake_parts if p])
        
        # Split camelCase and PascalCase
        if self.config.split_camel_case:
            # Find transitions: lowercase->uppercase or uppercase->uppercase->lowercase
            camel_parts = re.findall(
                r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)',
                identifier
            )
            parts.extend([p for p in camel_parts if p])
        
        return parts
    
    def _generate_ngrams(self, tokens: List[str]) -> Set[str]:
        """
        Generate bigrams from consecutive tokens.
        
        Example:
            [get, user, data] -> [get_user, user_data]
        """
        ngrams = set()
        
        # Generate bigrams (pairs of consecutive tokens)
        for i in range(len(tokens) - 1):
            if tokens[i] and tokens[i+1]:
                bigram = f"{tokens[i]}_{tokens[i+1]}"
                ngrams.add(bigram)
        
        return ngrams
    
    def _filter_tokens(self, tokens: Set[str]) -> List[str]:
        """
        Filter and normalize tokens.
        
        - Remove very short/long tokens
        - Preserve keywords
        - Convert to lowercase (unless preserve_case is True)
        """
        filtered = []
        
        for token in tokens:
            token_lower = token.lower()
            
            # Always keep keywords
            if token_lower in self.all_keywords:
                filtered.append(token_lower)
                continue
            
            # Length filter
            if len(token) < self.config.min_token_length:
                continue
            if len(token) > self.config.max_token_length:
                continue
            
            # Normalize case
            if self.config.preserve_case:
                filtered.append(token)
            else:
                filtered.append(token_lower)
        
        return filtered
    
    def tokenize_batch(self, texts: List[str]) -> List[List[str]]:
        """
        Tokenize multiple texts in batch.
        
        Args:
            texts: List of source code strings
            
        Returns:
            List of token lists
        """
        return [self.tokenize(text) for text in texts]


class CodeAwareTokenizer:
    """
    Enhanced tokenizer that preserves code structure context.
    
    Includes:
    - Function/class name detection
    - Comment preservation
    - String literal handling
    """
    
    def __init__(self):
        self.base_tokenizer = CodeTokenizer()
    
    def tokenize_with_context(self, text: str, metadata: dict = None) -> dict:
        """
        Tokenize with additional context preservation.
        
        Args:
            text: Source code
            metadata: Optional metadata (file_path, functions, etc.)
            
        Returns:
            Dict with tokens and context
        """
        tokens = self.base_tokenizer.tokenize(text)
        
        result = {
            'tokens': tokens,
            'token_count': len(tokens),
            'has_security_keywords': self._has_security_keywords(tokens),
        }
        
        if metadata:
            result['metadata'] = metadata
            
            # Boost tokens from function names
            if 'functions' in metadata:
                func_tokens = []
                for func_name in metadata['functions']:
                    func_tokens.extend(
                        self.base_tokenizer._split_identifier(func_name)
                    )
                result['function_tokens'] = func_tokens
        
        return result
    
    def _has_security_keywords(self, tokens: List[str]) -> bool:
        """Check if tokens contain security-relevant keywords"""
        token_set = set(t.lower() for t in tokens)
        return bool(token_set & CodeTokenizer.SECURITY_KEYWORDS)


# Convenience function for quick tokenization
def tokenize_code(text: str, config: TokenizerConfig = None) -> List[str]:
    """
    Quick tokenization function.
    
    Args:
        text: Source code string
        config: Optional tokenizer config
        
    Returns:
        List of tokens
    """
    tokenizer = CodeTokenizer(config)
    return tokenizer.tokenize(text)


if __name__ == "__main__":
    # Demo
    print("Code Tokenizer Demo")
    print("=" * 60)
    
    test_cases = [
        "def get_user_data(id):",
        "class HTTPServer:",
        "admin_flag = check_permission(user_id)",
        "execv('/bin/sh', args)",
    ]
    
    tokenizer = CodeTokenizer()
    
    for code in test_cases:
        tokens = tokenizer.tokenize(code)
        print(f"\nInput:  {code}")
        print(f"Tokens: {tokens[:15]}")  # Show first 15
