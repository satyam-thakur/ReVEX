"""
Common Data Types
=================

Lightweight data structures to replace heavy framework dependencies.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List

@dataclass
class Document:
    """
    Lightweight document representation.
    Replaces langchain.docstore.document.Document to avoid overhead.
    """
    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'page_content': self.page_content,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Document':
        return cls(
            page_content=data['page_content'],
            metadata=data.get('metadata', {})
        )
