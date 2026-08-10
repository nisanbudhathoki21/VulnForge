from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    source: str = "crawler"
    depth: int = 0
    content_type: Optional[str] = None

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "source": self.source,
            "depth": self.depth,
            "content_type": self.content_type,
        }
