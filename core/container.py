from __future__ import annotations
from typing import Any, Dict, Type, TypeVar, Optional
import logging

T = TypeVar("T")

class Container:
    """The central nervous system of VulnForge."""
    def __init__(self):
        self._registry: Dict[Type[Any], Any] = {}
        self.logger = logging.getLogger("VulnForge.Core")

    def register(self, interface: Type[T], implementation: Any):
        self._registry[interface] = implementation
        self.logger.info(f"Registered Service: {interface.__name__}")

    def resolve(self, interface: Type[T]) -> T:
        if interface not in self._registry:
            raise Exception(f"Service {interface.__name__} not found in container.")
        return self._registry[interface]

# Global Context
context = Container()
