from __future__ import annotations
from typing import Any, Callable, Dict, TypeVar, Literal
import threading
T = TypeVar("T")
Scope = Literal["singleton", "scoped", "transient"]
class Container:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._providers: Dict[str, tuple[Scope, Callable[[Container], Any]]] = {}
        self._singletons: Dict[str, Any] = {}
        self._scoped: threading.local = threading.local()
    def register(self, key: str, factory: Callable[[Container], T], scope: Scope = "singleton") -> None:
        with self._lock:
            self._providers[key] = (scope, factory)
    def resolve(self, key: str) -> Any:
        with self._lock:
            if key not in self._providers:
                raise KeyError(f"DI: unknown key '{key}'")
            scope, factory = self._providers[key]
            if scope == "singleton":
                if key not in self._singletons:
                    self._singletons[key] = factory(self)
                return self._singletons[key]
            if scope == "scoped":
                if not hasattr(self._scoped, "items"):
                    self._scoped.items = {}
                if key not in self._scoped.items:
                    self._scoped.items[key] = factory(self)
                return self._scoped.items[key]
            return factory(self)
