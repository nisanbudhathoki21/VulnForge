from __future__ import annotations
from typing import Dict, Any, Protocol
class Plugin(Protocol):
    name: str
    version: str
    def register(self, ctx: "PluginContext") -> None: ...
class PluginContext:
    def __init__(self) -> None:
        self._registries: Dict[str, Dict[str, Any]] = {}
    def provide(self, registry: str, key: str, value: Any) -> None:
        self._registries.setdefault(registry, {})[key] = value
    def get_registry(self, registry: str) -> Dict[str, Any]:
        return self._registries.get(registry, {})
class PluginManager:
    def __init__(self) -> None:
        self.ctx = PluginContext()
        self.loaded: Dict[str, Plugin] = {}
    def manual_register(self, plugin: Plugin) -> None:
        plugin.register(self.ctx)
        self.loaded[plugin.name] = plugin
