"""An explicit extension seam; no inferred application endpoints."""
from typing import Protocol
from .core import BridgeError, Store

class Adapter(Protocol):
    def receive(self, message_id: str) -> dict: ...

class ManualAdapter:
    def __init__(self, store: Store):
        self.store = store
    def receive(self, message_id: str) -> dict:
        return self.store.export(message_id)

class MockAdapter:
    def __init__(self, store: Store):
        self.store = store
    def receive(self, message_id: str) -> dict:
        return self.store.mock(message_id)

class UnconfiguredAgentAdapter:
    def __init__(self, name: str):
        self.name = name
    def receive(self, message_id: str) -> dict:
        raise BridgeError(self.name + " live transport is not configured; use manual handoff or verified MCP.", 409)

# Muse can reuse the same queue/tools; implement only a verified transport.
LIVE_ADAPTERS = {name: UnconfiguredAgentAdapter(name) for name in ("ada", "grokbot", "muse")}
