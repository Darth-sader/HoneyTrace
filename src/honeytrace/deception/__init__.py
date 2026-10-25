"""Deception layer: tokens, decoy generation, inventory and workspace."""

from honeytrace.deception.generator import DecoyContent, DecoyGenerator
from honeytrace.deception.inventory import DecoyInventory
from honeytrace.deception.tokens import TokenRegistry
from honeytrace.deception.workspace import DeceptionWorkspace, WorkspaceError

__all__ = [
    "DecoyContent",
    "DecoyGenerator",
    "DecoyInventory",
    "TokenRegistry",
    "DeceptionWorkspace",
    "WorkspaceError",
]
