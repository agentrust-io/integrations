"""Caller-supplied tool catalog: which system a tool touches, how sensitive that data is, and
whether a call writes.

The recorder never guesses this from tool names. You describe your own tools:

    catalog = ToolCatalog(
        {
            "inventory_lookup": ToolInfo("inventory-db", "database", "internal"),
            "purchase_orders": ToolInfo("erp", "erp", "confidential",
                                        write=lambda action: action not in {"get", "list"}),
            "crm_*": ToolInfo("crm", "crm", "confidential"),   # prefix match
        },
        taxonomy="example.v1",
        order=("public", "internal", "confidential"),          # lowest to highest
    )

Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Sequence, Union

__all__ = ["ToolInfo", "ToolCatalog"]

WriteRule = Union[bool, Callable[[Optional[str]], bool]]


@dataclass(frozen=True)
class ToolInfo:
    """system: id of the system the tool reaches (becomes the data-flow endpoint id).
    kind: endpoint kind, e.g. "database", "erp", "saas", "file".
    classification: one value from the catalog's order.
    write: True, False, or a function of the call's action verb (None when no verb was recorded).
    """

    system: str
    kind: str = "service"
    classification: str = "internal"
    write: WriteRule = False


class ToolCatalog:
    """Maps tool names to ToolInfo. Exact names win over "prefix*" keys; the longest prefix wins.

    A tool that is not in the catalog gets `default`. When no default is given, an unknown tool is
    treated as a write to an "uncatalogued" system at the highest classification, so a missing
    entry overstates rather than understates what happened.
    """

    def __init__(self, tools: Mapping[str, ToolInfo], *, taxonomy: str, order: Sequence[str],
                 default: Optional[ToolInfo] = None):
        if not taxonomy:
            raise ValueError("taxonomy is required")
        order = tuple(order)
        if not order or len(set(order)) != len(order):
            raise ValueError("order must list each classification once, lowest first")
        self.taxonomy = taxonomy
        self.order = order
        self.default = default or ToolInfo("uncatalogued", "other", order[-1], True)
        self._exact = {}
        self._prefixes = []
        for name, info in dict(tools).items():
            if info.classification not in order:
                raise ValueError(f"{name}: classification {info.classification!r} is not in order")
            if name.endswith("*"):
                self._prefixes.append((name[:-1], info))
            else:
                self._exact[name] = info
        if self.default.classification not in order:
            raise ValueError("default classification is not in order")
        self._prefixes.sort(key=lambda item: len(item[0]), reverse=True)

    def lookup(self, tool: str) -> ToolInfo:
        if tool in self._exact:
            return self._exact[tool]
        for prefix, info in self._prefixes:
            if tool.startswith(prefix):
                return info
        return self.default

    def is_write(self, tool: str, action: Optional[str] = None) -> bool:
        rule = self.lookup(tool).write
        return bool(rule(action)) if callable(rule) else bool(rule)

    def highest(self, classes) -> str:
        ranked = [c for c in classes if c in self.order]
        return max(ranked, key=self.order.index) if ranked else self.order[0]
