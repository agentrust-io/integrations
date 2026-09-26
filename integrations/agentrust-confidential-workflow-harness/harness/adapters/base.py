from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
from ..model import Observation, Scenario

@dataclass(frozen=True)
class AdapterResult:
    observations: tuple[Observation, ...]

class Adapter(Protocol):
    name: str
    def run(self, scenario: Scenario) -> AdapterResult: ...
