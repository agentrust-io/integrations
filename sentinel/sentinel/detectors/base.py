from abc import ABC, abstractmethod
from src.models import SentinelInput, DetectionResult

class BaseDetector(ABC):
    """Base class for all anomaly detectors."""

    @abstractmethod
    def detect(self, input_data: SentinelInput) -> DetectionResult:
        """Run detection logic and return a DetectionResult."""
        pass

    @abstractmethod
    def name(self) -> str:
        """Return the detector's name."""
        pass