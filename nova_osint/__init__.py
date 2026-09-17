"""OSINT Suite - all-in-one open-source intelligence collection."""

from .core.config import Config
from .core.engine import Engine
from .core.models import Confidence, Finding, Investigation, ScanResult, Severity, TargetType
from .core.registry import all_modules, detect_type

__version__ = "1.0.0"
__all__ = [
    "Config",
    "Engine",
    "Investigation",
    "ScanResult",
    "Finding",
    "TargetType",
    "Severity",
    "Confidence",
    "all_modules",
    "detect_type",
]
