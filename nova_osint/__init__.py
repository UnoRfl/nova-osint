"""OSINT Suite - all-in-one open-source intelligence collection."""

from .core.config import Config
from .core.engine import Engine
from .core.http import VERSION as __version__
from .core.models import Confidence, Finding, Investigation, ScanResult, Severity, TargetType
from .core.registry import all_modules, detect_type

#: One version string for the package, the User-Agent and the frozen build.
__all__ = [
    "__version__",
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
