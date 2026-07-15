"""
open-re Python bindings for reverse engineering.

This package provides Python bindings to the open-re reverse engineering platform,
allowing programmatic access to binary analysis, AI-powered analysis, and more.
"""

from .client import OpenREClient
from .models import (
    Project,
    File,
    Function,
    AnalysisJob,
    AnalysisResult,
    Plugin,
    User,
    APIKey,
)
from .analysis import AnalysisManager
from .plugins import PluginManager

__version__ = "0.1.0"
__all__ = [
    "OpenREClient",
    "Project",
    "File",
    "Function",
    "AnalysisJob",
    "AnalysisResult",
    "Plugin",
    "User",
    "APIKey",
    "AnalysisManager",
    "PluginManager",
]