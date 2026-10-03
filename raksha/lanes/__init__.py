"""Build-free lanes — proven findings on any target, any language, with no build.

The opening move on an unknown target and the fallback when a build fails: supply-chain
(vulnerable dependencies across ecosystems), secrets, and the dependency-bump patch lane.
"""

from . import bump, secrets, service, supply, version, vulndb
from .buildfree import BuildFreeResult, scan_target

__all__ = ["bump", "secrets", "service", "supply", "version", "vulndb", "BuildFreeResult", "scan_target"]
