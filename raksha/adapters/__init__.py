"""Language adapters — each turns one language's toolchain into a gate Target."""

from .java import MavenReplayTarget, dependency_bump_patch

__all__ = ["MavenReplayTarget", "dependency_bump_patch"]
