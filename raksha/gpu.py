"""Live VRAM reading — a scored resource metric, measured, never asserted.

The finale is judged on least resources, and VRAM is the headline GPU cost. This reads it from
`nvidia-smi` when a GPU is present and returns None when one is not (a CPU-only box, or this
build container) — so the metric is honestly absent rather than faked as a zero. On the finale
node it is a live gauge the Scorecard renders.

stdlib only; no NVML binding to audit. If anything about the reading is unavailable, it degrades
to None rather than raising — a missing telemetry reading must never crash the run.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class VramReading:
    used_mb: int
    total_mb: int

    @property
    def used_pct(self) -> float:
        return round(100.0 * self.used_mb / self.total_mb, 1) if self.total_mb else 0.0

    def as_dict(self) -> dict:
        return {"used_mb": self.used_mb, "total_mb": self.total_mb, "used_pct": self.used_pct}


def vram() -> VramReading | None:
    """Current VRAM use across GPUs, or None when no GPU / no nvidia-smi is available."""
    exe = shutil.which("nvidia-smi")
    if not exe:
        return None
    try:
        out = subprocess.run(
            [exe, "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    used = total = 0
    for line in out.stdout.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            used += int(parts[0])
            total += int(parts[1])
    return VramReading(used, total) if total else None
