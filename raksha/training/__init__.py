"""E8 — gated fine-tuning dataset curation (scaffolding, OFF by default).

This package curates a supervised fine-tuning dataset EXCLUSIVELY from gate-VERIFIED findings, so
the data is clean by construction: it learns only from proofs. It assembles pairs and refuses
anything unproven — it does **not** train anything.

!!! Actual fine-tuning is an optional, operator-initiated GPU step OUTSIDE this module. This package
    performs NO training and NO network I/O. Nothing in the RAKSHA pipeline invokes it automatically;
    an operator runs `dry_run` / `build_dataset` / `write_jsonl` by hand when (and only when) they
    choose to curate a corpus. See `raksha.training.dataset`.
"""

from __future__ import annotations

from .dataset import build_dataset, dry_run, eligibility, write_jsonl

__all__ = ["build_dataset", "dry_run", "write_jsonl", "eligibility"]
