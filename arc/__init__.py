"""Facade package for the archive-bomb admission-control exercise.

The public API is exported from :mod:`arc.api`; callers import the eight
contract functions from this package.
"""

from __future__ import annotations

from .api import (
    archive_batch,
    budget_check,
    depth_check,
    extract_plan,
    inspect,
    path_check,
    ratio_check,
    validate_policy,
)

__all__ = [
    "inspect",
    "ratio_check",
    "budget_check",
    "depth_check",
    "path_check",
    "extract_plan",
    "validate_policy",
    "archive_batch",
]