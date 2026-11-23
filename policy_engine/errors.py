"""Shared exception type for user-facing input errors."""

from __future__ import annotations


class PolicyEngineError(Exception):
    """Raised for bad input (missing/malformed/wrongly-shaped report or policy files)."""
