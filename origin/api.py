"""Public facade for the origin validation package."""

from ._impl import (
    check_referer,
    normalize,
    origin_batch,
    parse_origin,
    require_check,
    same_origin,
    trusted_origin,
    validate_policy,
)

__all__ = [
    "parse_origin",
    "normalize",
    "trusted_origin",
    "same_origin",
    "check_referer",
    "require_check",
    "validate_policy",
    "origin_batch",
]