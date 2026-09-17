"""Solve the Cloudflare WAF challenge with the Flash Solvers API."""

from .solver import (
    CLEARANCE_COOKIE,
    DEFAULT_ENDPOINT,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_USER_AGENT,
    APIError,
    CloudflareError,
    CloudflareSolver,
    NotClearedError,
    SolveError,
    SolveResult,
)
from .tls import TLSError, TLSSession

__version__ = "0.1.0"

__all__ = [
    "CLEARANCE_COOKIE",
    "DEFAULT_ENDPOINT",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_USER_AGENT",
    "APIError",
    "CloudflareError",
    "CloudflareSolver",
    "NotClearedError",
    "SolveError",
    "SolveResult",
    "TLSError",
    "TLSSession",
]
