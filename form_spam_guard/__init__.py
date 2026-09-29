"""form-spam-guard: CAPTCHA-free spam protection for web forms (stdlib only)."""

from .content import DEFAULT_BLOCKED_HOSTS, ContentFilter, Finding
from .guard import Decision, Guard
from .honeypot import Honeypot
from .ratelimit import RateLimiter
from .stores import InMemoryStore, NonceStore, SQLiteStore
from .tokens import TokenResult, TokenSigner

__version__ = "0.1.0"

__all__ = [
    "ContentFilter",
    "DEFAULT_BLOCKED_HOSTS",
    "Decision",
    "Finding",
    "Guard",
    "Honeypot",
    "InMemoryStore",
    "NonceStore",
    "RateLimiter",
    "SQLiteStore",
    "TokenResult",
    "TokenSigner",
]
