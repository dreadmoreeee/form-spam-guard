"""Guard: combines honeypot, token, rate limit and content checks."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Mapping, Optional, Union

from .content import ContentFilter
from .honeypot import Honeypot
from .ratelimit import RateLimiter
from .stores import NonceStore
from .tokens import TokenSigner

log = logging.getLogger("form_spam_guard")


@dataclass(frozen=True)
class Decision:
    """Outcome of a check. ``reason`` is machine-readable, ``check`` names the layer.

    ``reason`` is one of: ok, rate_limited, honeypot_filled, missing_token,
    bad_signature, too_fast, token_expired, token_replayed, foreign_script,
    blocked_link_host, too_many_links.
    """

    allowed: bool
    reason: str
    check: str

    def __bool__(self) -> bool:
        return self.allowed


def _values(form: Mapping[str, Any], skip: Iterable[str]) -> List[str]:
    skip = set(skip)
    out: List[str] = []
    for key in list(form.keys()):
        if key in skip:
            continue
        getlist = getattr(form, "getlist", None)
        raw = getlist(key) if callable(getlist) else [form[key]]
        out.extend(v for v in raw if isinstance(v, str))
    return out


class Guard:
    """One object per form (or per site) that runs every check.

    ``secret`` enables the signed timestamp token; leave it None to skip that
    layer. ``honeypot`` and ``content`` take True (defaults), False/None
    (disabled) or a configured instance. ``limiter`` is optional.

    Order: rate limit, honeypot, token, content. The first failure wins.
    """

    def __init__(
        self,
        secret: Union[str, bytes, None] = None,
        *,
        honeypot: Union[Honeypot, bool, None] = True,
        content: Union[ContentFilter, bool, None] = True,
        limiter: Optional[RateLimiter] = None,
        store: Optional[NonceStore] = None,
        min_age: float = 3.0,
        max_age: float = 7200.0,
        form_id: str = "",
        token_field: str = "fsg_token",
        text_fields: Optional[Iterable[str]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.honeypot = Honeypot() if honeypot is True else (honeypot or None)
        self.content = ContentFilter() if content is True else (content or None)
        self.limiter = limiter
        self.signer = (
            TokenSigner(secret, min_age=min_age, max_age=max_age, store=store, clock=clock)
            if secret is not None
            else None
        )
        self.form_id = form_id
        self.token_field = token_field
        self.text_fields = tuple(text_fields) if text_fields is not None else None

    def render_fields(self, form_id: Optional[str] = None, include_css: bool = True) -> str:
        """HTML to place inside the <form>: the honeypot and a fresh token.

        With ``include_css`` the off-screen rule is emitted as an inline
        <style>. If your CSP forbids inline styles, pass False and add
        ``guard.honeypot.css()`` to your stylesheet instead.
        """
        parts = []
        if self.honeypot is not None:
            if include_css:
                parts.append("<style>" + self.honeypot.css() + "</style>")
            parts.append(self.honeypot.render())
        if self.signer is not None:
            token = self.signer.issue(self.form_id if form_id is None else form_id)
            parts.append(
                '<input type="hidden" name="' + self.token_field + '" value="' + token + '">'
            )
        return "".join(parts)

    def check(
        self,
        form: Mapping[str, Any],
        *,
        key: Optional[str] = None,
        form_id: Optional[str] = None,
        text: Optional[str] = None,
    ) -> Decision:
        """Run all checks on a submitted form (any mapping of field to value).

        ``key`` is the rate-limit key (client IP or email). ``text`` overrides
        the text to scan; by default every string field is scanned, except
        the honeypot and token fields (or only ``text_fields`` if given).
        """
        decision = self._run(form, key, self.form_id if form_id is None else form_id, text)
        if not decision.allowed:
            log.info("form blocked: reason=%s check=%s key=%s", decision.reason, decision.check, key)
        return decision

    def _run(self, form: Mapping[str, Any], key: Optional[str], form_id: str, text: Optional[str]) -> Decision:
        if self.limiter is not None and key is not None and not self.limiter.allow(key):
            return Decision(False, "rate_limited", "rate_limit")
        if self.honeypot is not None and self.honeypot.is_filled(form):
            return Decision(False, "honeypot_filled", "honeypot")
        if self.signer is not None:
            raw = form.get(self.token_field)
            result = self.signer.verify(raw if isinstance(raw, str) else None, form_id)
            if not result.ok:
                return Decision(False, result.reason, "token")
        if self.content is not None:
            if text is None:
                if self.text_fields is not None:
                    text = "\n".join(str(form[f]) for f in self.text_fields if f in form)
                else:
                    skip = [self.token_field]
                    if self.honeypot is not None:
                        skip.append(self.honeypot.field_name)
                    text = "\n".join(_values(form, skip))
            finding = self.content.check(text)
            if finding is not None:
                return Decision(False, finding.reason, "content")
        return Decision(True, "ok", "guard")
