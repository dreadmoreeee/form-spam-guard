"""Signed timestamp tokens (HMAC-SHA256, URL-safe base64)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Optional, Union

from .stores import NonceStore

_PREFIX = b"fsg1\x00"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


@dataclass(frozen=True)
class TokenResult:
    ok: bool
    reason: str = "ok"


class TokenSigner:
    """Issues and verifies form tokens.

    A token binds the issue time, a random nonce and an optional ``form_id``
    under an HMAC. On verification:

    * a bad or altered token gives ``bad_signature`` (``missing_token`` if empty),
    * younger than ``min_age`` seconds gives ``too_fast``,
    * older than ``max_age`` seconds gives ``token_expired``,
    * with a ``store`` set, a second use of the same token gives ``token_replayed``.

    The nonce is only consumed by a submission that passed every other check.
    """

    def __init__(
        self,
        secret: Union[str, bytes],
        *,
        min_age: float = 3.0,
        max_age: float = 7200.0,
        store: Optional[NonceStore] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(key) < 16:
            raise ValueError("secret must be at least 16 bytes long")
        if min_age < 0 or max_age <= min_age:
            raise ValueError("need 0 <= min_age < max_age")
        self._key = key
        self.min_age = min_age
        self.max_age = max_age
        self.store = store
        self._clock = clock

    def _sign(self, payload: bytes, form_id: str) -> bytes:
        msg = _PREFIX + payload + b"\x00" + form_id.encode("utf-8")
        return hmac.new(self._key, msg, hashlib.sha256).digest()

    def issue(self, form_id: str = "") -> str:
        issued_ms = int(self._clock() * 1000)
        nonce = secrets.token_hex(12)
        payload = ("%d:%s" % (issued_ms, nonce)).encode("ascii")
        return _b64e(payload) + "." + _b64e(self._sign(payload, form_id))

    def verify(self, token: Optional[str], form_id: str = "") -> TokenResult:
        if not token:
            return TokenResult(False, "missing_token")
        try:
            payload_part, sig_part = token.strip().split(".")
            payload = _b64d(payload_part)
            sig = _b64d(sig_part)
        except (ValueError, binascii.Error, UnicodeError):
            return TokenResult(False, "bad_signature")
        if not hmac.compare_digest(sig, self._sign(payload, form_id)):
            return TokenResult(False, "bad_signature")
        try:
            issued_text, nonce = payload.decode("ascii").split(":", 1)
            issued = int(issued_text) / 1000.0
        except (ValueError, UnicodeError):
            return TokenResult(False, "bad_signature")

        now = self._clock()
        age = now - issued
        if age < self.min_age:
            return TokenResult(False, "too_fast")
        if age > self.max_age:
            return TokenResult(False, "token_expired")
        if self.store is not None:
            if not self.store.add_if_new(nonce, issued + self.max_age, now):
                return TokenResult(False, "token_replayed")
        return TokenResult(True)
