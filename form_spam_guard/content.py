"""Content filter: foreign scripts, blocked link hosts, too many links."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set
from urllib.parse import urlsplit

# Script names as they appear as the first word of unicodedata.name().
_KNOWN_SCRIPTS = frozenset(
    """
    LATIN CYRILLIC GREEK ARABIC HEBREW CJK HIRAGANA KATAKANA HANGUL BOPOMOFO
    DEVANAGARI THAI ARMENIAN GEORGIAN BENGALI TAMIL ETHIOPIC KHMER LAO TIBETAN
    MYANMAR SINHALA GUJARATI GURMUKHI TELUGU KANNADA MALAYALAM ORIYA SYRIAC
    THAANA MONGOLIAN CHEROKEE CANADIAN
    """.split()
)

# Friendly names accepted in ``allowed_scripts``.
_ALIASES = {
    "han": {"CJK"},
    "chinese": {"CJK", "BOPOMOFO"},
    "japanese": {"CJK", "HIRAGANA", "KATAKANA"},
    "korean": {"HANGUL", "CJK"},
    "syllabics": {"CANADIAN"},
    "canadian_aboriginal": {"CANADIAN"},
}

DEFAULT_BLOCKED_HOSTS = (
    # wildcard DNS
    "sslip.io",
    "nip.io",
    "xip.io",
    "traefik.me",
    # tunnels
    "ngrok.io",
    "ngrok.app",
    "ngrok.dev",
    "ngrok-free.app",
    "ngrok-free.dev",
    "trycloudflare.com",
    "loca.lt",
    "localhost.run",
    "serveo.net",
    # shorteners and anonymous publishing
    "bit.ly",
    "bit.do",
    "tinyurl.com",
    "cutt.ly",
    "is.gd",
    "v.gd",
    "tiny.cc",
    "rb.gy",
    "shorturl.at",
    "t.me",
    "telegra.ph",
)

_SCHEME_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'\]\[)(]+")
_BARE_HOST = re.compile(
    r"(?i)(?<![\w@.\-])((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,})(?::\d+)?(?:/[^\s]*)?"
)


def _host_matches(host: str, domains: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _normalize_domain(value: str) -> str:
    d = value.strip().lower().rstrip(".")
    if "//" in d:
        d = urlsplit(d).hostname or d
    return d[2:] if d.startswith("*.") else d


def _script_of(ch: str) -> Optional[str]:
    """Script name of a letter, or None for letters we do not classify."""
    if not ch.isalpha():
        return None
    first = unicodedata.name(ch, "").split(" ", 1)[0]
    return first if first in _KNOWN_SCRIPTS else None


@dataclass(frozen=True)
class Finding:
    reason: str
    detail: str = ""


class ContentFilter:
    """Checks free text for typical form spam.

    * ``allowed_scripts``: scripts your site uses (``["latin"]`` for English
      and French). If letters in any other script exceed ``max_foreign_ratio``
      of all classified letters, the text is flagged ``foreign_script``.
      Names: ``latin``, ``cyrillic``, ``greek``, ``arabic``, ``hebrew``,
      ``cjk``, ``chinese``, ``japanese``, ``korean``, ``devanagari``, ``thai``,
      ``syllabics`` ... (any first word of a Unicode character name works).
    * links whose host is, or is a subdomain of, a blocked host give
      ``blocked_link_host``. ``blocked_hosts`` extends the built-in list.
    * more than ``max_links`` links give ``too_many_links``.
    * links to ``allowed_domains`` (and subdomains) are ignored by the two
      link checks, so your own site and your customers' sites are fine.
    """

    def __init__(
        self,
        allowed_scripts: Sequence[str] = ("latin",),
        max_foreign_ratio: float = 0.3,
        min_letters: int = 4,
        blocked_hosts: Iterable[str] = (),
        use_default_blocked_hosts: bool = True,
        allowed_domains: Iterable[str] = (),
        max_links: int = 2,
        check_scripts: bool = True,
    ) -> None:
        allowed: Set[str] = set()
        for name in allowed_scripts:
            key = name.strip().lower()
            allowed |= _ALIASES.get(key, {key.upper()})
        self.allowed_scripts = frozenset(allowed)
        self.max_foreign_ratio = max_foreign_ratio
        self.min_letters = min_letters
        self.check_scripts = check_scripts
        self.max_links = max_links
        hosts = list(DEFAULT_BLOCKED_HOSTS) if use_default_blocked_hosts else []
        hosts += list(blocked_hosts)
        self.blocked_hosts = tuple(sorted({_normalize_domain(h) for h in hosts}))
        self.allowed_domains = tuple(sorted({_normalize_domain(d) for d in allowed_domains}))

    # -- scripts ---------------------------------------------------------

    def foreign_ratio(self, text: str) -> float:
        """Share (0..1) of classified letters outside the allowed scripts.

        URLs are ignored so a link's host name does not count as text.
        """
        text = _SCHEME_URL.sub(" ", text)
        total = foreign = 0
        for ch in text:
            script = _script_of(ch)
            if script is None:
                continue
            total += 1
            if script not in self.allowed_scripts:
                foreign += 1
        if total < self.min_letters:
            return 0.0
        return foreign / total

    # -- links -----------------------------------------------------------

    def extract_hosts(self, text: str) -> List[str]:
        """Host names of links in ``text`` (scheme/www URLs, plus bare blocked hosts)."""
        hosts: List[str] = []
        for match in _SCHEME_URL.finditer(text):
            url = match.group(0).rstrip(".,;:!?")
            if not url.lower().startswith(("http://", "https://")):
                url = "http://" + url
            try:
                host = urlsplit(url).hostname
            except ValueError:
                continue
            if host:
                hosts.append(host.lower().rstrip("."))
        rest = _SCHEME_URL.sub(" ", text)
        for match in _BARE_HOST.finditer(rest):
            host = match.group(1).lower()
            if _host_matches(host, self.blocked_hosts):
                hosts.append(host)
        return hosts

    def findings(self, text: str) -> List[Finding]:
        """Every problem found in ``text``, in check order."""
        out: List[Finding] = []
        if self.check_scripts and self.allowed_scripts:
            ratio = self.foreign_ratio(text)
            if ratio > self.max_foreign_ratio:
                out.append(Finding("foreign_script", "foreign letters %.0f%%" % (ratio * 100)))
        counted = [h for h in self.extract_hosts(text) if not _host_matches(h, self.allowed_domains)]
        for host in counted:
            if _host_matches(host, self.blocked_hosts):
                out.append(Finding("blocked_link_host", host))
                break
        if len(counted) > self.max_links:
            out.append(Finding("too_many_links", "%d links" % len(counted)))
        return out

    def check(self, text: str) -> Optional[Finding]:
        """The first problem found, or None when the text looks fine."""
        found = self.findings(text)
        return found[0] if found else None
