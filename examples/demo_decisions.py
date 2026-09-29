"""Run sample submissions through a Guard, entirely offline, and print a table.

    python examples/demo_decisions.py

Time is simulated with a fake clock, so nothing sleeps and nothing touches the
network. No request is sent anywhere.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from form_spam_guard import ContentFilter, Guard, InMemoryStore, RateLimiter  # noqa: E402

SECRET = "demo-secret-not-for-production"

SPAM_RU = (
    "\u0412\u0430\u043c \u043f\u0435\u0440\u0435\u0432\u043e\u0434 193155 "
    "\u0440\u0443\u0431. \u0437\u0430\u0431\u0440\u0430\u0442\u044c \u0442\u0443\u0442 "
    "https://5d58cc63.sslip.io/x"
)
SPAM_RU_LATIN = "Vam perevod 193155 rub. zabrat tut https://5d58cc63.sslip.io/x"
FRENCH = "Bonjour, je m'appelle H\u00e9l\u00e8ne Th\u00e9riault, je voudrais une soumission pour un site web."
ENGLISH = "Hi, I would like a quote for a new website for my bakery. Please call me this week."
OWN_SITE = "Hello, my current site is https://boulangerie-leblanc.ca and I want it refreshed."
MANY_LINKS = "cheap seo http://a.example.org http://b.example.org http://c.example.org"
TUNNEL = "Check the photos here https://abc123.ngrok-free.app/pics"
CJK = "\u4f60\u597d\uff0c\u6211\u60f3\u4e70\u4f60\u4eec\u7684\u4ea7\u54c1\uff0c\u8bf7\u8054\u7cfb\u6211"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def main() -> None:
    clock = FakeClock()
    guard = Guard(
        SECRET,
        clock=clock,
        store=InMemoryStore(),
        limiter=RateLimiter(capacity=3, refill_per_second=0, clock=clock),
        content=ContentFilter(
            allowed_scripts=["latin"],
            allowed_domains=["boulangerie-leblanc.ca"],
            max_links=2,
        ),
    )

    def page_token() -> str:
        html = guard.render_fields()
        return html.split('name="fsg_token" value="')[1].split('"')[0]

    def form(message: str, **extra: str) -> dict:
        data = {"name": "Demo", "message": message, "website": "", "fsg_token": page_token()}
        data.update(extra)
        return data

    rows = []

    def run(label: str, data: dict, wait: float = 10.0, key: str = "203.0.113.7") -> None:
        clock.now += wait
        d = guard.check(data, key=key)
        rows.append((label, d.allowed, d.reason))

    run("English enquiry", form(ENGLISH), key="198.51.100.1")
    run("French name with accents", form(FRENCH), key="198.51.100.2")
    run("Link to customer's own site", form(OWN_SITE), key="198.51.100.3")
    run("Russian spam + sslip.io link", form(SPAM_RU), key="192.0.2.10")
    run("Latin-script version of same spam", form(SPAM_RU_LATIN), key="192.0.2.11")
    run("Chinese text", form(CJK), key="192.0.2.12")
    run("ngrok tunnel link", form(TUNNEL), key="192.0.2.13")
    run("Too many links", form(MANY_LINKS), key="192.0.2.14")
    run("Honeypot field filled", form(ENGLISH, website="http://spam.example"), key="192.0.2.15")
    run("Submitted after 0.4 s", form(ENGLISH), wait=0.4, key="192.0.2.16")
    run("Token expired (3 h)", form(ENGLISH), wait=3 * 3600, key="192.0.2.17")

    tampered = form(ENGLISH)
    tampered["fsg_token"] = "A" + tampered["fsg_token"][1:]
    run("Tampered token", tampered, key="192.0.2.18")

    missing = form(ENGLISH)
    del missing["fsg_token"]
    run("No token at all", missing, key="192.0.2.19")

    replay = form(ENGLISH)
    run("Token used once", replay, key="192.0.2.20")
    run("Same token used again", replay, wait=1.0, key="192.0.2.20")

    for i in range(1, 5):
        run("Same IP, message %d" % i, form(ENGLISH), key="192.0.2.99")

    width = max(len(r[0]) for r in rows)
    rwidth = max(len(r[2]) for r in rows)
    print("%-*s  %-7s  %s" % (width, "sample", "allowed", "reason"))
    print("%s  %s  %s" % ("-" * width, "-" * 7, "-" * rwidth))
    for label, allowed, reason in rows:
        print("%-*s  %-7s  %s" % (width, label, "yes" if allowed else "no", reason))


if __name__ == "__main__":
    main()
