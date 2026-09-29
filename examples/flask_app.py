"""Flask contact form protected by form-spam-guard.

Run:  pip install flask
      FSG_SECRET=change-me-to-a-long-random-string flask --app "flask_app:create_app()" run

``spam_protected`` is a decorator. A blocked submission gets the normal
thank-you page (so bots learn nothing) and the reason is logged; the view
itself, which would send the email or store the message, never runs.
"""

from __future__ import annotations

import functools
import logging
import os
from typing import Optional

from flask import Flask, g, request

from form_spam_guard import ContentFilter, Guard, RateLimiter, SQLiteStore

log = logging.getLogger("contact")

THANKS = "<h1>Thank you!</h1><p>We received your message and will reply soon.</p>"


def spam_protected(guard: Guard, thank_you: str = THANKS):
    """Run ``guard`` on request.form before the view; answer bots with ``thank_you``."""

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            decision = guard.check(request.form, key=request.remote_addr)
            g.spam_decision = decision
            if not decision.allowed:
                log.warning("spam blocked: %s (%s)", decision.reason, decision.check)
                return thank_you  # HTTP 200, same page as a real submission
            return view(*args, **kwargs)

        return wrapper

    return decorator


def default_guard() -> Guard:
    return Guard(
        os.environ.get("FSG_SECRET", "dev-only-secret-change-me-please"),
        store=SQLiteStore(os.environ.get("FSG_DB", "nonces.sqlite3")),
        limiter=RateLimiter(capacity=5, refill_per_second=1 / 60),
        content=ContentFilter(allowed_scripts=["latin"], allowed_domains=["example.ca"]),
        form_id="contact",
    )


def create_app(guard: Optional[Guard] = None) -> Flask:
    guard = guard or default_guard()
    app = Flask(__name__)

    @app.get("/")
    def show_form():
        return (
            '<form method="post" action="/contact">'
            '<input name="name"><textarea name="message"></textarea>'
            + guard.render_fields()
            + "<button>Send</button></form>"
        )

    @app.post("/contact")
    @spam_protected(guard)
    def contact():
        log.info("real message from %s", request.form.get("name"))
        # send_email(request.form) / save_message(request.form) goes here
        return THANKS

    return app
