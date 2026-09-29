"""FastAPI contact form protected by form-spam-guard.

Run:  pip install fastapi uvicorn python-multipart
      FSG_SECRET=change-me-to-a-long-random-string uvicorn --factory fastapi_app:create_app

The guard runs as a dependency. A blocked submission gets the normal thank-you
page (so bots learn nothing) and the reason is logged; no email is sent.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse

from form_spam_guard import ContentFilter, Decision, Guard, RateLimiter, SQLiteStore

log = logging.getLogger("contact")

THANKS = "<h1>Thank you!</h1><p>We received your message and will reply soon.</p>"


def default_guard() -> Guard:
    return Guard(
        os.environ.get("FSG_SECRET", "dev-only-secret-change-me-please"),
        store=SQLiteStore(os.environ.get("FSG_DB", "nonces.sqlite3")),
        limiter=RateLimiter(capacity=5, refill_per_second=1 / 60),
        content=ContentFilter(allowed_scripts=["latin"], allowed_domains=["example.ca"]),
        form_id="contact",
    )


def create_app(guard: Optional[Guard] = None) -> FastAPI:
    guard = guard or default_guard()
    app = FastAPI()

    async def spam_decision(request: Request) -> Decision:
        form = await request.form()
        client = request.client.host if request.client else None
        return guard.check(dict(form), key=client)

    @app.get("/", response_class=HTMLResponse)
    def show_form() -> str:
        return (
            '<form method="post" action="/contact">'
            '<input name="name"><textarea name="message"></textarea>'
            + guard.render_fields()
            + '<button>Send</button></form>'
        )

    @app.post("/contact", response_class=HTMLResponse)
    async def contact(request: Request, decision: Decision = Depends(spam_decision)) -> str:
        if not decision.allowed:
            log.warning("spam blocked: %s (%s)", decision.reason, decision.check)
            return THANKS  # same page as a real submission
        form = await request.form()
        log.info("real message from %s", form.get("name"))
        # send_email(form) / save_message(form) goes here
        return THANKS

    return app
