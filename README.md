# form-spam-guard

CAPTCHA-free spam protection for web forms: a **honeypot**, a **signed timestamp token**, a **content filter** and a **per-key rate limiter**, combined behind one `Guard` that returns a machine-readable `Decision`.

```python
from form_spam_guard import Guard, ContentFilter

guard = Guard("a-long-random-secret", content=ContentFilter(allowed_domains=["mysite.ca"]))

html = guard.render_fields()            # put inside your <form>
d = guard.check(request_form, key=client_ip)
d.allowed, d.reason, d.check            # (False, 'foreign_script', 'content')
```

Why another spam filter:

- **CAPTCHAs hurt real customers.** A baker in Miramichi who loses a quote request because a visitor could not read distorted letters loses money. Small-business contact forms get a steady stream of bot spam (foreign-language "you have a transfer" messages pointing at throwaway tunnel hosts), and most of it is easy to spot without bothering anyone.
- **Layers that cost the visitor nothing.** A hidden field, a form that cannot be posted in under 3 seconds, text in a script your site does not use, and links to hosts nobody legitimate uses in a contact form.
- **Reasons, not just yes/no.** `honeypot_filled`, `too_fast`, `token_expired`, `token_replayed`, `bad_signature`, `foreign_script`, `blocked_link_host`, `too_many_links`, `rate_limited`: easy to log, count and tune.
- **No dependencies.** Standard library only, Python 3.10+. Flask and FastAPI are optional and only used by the examples.

## Install

```
pip install .            # from a checkout; core is stdlib only
pip install .[flask]     # only to run examples/flask_app.py
pip install .[fastapi]   # only to run examples/fastapi_app.py
```

## Usage

### Core

```python
from form_spam_guard import (
    Guard, Honeypot, ContentFilter, RateLimiter, SQLiteStore,
)

guard = Guard(
    "a-long-random-secret",                  # same value in every worker
    store=SQLiteStore("nonces.sqlite3"),     # optional: each token works once
    limiter=RateLimiter(capacity=5, refill_per_second=1 / 60),
    honeypot=Honeypot(field_name="website"),
    content=ContentFilter(
        allowed_scripts=["latin"],           # English/French site
        allowed_domains=["mysite.ca", "customer-site.ca"],
        blocked_hosts=["my-own-blocklisted.example"],   # extends the built-in list
        max_links=2,
    ),
    min_age=3, max_age=2 * 3600,
)

form_html = guard.render_fields()   # hidden decoy field + signed token input
decision = guard.check(form, key=client_ip)
```

Order of checks: rate limit, honeypot, token, content. The first failure wins. Every layer also works on its own: `Honeypot`, `TokenSigner(secret).issue()/.verify()`, `ContentFilter.findings(text)` (lists all problems, not just the first), `RateLimiter.allow(key)`.

What each layer does:

- **Honeypot.** A field with a real-looking name (`website`), hidden off-screen by CSS class, with `tabindex="-1"` and `autocomplete="off"`. Any value means a bot. Use `guard.honeypot.css()` in your stylesheet if your CSP blocks inline styles (`render_fields(include_css=False)`).
- **Token.** HMAC-SHA256 over the issue time, a random nonce and an optional form id, URL-safe base64, checked with `hmac.compare_digest`. Rejected when younger than `min_age`, older than `max_age`, altered, or (with a store) used twice.
- **Content.** Share of letters in scripts you did not allow (Cyrillic, CJK, Arabic... over `max_foreign_ratio`, default 30%); links to tunnel, wildcard-DNS and shortener hosts (`sslip.io`, `nip.io`, `xip.io`, `ngrok.io`, `ngrok-free.app`, `trycloudflare.com`, `loca.lt`, `bit.ly`, `tinyurl.com`, `t.me`, `telegra.ph`, `cutt.ly`, `is.gd` and more, with suffix matching so `*.sslip.io` is caught); too many links; and an allowlist of your own domains, whose links are always fine.
- **Rate limit.** Token bucket per key (IP or email), thread-safe, injectable clock.

### Flask

`examples/flask_app.py` has a `spam_protected(guard)` decorator:

```python
@app.post("/contact")
@spam_protected(guard)
def contact():
    send_email(request.form)      # only runs for real messages
    return THANKS
```

### FastAPI

`examples/fastapi_app.py` has the guard as a dependency:

```python
@app.post("/contact")
async def contact(request: Request, decision: Decision = Depends(spam_decision)):
    if not decision.allowed:
        log.warning("spam blocked: %s", decision.reason)
        return THANKS
    ...
```

Both examples are tested with the framework's own test client and skipped when the framework is not installed.

## The recommended pattern: answer bots with "thank you"

When a submission is blocked, **do not show an error.** Return the same "thank you" page a real visitor gets, log `decision.reason`, and skip the side effects (no email, nothing stored). A bot that sees an error retries with something different; a bot that sees success moves on. A real customer who trips a filter by accident is not confronted with an accusation (and the log tells you to tune the rules).

```python
decision = guard.check(form, key=ip)
if not decision.allowed:
    logger.info("blocked: %s", decision.reason)   # never log the message body
    return thank_you_page()                        # same page, HTTP 200
send_email(form)
```

## Measured result

`python examples/demo_decisions.py` runs sample submissions through a `Guard` locally, with a fake clock. No network, nothing is posted anywhere:

```
$ python examples/demo_decisions.py
sample                             allowed  reason
---------------------------------  -------  -----------------
English enquiry                    yes      ok
French name with accents           yes      ok
Link to customer's own site        yes      ok
Russian spam + sslip.io link       no       foreign_script
Latin-script version of same spam  no       blocked_link_host
Chinese text                       no       foreign_script
ngrok tunnel link                  no       blocked_link_host
Too many links                     no       too_many_links
Honeypot field filled              no       honeypot_filled
Submitted after 0.4 s              no       too_fast
Token expired (3 h)                no       token_expired
Tampered token                     no       bad_signature
No token at all                    no       missing_token
Token used once                    yes      ok
Same token used again              no       token_replayed
Same IP, message 1                 yes      ok
Same IP, message 2                 yes      ok
Same IP, message 3                 yes      ok
Same IP, message 4                 no       rate_limited

$ python -m pytest -q
88 passed, 2 skipped in 1.04s (the 2 skips are the Flask example tests when Flask is not installed)
```

The tests include the real spam message (a Cyrillic "you have a transfer of 193155 rub, collect it here" pointing at an `sslip.io` host), which is blocked both for foreign script and for the blocked link host, and real customer messages that must pass: French names with accents (Helene Theriault with accents), an English enquiry, and a message linking to the customer's own site.

## Limitations

- **A determined human spammer gets through.** This stops bots and drive-by spam, not a person who opens the page, waits, and types a clean message. Add moderation or an email review step if that matters.
- **A shared secret is needed across workers.** Every process (and every server) must use the same `secret`, or tokens issued by one will fail on another. Keep it out of the repository (environment variable).
- **The in-memory store is per process.** Replay protection with `InMemoryStore` only works inside one process; with several workers use `SQLiteStore` on a shared disk, or implement `NonceStore` on top of Redis or your database. Without any store, tokens are not single-use (age checks and signatures still apply).
- **The rate limiter is per process too.** Buckets live in memory.
- **The script filter is a heuristic.** A Latin-only setting rejects genuine Cyrillic or Chinese messages; list the scripts you serve in `allowed_scripts`. Very short texts are not judged by script.
- **Links are found with a regex,** not a full parser: `scheme://` and `www.` URLs, plus bare blocked hosts such as `bit.ly/abc`.
- The honeypot decoy is marked `aria-hidden` and skipped by the keyboard, but if your CSS fails to load it becomes a visible field.

## Author

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
