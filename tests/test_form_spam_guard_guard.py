import logging

import pytest

from form_spam_guard import ContentFilter, Decision, Guard, Honeypot, InMemoryStore, RateLimiter, SQLiteStore

SECRET = "guard-test-secret-0123456789"

SPAM = (
    "\u0412\u0430\u043c \u043f\u0435\u0440\u0435\u0432\u043e\u0434 193155 "
    "\u0440\u0443\u0431. \u0437\u0430\u0431\u0440\u0430\u0442\u044c \u0442\u0443\u0442 "
    "https://5d58cc63.sslip.io/x"
)


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


def build(clock, **kw):
    kw.setdefault("store", InMemoryStore())
    kw.setdefault("content", ContentFilter(allowed_domains=["boulangerie-leblanc.ca"]))
    return Guard(SECRET, clock=clock, **kw)


def submit(guard, clock, message, wait=10, **extra):
    """Render the form, wait, and return the form data a browser would post."""
    fields = guard.render_fields()
    token = fields.split('name="fsg_token" value="')[1].split('"')[0]
    clock.t += wait
    data = {"name": "Test", "message": message, "fsg_token": token, "website": ""}
    data.update(extra)
    return data


def test_decision_shape():
    d = Decision(True, "ok", "guard")
    assert d.allowed and bool(d)
    assert not Decision(False, "too_fast", "token")


def test_spam_sample_blocked_by_guard(clock):
    g = build(clock)
    d = g.check(submit(g, clock, SPAM))
    assert d == Decision(False, "foreign_script", "content")


def test_spam_blocked_for_link_host_when_scripts_allowed(clock):
    g = build(clock, content=ContentFilter(allowed_scripts=["latin", "cyrillic"]))
    d = g.check(submit(g, clock, SPAM))
    assert (d.allowed, d.reason) == (False, "blocked_link_host")


def test_real_customers_pass(clock):
    g = build(clock)
    samples = [
        "Bonjour, je m'appelle H\u00e9l\u00e8ne Th\u00e9riault et je cherche un site pour ma boutique.",
        "Hello, we need a quote for a website redesign. Thanks!",
        "Hi, our current site is https://boulangerie-leblanc.ca and it needs an update.",
    ]
    for msg in samples:
        d = g.check(submit(g, clock, msg))
        assert d == Decision(True, "ok", "guard"), msg


def test_honeypot_filled(clock):
    g = build(clock)
    d = g.check(submit(g, clock, "Hello there friend", website="http://x.example"))
    assert d == Decision(False, "honeypot_filled", "honeypot")


def test_too_fast(clock):
    g = build(clock)
    d = g.check(submit(g, clock, "Hello there friend", wait=0.5))
    assert d == Decision(False, "too_fast", "token")


def test_expired(clock):
    g = build(clock)
    d = g.check(submit(g, clock, "Hello there friend", wait=3 * 3600))
    assert d.reason == "token_expired"


def test_missing_and_tampered_token(clock):
    g = build(clock)
    data = submit(g, clock, "Hello there friend")
    data.pop("fsg_token")
    assert g.check(data).reason == "missing_token"
    data["fsg_token"] = "x" + submit(g, clock, "hi")["fsg_token"]
    assert g.check(data).reason == "bad_signature"


def test_replay_with_sqlite_store(clock, tmp_path):
    store = SQLiteStore(str(tmp_path / "n.sqlite3"))
    try:
        g = build(clock, store=store)
        data = submit(g, clock, "Hello there friend")
        assert g.check(data).allowed
        d = g.check(data)
        assert (d.allowed, d.reason) == (False, "token_replayed")
    finally:
        store.close()


def test_form_id_mismatch(clock):
    g = build(clock, form_id="contact")
    data = submit(g, clock, "Hello there friend")
    assert g.check(data).allowed is True
    data2 = submit(g, clock, "Hello there friend")
    assert g.check(data2, form_id="other").reason == "bad_signature"


def test_rate_limited_first(clock):
    limiter = RateLimiter(capacity=2, refill_per_second=0, clock=clock)
    g = build(clock, limiter=limiter)
    results = [g.check(submit(g, clock, "Hello there friend"), key="9.9.9.9") for _ in range(3)]
    assert [r.allowed for r in results] == [True, True, False]
    assert results[2] == Decision(False, "rate_limited", "rate_limit")
    assert g.check(submit(g, clock, "Hello there friend"), key="8.8.8.8").allowed


def test_too_many_links(clock):
    g = build(clock, content=ContentFilter(max_links=2))
    msg = "see https://a.example.com https://b.example.com https://c.example.com"
    assert g.check(submit(g, clock, msg)).reason == "too_many_links"


def test_without_secret_token_layer_is_off():
    g = Guard()
    assert g.check({"message": "Hello there friend"}).allowed
    assert g.check({"message": "x", "website": "spam"}).reason == "honeypot_filled"
    assert 'fsg_token' not in g.render_fields()


def test_honeypot_field_is_not_scanned_as_text():
    g = Guard(honeypot=Honeypot("company"), content=ContentFilter(max_links=0))
    assert g.check({"message": "hello", "company": ""}).allowed


def test_text_fields_restricts_scanning(clock):
    g = build(clock, text_fields=["message"])
    data = submit(g, clock, "Hello there friend", name="\u0412\u0430\u043c \u043f\u0435\u0440\u0435\u0432\u043e\u0434")
    assert g.check(data).allowed


def test_multivalue_form_objects(clock):
    class Multi(dict):
        def getlist(self, key):
            v = self[key]
            return v if isinstance(v, list) else [v]

    g = build(clock)
    data = Multi(submit(g, clock, ["fine text here", SPAM]))
    assert g.check(data).reason == "foreign_script"


def test_blocked_submission_is_logged_without_content(clock, caplog):
    g = build(clock)
    with caplog.at_level(logging.INFO, logger="form_spam_guard"):
        g.check(submit(g, clock, SPAM), key="1.2.3.4")
    assert "reason=foreign_script" in caplog.text
    assert "sslip" not in caplog.text


def test_render_fields_contains_honeypot_and_token(clock):
    html = build(clock).render_fields()
    assert 'name="website"' in html and 'name="fsg_token"' in html
    assert html.startswith("<style>")
    assert not build(clock).render_fields(include_css=False).startswith("<style>")
