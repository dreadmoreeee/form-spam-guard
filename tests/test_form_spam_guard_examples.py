import importlib.util
import logging
import pathlib
import subprocess
import sys

import pytest

from form_spam_guard import ContentFilter, Guard, InMemoryStore

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"
SECRET = "example-test-secret-0123456789"

SPAM = (
    "\u0412\u0430\u043c \u043f\u0435\u0440\u0435\u0432\u043e\u0434 193155 "
    "\u0440\u0443\u0431. \u0437\u0430\u0431\u0440\u0430\u0442\u044c \u0442\u0443\u0442 "
    "https://5d58cc63.sslip.io/x"
)


def load(name):
    spec = importlib.util.spec_from_file_location("example_" + name, EXAMPLES / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


def make_guard(clock):
    return Guard(SECRET, clock=clock, store=InMemoryStore(), content=ContentFilter(), form_id="contact")


def token_from(html):
    return html.split('name="fsg_token" value="')[1].split('"')[0]


def test_demo_runs_offline_and_prints_table():
    out = subprocess.run(
        [sys.executable, str(EXAMPLES / "demo_decisions.py")],
        capture_output=True, text=True, check=True, timeout=60,
    ).stdout
    assert "sample" in out and "allowed" in out and "reason" in out
    for reason in ("foreign_script", "honeypot_filled", "too_fast", "token_expired",
                   "token_replayed", "bad_signature", "too_many_links", "rate_limited",
                   "blocked_link_host"):
        assert reason in out, reason
    assert out.isascii()


def test_flask_example(caplog):
    pytest.importorskip("flask")
    caplog.set_level(logging.INFO, logger="contact")
    mod = load("flask_app")
    clock = Clock()
    guard = make_guard(clock)
    client = mod.create_app(guard).test_client()

    page = client.get("/").get_data(as_text=True)
    assert 'name="website"' in page
    token = token_from(page)
    clock.t += 10
    ok = client.post("/contact", data={"name": "A", "message": "Hello, a quote please", "fsg_token": token, "website": ""})
    assert ok.status_code == 200 and "Thank you" in ok.get_data(as_text=True)

    token2 = token_from(client.get("/").get_data(as_text=True))
    clock.t += 10
    spam = client.post("/contact", data={"name": "A", "message": SPAM, "fsg_token": token2, "website": ""})
    assert spam.status_code == 200 and "Thank you" in spam.get_data(as_text=True)
    assert "real message" in caplog.text and caplog.text.count("spam blocked: foreign_script") == 1


def test_flask_decorator_blocks_view():
    flask = pytest.importorskip("flask")
    mod = load("flask_app")
    clock = Clock()
    guard = make_guard(clock)
    app = flask.Flask(__name__)
    calls = []

    @app.post("/c")
    @mod.spam_protected(guard)
    def view():
        calls.append(1)
        return "sent"

    client = app.test_client()
    token = token_from(guard.render_fields())
    clock.t += 10
    client.post("/c", data={"message": "hello there", "fsg_token": token, "website": "x"})
    assert calls == []
    token = token_from(guard.render_fields())
    clock.t += 10
    res = client.post("/c", data={"message": "hello there", "fsg_token": token, "website": ""})
    assert calls == [1] and res.get_data(as_text=True) == "sent"


def test_fastapi_example(caplog):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("multipart")
    from fastapi.testclient import TestClient

    caplog.set_level(logging.INFO, logger="contact")
    mod = load("fastapi_app")
    clock = Clock()
    guard = make_guard(clock)
    client = TestClient(mod.create_app(guard))

    token = token_from(client.get("/").text)
    clock.t += 10
    ok = client.post("/contact", data={"name": "A", "message": "Hello, a quote please", "fsg_token": token, "website": ""})
    assert ok.status_code == 200 and "Thank you" in ok.text

    token2 = token_from(client.get("/").text)
    clock.t += 10
    spam = client.post("/contact", data={"name": "A", "message": SPAM, "fsg_token": token2, "website": ""})
    assert spam.status_code == 200 and "Thank you" in spam.text
    assert caplog.text.count("real message") == 1
    assert caplog.text.count("spam blocked: foreign_script") == 1
