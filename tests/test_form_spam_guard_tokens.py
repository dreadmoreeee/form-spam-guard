import threading

import pytest

from form_spam_guard import InMemoryStore, SQLiteStore, TokenSigner

SECRET = "unit-test-secret-0123456789"


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def make(clock=None, **kw):
    clock = clock or Clock()
    return TokenSigner(SECRET, clock=clock, **kw), clock


def test_valid_token_after_min_age():
    signer, clock = make(min_age=3, max_age=7200)
    token = signer.issue()
    clock.advance(10)
    assert signer.verify(token).ok


def test_token_is_urlsafe_ascii():
    signer, _ = make()
    token = signer.issue("contact")
    assert token.isascii()
    assert all(c.isalnum() or c in "-_." for c in token)


def test_too_fast():
    signer, clock = make(min_age=3)
    token = signer.issue()
    clock.advance(1.0)
    res = signer.verify(token)
    assert (res.ok, res.reason) == (False, "too_fast")
    clock.advance(2.5)
    assert signer.verify(token).ok


def test_expired():
    signer, clock = make(min_age=3, max_age=7200)
    token = signer.issue()
    clock.advance(7201)
    res = signer.verify(token)
    assert (res.ok, res.reason) == (False, "token_expired")


def test_token_from_the_future_is_too_fast():
    signer, clock = make()
    token = signer.issue()
    clock.advance(-100)
    assert signer.verify(token).reason == "too_fast"


def test_missing_token():
    signer, _ = make()
    assert signer.verify(None).reason == "missing_token"
    assert signer.verify("").reason == "missing_token"


@pytest.mark.parametrize("junk", ["abc", "a.b.c", "....", "!!!.???", "\u00e9.\u00e9", "MTox.AAAA"])
def test_malformed_tokens(junk):
    signer, _ = make()
    assert signer.verify(junk).reason == "bad_signature"


def test_tampered_payload_and_signature():
    signer, clock = make()
    token = signer.issue()
    clock.advance(10)
    payload, sig = token.split(".")
    flipped = ("A" if payload[0] != "A" else "B") + payload[1:]
    assert signer.verify(flipped + "." + sig).reason == "bad_signature"
    flipped_sig = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
    assert signer.verify(payload + "." + flipped_sig).reason == "bad_signature"
    assert signer.verify(sig + "." + payload).reason == "bad_signature"


def test_forged_earlier_timestamp_is_rejected():
    signer, clock = make(min_age=3, max_age=7200)
    token = signer.issue()
    clock.advance(10_000)
    # An attacker rewrites the issue time to look fresh; the signature no longer matches.
    import base64
    payload, sig = token.split(".")
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
    _, nonce = raw.split(":")
    fake = base64.urlsafe_b64encode(("%d:%s" % (int((clock.t - 100) * 1000), nonce)).encode()).rstrip(b"=")
    assert signer.verify(fake.decode() + "." + sig).reason == "bad_signature"


def test_wrong_secret():
    a, clock = make()
    b = TokenSigner("another-secret-0123456789", clock=clock)
    token = a.issue()
    clock.advance(10)
    assert b.verify(token).reason == "bad_signature"


def test_form_id_binding():
    signer, clock = make()
    token = signer.issue("contact")
    clock.advance(10)
    assert signer.verify(token, "newsletter").reason == "bad_signature"
    assert signer.verify(token, "contact").ok
    assert signer.verify(token).reason == "bad_signature"


def test_short_secret_rejected():
    with pytest.raises(ValueError):
        TokenSigner("short")


def test_bad_ages_rejected():
    with pytest.raises(ValueError):
        TokenSigner(SECRET, min_age=10, max_age=5)


def test_no_store_means_reuse_is_allowed():
    signer, clock = make()
    token = signer.issue()
    clock.advance(10)
    assert signer.verify(token).ok
    assert signer.verify(token).ok


# -- replay ---------------------------------------------------------------


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        yield InMemoryStore()
    else:
        s = SQLiteStore(str(tmp_path / "nonces.sqlite3"))
        yield s
        s.close()


def test_replay_is_detected(store):
    signer, clock = make(store=store)
    token = signer.issue()
    clock.advance(10)
    assert signer.verify(token).ok
    res = signer.verify(token)
    assert (res.ok, res.reason) == (False, "token_replayed")


def test_two_tokens_are_independent(store):
    signer, clock = make(store=store)
    t1, t2 = signer.issue(), signer.issue()
    clock.advance(10)
    assert signer.verify(t1).ok
    assert signer.verify(t2).ok


def test_too_fast_does_not_burn_the_nonce(store):
    signer, clock = make(store=store, min_age=3)
    token = signer.issue()
    clock.advance(1)
    assert signer.verify(token).reason == "too_fast"
    clock.advance(5)
    assert signer.verify(token).ok


def test_cleanup_removes_expired(store):
    signer, clock = make(store=store, max_age=100)
    for _ in range(5):
        signer.issue()
    tokens = [signer.issue() for _ in range(3)]
    clock.advance(10)
    for t in tokens:
        assert signer.verify(t).ok
    assert len(store) == 3
    assert store.cleanup(clock.t + 1000) == 3
    assert len(store) == 0


def test_add_if_new_is_expiring(store):
    assert store.add_if_new("n1", expires_at=110.0, now=100.0)
    assert not store.add_if_new("n1", expires_at=110.0, now=105.0)
    assert store.add_if_new("n1", expires_at=300.0, now=200.0)


def test_store_purges_on_add(store):
    store.add_if_new("old", expires_at=10.0, now=0.0)
    store.add_if_new("new", expires_at=1000.0, now=500.0)
    assert len(store) == 1


def test_sqlite_store_persists_between_connections(tmp_path):
    path = str(tmp_path / "shared.sqlite3")
    a = SQLiteStore(path)
    assert a.add_if_new("abc", 1000.0, 0.0)
    a.close()
    b = SQLiteStore(path)
    try:
        assert not b.add_if_new("abc", 1000.0, 1.0)
    finally:
        b.close()


def test_concurrent_replay_only_one_wins(store):
    signer, clock = make(store=store)
    token = signer.issue()
    clock.advance(10)
    results = []

    def worker():
        results.append(signer.verify(token).ok)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
