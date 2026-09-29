import threading

import pytest

from form_spam_guard import Honeypot, RateLimiter


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_honeypot_render_is_hidden_and_marked():
    html = Honeypot().render()
    assert 'name="website"' in html
    assert 'tabindex="-1"' in html
    assert 'autocomplete="off"' in html
    assert 'class="fsg-hp"' in html
    assert 'type="hidden"' not in html
    assert "display:none" not in html


def test_honeypot_css_moves_offscreen():
    css = Honeypot().css()
    assert css.startswith(".fsg-hp{")
    assert "-10000px" in css


def test_honeypot_custom_name_is_escaped():
    hp = Honeypot(field_name='we"b', css_class="x y", label="A<B")
    html = hp.render()
    assert 'we&quot;b' in html
    assert "A&lt;B" in html


def test_honeypot_filled_detection():
    hp = Honeypot(field_name="url")
    assert not hp.is_filled({})
    assert not hp.is_filled({"url": ""})
    assert not hp.is_filled({"url": "   "})
    assert not hp.is_filled({"website": "x"})
    assert hp.is_filled({"url": "http://spam.example"})
    assert hp.is_filled({"url": "0"})


def test_bucket_allows_burst_then_blocks():
    clock = Clock()
    rl = RateLimiter(capacity=3, refill_per_second=1.0, clock=clock)
    assert [rl.allow("1.2.3.4") for _ in range(4)] == [True, True, True, False]


def test_bucket_refills_over_time():
    clock = Clock()
    rl = RateLimiter(capacity=2, refill_per_second=0.5, clock=clock)
    assert rl.allow("k") and rl.allow("k")
    assert not rl.allow("k")
    clock.t += 1.0  # 0.5 token, not enough
    assert not rl.allow("k")
    clock.t += 1.0  # 1.0 token
    assert rl.allow("k")
    assert not rl.allow("k")


def test_bucket_never_exceeds_capacity():
    clock = Clock()
    rl = RateLimiter(capacity=2, refill_per_second=10, clock=clock)
    rl.allow("k")
    clock.t += 3600
    assert rl.remaining("k") == 2
    assert [rl.allow("k") for _ in range(3)] == [True, True, False]


def test_keys_are_independent():
    clock = Clock()
    rl = RateLimiter(capacity=1, refill_per_second=0, clock=clock)
    assert rl.allow("a@example.com")
    assert not rl.allow("a@example.com")
    assert rl.allow("b@example.com")


def test_cost_and_no_refill():
    clock = Clock()
    rl = RateLimiter(capacity=5, refill_per_second=0, clock=clock)
    assert rl.allow("k", cost=5)
    assert not rl.allow("k")


def test_max_keys_prunes():
    clock = Clock()
    rl = RateLimiter(capacity=1, refill_per_second=1.0, clock=clock, max_keys=3)
    for i in range(10):
        rl.allow("k%d" % i)
    assert len(rl._buckets) <= 3


def test_thread_safety_exact_count():
    rl = RateLimiter(capacity=100, refill_per_second=0, clock=Clock())
    hits = []

    def worker():
        for _ in range(50):
            hits.append(rl.allow("shared"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert hits.count(True) == 100


def test_invalid_arguments():
    with pytest.raises(ValueError):
        RateLimiter(capacity=0)
    with pytest.raises(ValueError):
        RateLimiter(capacity=1, refill_per_second=-1)
