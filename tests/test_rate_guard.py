import threading

import pytest

import rate_guard as rg


def test_1_sixth_attempt_is_rejected():
    results = [rg.allow_attempt("1.2.3.4", "alice", now=1000 + i) for i in range(6)]
    assert results[-1] is False


def test_2_only_limit_attempts_are_allowed():
    results = [rg.allow_attempt("1.2.3.4", "alice", now=1000 + i) for i in range(100)]
    assert sum(1 for item in results if item) <= 5


def test_3_zero_limit_rejects_everything():
    assert rg.allow_attempt("1.2.3.4", "alice", now=1000, limit=0) is False


def test_4_negative_limit_is_rejected():
    with pytest.raises(ValueError):
        rg.allow_attempt("1.2.3.4", "alice", now=1000, limit=-1)


def test_5_zero_window_is_rejected():
    with pytest.raises(ValueError):
        rg.allow_attempt("1.2.3.4", "alice", now=1000, window=0)


def test_6_empty_ip_is_rejected():
    with pytest.raises(ValueError):
        rg.allow_attempt("", "alice", now=1000)


def test_7_empty_account_is_rejected():
    with pytest.raises(ValueError):
        rg.allow_attempt("1.2.3.4", "", now=1000)


def test_8_non_string_ip_is_rejected():
    with pytest.raises(TypeError):
        rg.allow_attempt(123, "alice", now=1000)


def test_9_non_string_account_is_rejected():
    with pytest.raises(TypeError):
        rg.allow_attempt("1.2.3.4", 123, now=1000)


def test_10_concurrent_attempts_are_capped():
    results = []

    def worker():
        results.append(rg.allow_attempt("1.2.3.4", "alice", now=1000))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for item in results if item) <= 5


def test_11_trusted_proxy_uses_forwarded_for():
    assert rg.client_key("10.0.0.1", "9.9.9.9", trust_proxy=True) == "9.9.9.9"


def test_12_trusted_proxy_requires_forwarded_for():
    with pytest.raises(ValueError):
        rg.client_key("10.0.0.1", None, trust_proxy=True)


def test_13_invalid_forwarded_for_is_rejected():
    with pytest.raises(ValueError):
        rg.client_key("10.0.0.1", "not-an-ip", trust_proxy=True)


def test_14_time_going_backwards_is_rejected():
    rg.allow_attempt("1.2.3.4", "alice", now=2000)
    with pytest.raises(ValueError):
        rg.allow_attempt("1.2.3.4", "alice", now=1000)


def test_15_negative_window_is_rejected():
    with pytest.raises(ValueError):
        rg.allow_attempt("1.2.3.4", "alice", now=1000, window=-1)
