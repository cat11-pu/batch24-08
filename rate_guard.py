import bisect
import ipaddress
import math
import threading
import time
from collections import defaultdict

ATTEMPTS = defaultdict(list)

_LAST_SEEN = {}
_LOCK = threading.Lock()


def _validate_ip(ip):
    if not isinstance(ip, str):
        raise TypeError("ip must be a string")
    if not ip:
        raise ValueError("ip must not be empty")


def _validate_account(account):
    if not isinstance(account, str):
        raise TypeError("account must be a string")
    if not account:
        raise ValueError("account must not be empty")


def _validate_limit(limit):
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if limit < 0:
        raise ValueError("limit must be >= 0")


def _validate_window(window):
    if isinstance(window, bool) or not isinstance(window, (int, float)):
        raise TypeError("window must be a number")
    if not math.isfinite(window) or window <= 0:
        raise ValueError("window must be a positive finite number")


def _validate_now(now):
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise TypeError("now must be a number")
    if not math.isfinite(now):
        raise ValueError("now must be a finite number")


def allow_attempt(ip, account, now=None, limit=5, window=60):
    _validate_ip(ip)
    _validate_account(account)
    _validate_limit(limit)
    _validate_window(window)
    if now is None:
        now = time.time()
    _validate_now(now)
    key = (ip, account)
    with _LOCK:
        last = _LAST_SEEN.get(key)
        if last is not None and now < last:
            raise ValueError("now must not go backwards for a given ip/account")
        _LAST_SEEN[key] = now
        attempts = ATTEMPTS[key]
        stale = bisect.bisect_right(attempts, now - window)
        if stale:
            del attempts[:stale]
        allowed = len(attempts) < limit
        attempts.append(now)
        return allowed


def reset(ip, account):
    with _LOCK:
        ATTEMPTS.pop((ip, account), None)
        _LAST_SEEN.pop((ip, account), None)


def reset_all():
    with _LOCK:
        ATTEMPTS.clear()
        _LAST_SEEN.clear()


def client_key(ip, forwarded_for=None, trust_proxy=False):
    _validate_ip(ip)
    if not trust_proxy:
        return ip
    if forwarded_for is None:
        raise ValueError("forwarded_for is required when trust_proxy is True")
    if not isinstance(forwarded_for, str):
        raise TypeError("forwarded_for must be a string")
    first_hop = forwarded_for.split(",")[0].strip()
    if not first_hop:
        raise ValueError("forwarded_for must not be empty")
    try:
        ipaddress.ip_address(first_hop)
    except ValueError:
        raise ValueError("forwarded_for is not a valid IP address")
    return first_hop
