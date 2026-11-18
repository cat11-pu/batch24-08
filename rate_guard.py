import time
from collections import defaultdict

ATTEMPTS = defaultdict(list)


def allow_attempt(ip, account, now=None, limit=5, window=60):
    if now is None:
        now = time.time()
    ATTEMPTS[(ip, account)].append(now)
    return True


def reset(ip, account):
    ATTEMPTS.pop((ip, account), None)


def client_key(ip, forwarded_for=None, trust_proxy=False):
    return ip
