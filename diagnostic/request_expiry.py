"""Microsoft auth notification expiration is absolute Unix seconds."""
import math
import re
import time
from research_runtime import require


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{8,11}", value) is not None,
            "request_expiration_required")
    return int(value)


def deadline(value, received_monotonic, *, now_monotonic=None, now_unix=None):
    monotonic = time.monotonic() if now_monotonic is None else now_monotonic
    unix = time.time() if now_unix is None else now_unix
    require(math.isfinite(received_monotonic) and received_monotonic <= monotonic,
            "invalid_request_receipt_time")
    remaining = timestamp(value) - unix
    require(remaining > 0, "approval_request_expired")
    result = min(received_monotonic + 120, monotonic + remaining)
    require(result > monotonic, "approval_request_expired")
    return result
