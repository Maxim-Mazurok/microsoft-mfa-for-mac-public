"""Bounded one-request-per-operation HTTPS transport; no approval decisions."""
import asyncio
from urllib.parse import urlsplit

import e02
import enrollment_protocol as ep
import mfa_protocol as protocol
import push_protocol as p
from p01 import require


def report(experiment, kinds, maximum_posts):
    result = {"experiment": experiment, "http_posts_attempted": 0, "maximum_http_posts": maximum_posts,
              "automatic_retries": 0, "mcs_connections": 0, "new_google_requests": 0,
              "authentication_approvals_sent": 0, "stage": "local_prerequisites", "error": None}
    for kind in kinds:
        result[kind + "_connections_attempted"] = 0
        result[kind + "_tls_verified"] = False
        result[kind + "_posts_attempted"] = 0
        result[kind + "_http_status"] = None
        result[kind + "_received_bytes"] = 0
    return result


def wire(kind, request):
    actions = {"poll": "phoneAppCheckForAuthenticationRequest", "retrieve": "phoneAppAuthenticationRequest",
               "number": "phoneAppPinValidationRequest"}
    require(kind in actions and request.headers.get("x-ms-mac-action") == actions[kind], "invalid_mfa_operation")
    if kind == "poll":
        require(request.url == protocol.POLL_URL, "invalid_poll_destination")
        parts = urlsplit(request.url); host, path = parts.hostname, parts.path
    else:
        dest = ep.validate_pad_request_url(request.url); host, path = dest.host, dest.path
    require(0 < len(request.body) <= 32768, "request_size_limit")
    headers = {"Host": host, "Connection": "close", "Content-Length": str(len(request.body)),
               "Accept-Encoding": "identity", "User-Agent": "Mac-MFA-research/0.2"}
    seen = {k.lower() for k in headers}
    for key, value in request.headers.items():
        require(e02.re.fullmatch(r"[A-Za-z0-9-]+", key) and key.lower() not in seen
                and isinstance(value, str) and value.isascii() and all(32 <= ord(c) < 127 for c in value),
                "invalid_http_header")
        seen.add(key.lower()); headers[key] = value
    return host, (f"POST {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                  + "\r\n").encode() + request.body


async def post(kind, request, run, state):
    host, raw_request = wire(kind, request)
    require(state["http_posts_attempted"] < state["maximum_http_posts"] and state[kind + "_posts_attempted"] == 0,
            "mfa_request_budget_exhausted")
    async with asyncio.timeout(30):
        async with e02.connection(host, 443, kind, state) as (reader, writer):
            state["stage"] = kind + "_send"
            state["http_posts_attempted"] += 1; state[kind + "_posts_attempted"] += 1
            writer.write(raw_request); await writer.drain()
            state["stage"] = kind + "_response"
            data = bytearray()
            with run.capture(kind + "-response.bin") as capture:
                while True:
                    chunk = await reader.read(min(4096, p.LIMIT - len(data) + 1))
                    if not chunk: break
                    require(len(data) + len(chunk) <= p.LIMIT, "http_receive_limit")
                    data.extend(chunk); capture.write(chunk); state[kind + "_received_bytes"] += len(chunk)
            status, body = e02.parse_http(bytes(data))
            state[kind + "_http_status"] = status
            run.write(kind + "-body.bin", body)
            require(200 <= status < 300, kind + "_http_rejected")
            return body
