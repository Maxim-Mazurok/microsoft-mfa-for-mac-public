"""TLS-only bounded receive transport and exactly one HTTP attempt per call.

No check-in, sender registration, FIS refresh or enrollment is initiated here.
Reconnecting preserves the issuer-backed identity already stored in Keychain.
"""
import bootstrap  # noqa: F401
import asyncio
import time

import e02
import mfa_transport
import p02
import push_protocol as p


class TransportError(ValueError):
    pass


async def post_number(request, before_send):
    """No redirects, retries, alternate addresses, raw capture or provider logging."""
    host, wire = mfa_transport.wire("number", request)
    report = {"number_connections_attempted": 0}
    async with asyncio.timeout(30):
        async with e02.connection(host, 443, "number", report) as (reader, writer):
            before_send()  # Revalidate focus/lock/expiry and fsync the durable claim now.
            writer.write(wire)
            await writer.drain()
            data = bytearray()
            while True:
                chunk = await reader.read(min(4096, p.LIMIT - len(data) + 1))
                if not chunk: break
                if len(data) + len(chunk) > p.LIMIT: raise TransportError("response_size_limit")
                data.extend(chunk)
            status, body = e02.parse_http(bytes(data))
            if status != 200: raise TransportError("approval_http_rejected")
            return body


def stream_ack(stream_id):
    # Chromium BuildStreamAck: IQ SET with empty id and extension 13, empty data.
    extension = p.field(1, 13) + p.field(2, b"")
    return p.mcs_frame(7, p.field(2, 1) + p.field(3, "") + p.field(7, extension) + p.field(10, stream_id))


class MCSConnection:
    HEARTBEAT_SECONDS = 240
    HEARTBEAT_RESPONSE_SECONDS = 30
    MAX_CONNECTION_SECONDS = 21600  # Refresh connection every six hours; identity unchanged.
    MAX_BYTES = 8 * 1024 * 1024
    MAX_FRAMES = 4096

    def __init__(self, credentials, on_data, on_connected):
        self.credentials, self.on_data, self.on_connected = credentials, on_data, on_connected
        self.writer = None
        self.decoder = p.MCSDecoder()
        self.frames = []
        self.received_bytes = 0
        self.stream_id = 0
        self.heartbeat_pending = False

    async def frame(self, reader):
        while not self.frames:
            chunk = await reader.read(4096)
            if not chunk: raise ConnectionError("mcs_closed")
            self.received_bytes += len(chunk)
            if self.received_bytes > self.MAX_BYTES: raise TransportError("connection_receive_budget")
            self.frames.extend(self.decoder.feed(chunk))
        self.stream_id += 1
        if self.stream_id > self.MAX_FRAMES: raise TransportError("connection_frame_budget")
        return self.frames.pop(0)

    async def send(self, wire):
        self.writer.write(wire)
        await asyncio.wait_for(self.writer.drain(), 10)

    async def run(self):
        report = {"mcs_connections_attempted": 0}
        # Includes DNS, TCP, TLS and login in the first 30 seconds.
        manager = e02.connection("mtalk.google.com", 5228, "mcs", report)
        async with asyncio.timeout(30):
            reader, self.writer = await manager.__aenter__()
        try:
            async with asyncio.timeout(30):
                await self.send(p.build_mcs_login(self.credentials.checkin))
                if not p.parse_mcs_login(await self.frame(reader)):
                    raise TransportError("provider_credentials_rejected")
            await self.on_connected()
            started = time.monotonic()
            while time.monotonic() - started < self.MAX_CONNECTION_SECONDS:
                timeout = self.HEARTBEAT_RESPONSE_SECONDS if self.heartbeat_pending else self.HEARTBEAT_SECONDS
                try:
                    frame = await asyncio.wait_for(self.frame(reader), timeout)
                except TimeoutError:
                    if self.heartbeat_pending: raise TransportError("heartbeat_timeout") from None
                    await self.send(p.mcs_frame(0, p.field(2, self.stream_id)))
                    self.heartbeat_pending = True
                    continue
                self.heartbeat_pending = False  # Any valid downstream packet proves liveness.
                if frame.tag == 8:
                    await self.on_data(frame)
                    # ACK receipt, not Microsoft approval. Claiming approval stays separate.
                    await self.send(stream_ack(self.stream_id))
                elif frame.tag in (0, 1, 7):
                    p02.housekeeping(frame)
                    if frame.tag == 0:
                        await self.send(p.mcs_frame(1, p.field(2, self.stream_id)))
                elif frame.tag == 4:
                    raise ConnectionError("provider_closed_stream")
                else:
                    raise TransportError("unsupported_mcs_frame")
            return "scheduled_connection_refresh"
        finally:
            await manager.__aexit__(None, None, None)
            self.writer = None
