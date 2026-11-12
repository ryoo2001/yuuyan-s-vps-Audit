"""Authenticated UDP frames; standard library only, no queue or server side effects.

Frame: TA1 | one-byte node length | ASCII node | HMAC-SHA256 | zlib(compact JSON).
The MAC covers b"traffic-audit-udp-v1\0" + node bytes + compressed bytes.
MAX_PACKET includes the entire frame; MAX_BODY limits uncompressed UTF-8 JSON.
Decode authenticates BEFORE bounded decompression; invalid input raises ValueError.
PacketTooLarge also covers bodies over MAX_BODY, even when highly compressible.
Keys must be nonempty bytes. No encryption or sent_at/replay policy is provided.

exchange() requires payload['events'] to be a list. It sends once and only returns
an authenticated, matching ACK; timeout/transport errors propagate, never confirm
queue deletion. All socket waits share one monotonic deadline. Hostname resolution
uses the OS resolver (not interruptible by socket timeouts); use an IPv4 address
when a strict overall network deadline is required. Receiver integration, replay
checks, batch shrinking and retries belong to the caller.
"""

import errno
import hashlib
import hmac
import json
import math
import re
import socket
import time
import zlib

__all__ = ["encode", "decode", "exchange", "PacketTooLarge", "MAX_PACKET", "MAX_BODY"]
MAX_PACKET = 1200
MAX_BODY = 524288
_MAGIC = b"TA1"
_DOMAIN = b"traffic-audit-udp-v1\0"
_NODE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_MAC_SIZE = 32


class PacketTooLarge(ValueError):
    """Frame/body exceeds its hard limit; caller must shrink its batch."""


def _node_bytes(node):
    if not isinstance(node, str) or _NODE.fullmatch(node) is None:
        raise ValueError("invalid_node")
    return node.encode("ascii")


def _key_bytes(key):
    if not isinstance(key, bytes) or not key:
        raise ValueError("invalid_key")
    return key


def encode(node: str, key: bytes, payload: dict) -> bytes:
    """Encode one complete dictionary, or fail without dropping any events."""
    node_bytes, key = _node_bytes(node), _key_bytes(key)
    if not isinstance(payload, dict):
        raise ValueError("payload_must_be_dict")
    body = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    try:
        for chunk in encoder.iterencode(payload):
            chunk = chunk.encode("utf-8")
            if len(body) + len(chunk) > MAX_BODY:
                raise PacketTooLarge("body_too_large")
            body.extend(chunk)
    except PacketTooLarge:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("invalid_payload") from None
    compressed = zlib.compress(body)
    if 4 + len(node_bytes) + _MAC_SIZE + len(compressed) > MAX_PACKET:
        raise PacketTooLarge("packet_too_large")
    signature = hmac.digest(key, _DOMAIN + node_bytes + compressed, "sha256")
    return _MAGIC + bytes((len(node_bytes),)) + node_bytes + signature + compressed


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite_json")
    return number


def _reject_constant(value):
    raise ValueError("nonfinite_json")


def decode(packet: bytes, key_lookup) -> tuple:
    """Return (node, dictionary); key_lookup(node) supplies a nonempty bytes key."""
    if not isinstance(packet, bytes):
        raise ValueError("invalid_packet")
    if len(packet) > MAX_PACKET:
        raise PacketTooLarge("packet_too_large")
    if len(packet) < 4 or packet[:3] != _MAGIC:
        raise ValueError("invalid_frame")
    size = packet[3]
    mac_start, body_start = 4 + size, 4 + size + _MAC_SIZE
    if not 1 <= size <= 64 or len(packet) <= body_start:
        raise ValueError("invalid_frame")
    try:
        node = packet[4:mac_start].decode("ascii")
    except UnicodeError:
        raise ValueError("invalid_node") from None
    node_bytes = _node_bytes(node)
    try:
        key = _key_bytes(key_lookup(node))
    except KeyError:
        raise ValueError("unknown_node") from None
    compressed = packet[body_start:]
    expected = hmac.digest(key, _DOMAIN + node_bytes + compressed, "sha256")
    if not hmac.compare_digest(packet[mac_start:body_start], expected):
        raise ValueError("invalid_signature")
    decompressor = zlib.decompressobj()
    try:
        body = decompressor.decompress(compressed, MAX_BODY + 1)
    except zlib.error:
        raise ValueError("invalid_compression") from None
    if len(body) > MAX_BODY:
        raise PacketTooLarge("body_too_large")
    # Never call unbounded flush(), including on incomplete/concatenated streams.
    if not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        raise ValueError("invalid_compression")
    try:
        payload = json.loads(body.decode("utf-8"), parse_constant=_reject_constant,
                             parse_float=_finite_float)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("invalid_json") from None
    if not isinstance(payload, dict):
        raise ValueError("payload_must_be_dict")
    return node, payload


def exchange(address: tuple, node: str, key: bytes, payload: dict, timeout=3) -> dict:
    """Send one request; return only its exact authenticated ACK, else raise.

    ACK requires the same node, ack=SHA256(request frame).hexdigest(), and an
    actual int (not bool/float) accepted equal to the request's event count.
    """
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("invalid_timeout")
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        raise ValueError("events_must_be_list")
    count = len(payload["events"])
    request = encode(node, key, payload)
    request_hash = hashlib.sha256(request).hexdigest()
    deadline = time.monotonic() + timeout

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("udp_ack_timeout")
        return seconds

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(remaining())
        sock.connect(address)
        sock.settimeout(remaining())
        if sock.send(request) != len(request):
            raise OSError("udp_short_send")
        while True:
            sock.settimeout(remaining())
            try:
                # One extra byte detects oversized datagrams, not a valid prefix.
                response = sock.recv(MAX_PACKET + 1)
            except OSError as error:
                # Windows can discard an oversized UDP datagram with WSAEMSGSIZE.
                if error.errno == errno.EMSGSIZE or getattr(error, "winerror", None) == 10040:
                    continue
                raise
            try:
                ack_node, ack = decode(response, lambda candidate: key if candidate == node else None)
            except ValueError:
                continue
            if (ack_node == node and ack.get("ack") == request_hash and
                    type(ack.get("accepted")) is int and ack["accepted"] == count):
                remaining()  # decoding a late ACK must not extend the deadline
                return ack
    finally:
        sock.close()
