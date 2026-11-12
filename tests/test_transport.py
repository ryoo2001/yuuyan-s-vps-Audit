"""Protocol, bounded decoding, mocked socket cleanup, and local-only UDP tests."""
import errno
import hashlib
import hmac
import json
import random
import socket
import threading
import time
import unittest
import zlib
from contextlib import contextmanager
from unittest import mock

import transport as t

KEY = b"test-only-authentication-key"
NODE = "entry-a0"
DOMAIN = b"traffic-audit-udp-v1\0"
REQUEST = {"events": [{"type": "wire_delta", "up_bytes": 123}], "sent_at": 1790985600}


def signed_body(body, node=NODE, key=KEY, compressed=False):
    node_bytes = node.encode("ascii")
    data = body if compressed else zlib.compress(body)
    signature = hmac.digest(key, DOMAIN + node_bytes + data, "sha256")
    return b"TA1" + bytes((len(node_bytes),)) + node_bytes + signature + data


def ack_for(request, **overrides):
    result = {"ack": hashlib.sha256(request).hexdigest(), "accepted": 1}
    result.update(overrides)
    return result


class CodecTests(unittest.TestCase):
    def decode(self, packet):
        return t.decode(packet, lambda node: KEY if node == NODE else None)

    def test_roundtrip_unicode_nested_values(self):
        payload = {"events": [{"text": "中文😀", "nested": [None, True, 1, 2.5]}]}
        self.assertEqual(self.decode(t.encode(NODE, KEY, payload)), (NODE, payload))

    def test_sent_at_presence_and_replay_policy_belong_to_caller(self):
        for payload in ({}, {"events": []}, {"sent_at": 0}, {"sent_at": "caller-validated"}):
            with self.subTest(payload=payload):
                self.assertEqual(self.decode(t.encode(NODE, KEY, payload)), (NODE, payload))

    def test_all_frame_prefixes_and_single_byte_tampering_raise_valueerror(self):
        packet = t.encode(NODE, KEY, REQUEST)
        for length in range(len(packet)):
            with self.subTest(prefix_length=length), self.assertRaises(ValueError):
                self.decode(packet[:length])
        for index in range(len(packet)):
            changed = bytearray(packet)
            changed[index] ^= 1
            with self.subTest(tampered_index=index), self.assertRaises(ValueError):
                self.decode(bytes(changed))

    def test_exact_layout_compact_json_and_domain_separation(self):
        packet = t.encode(NODE, KEY, {"a": 1, "b": "two"})
        size = len(NODE)
        self.assertEqual(packet[:4], b"TA1" + bytes((size,)))
        self.assertEqual(packet[4:4 + size], NODE.encode())
        compressed = packet[4 + size + 32:]
        self.assertEqual(zlib.decompress(compressed), b'{"a":1,"b":"two"}')
        self.assertEqual(packet[4 + size:4 + size + 32],
                         hmac.digest(KEY, DOMAIN + NODE.encode() + compressed, "sha256"))
        signature = hmac.digest(KEY, NODE.encode() + compressed, "sha256")
        with self.assertRaises(ValueError):
            self.decode(packet[:4 + size] + signature + compressed)

    def test_valid_node_boundaries_and_charset(self):
        for node in ("a", "_-", "A09_test-Node", "n" * 64):
            with self.subTest(node=node):
                self.assertEqual(t.decode(t.encode(node, KEY, {}), lambda n: KEY), (node, {}))

    def test_invalid_encode_nodes(self):
        for node in ("", "n" * 65, "中文", "é", "a b", "a.b", "a/b", "a\n", "a\x00", b"abc", 1, None):
            with self.subTest(node=node), self.assertRaises(ValueError):
                t.encode(node, KEY, {})

    def test_invalid_frame_magic_lengths_and_node(self):
        valid = t.encode(NODE, KEY, {})
        frames = [b"", b"TA1", b"XX1" + valid[3:], b"TA1\x00" + b"x" * 40,
                  b"TA1\x41" + b"n" * 65 + b"x" * 40,
                  b"TA1\x01\xff" + b"x" * 40, b"TA1\x01." + b"x" * 40,
                  b"TA1\x01n" + b"x" * 32, valid[:10]]
        for frame in frames:
            with self.subTest(frame_len=len(frame)), self.assertRaises(ValueError):
                self.decode(frame)

    def test_invalid_node_rejected_before_key_lookup(self):
        lookup = mock.Mock(return_value=KEY)
        with self.assertRaises(ValueError):
            t.decode(b"TA1\x01/" + b"x" * 40, lookup)
        lookup.assert_not_called()

    def test_tampered_node_signature_and_compressed_body(self):
        original = t.encode(NODE, KEY, REQUEST)
        for index in (4, 4 + len(NODE), len(original) - 1):
            packet = bytearray(original)
            packet[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                t.decode(bytes(packet), lambda node: KEY)

    def test_wrong_or_missing_key(self):
        packet = t.encode(NODE, KEY, {})
        for lookup in (lambda node: b"wrong", lambda node: None, lambda node: b"", {}.__getitem__):
            with self.subTest(lookup=lookup), self.assertRaises(ValueError):
                t.decode(packet, lookup)

    def test_invalid_encode_key_and_payload(self):
        for key in (b"", "string", None, bytearray(KEY)):
            with self.subTest(key_type=type(key)), self.assertRaises(ValueError):
                t.encode(NODE, key, {})
        for payload in ([], 42, True, None, "text", {"not_json": object()}):
            with self.subTest(payload_type=type(payload)), self.assertRaises(ValueError):
                t.encode(NODE, KEY, payload)

    def test_bad_mac_is_rejected_before_decompression(self):
        packet = bytearray(t.encode(NODE, KEY, {}))
        packet[4 + len(NODE)] ^= 1
        with mock.patch.object(t.zlib, "decompressobj") as decompress:
            with self.assertRaises(ValueError):
                self.decode(bytes(packet))
        decompress.assert_not_called()

    def test_encode_rejects_nonfinite_values(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                t.encode(NODE, KEY, {"events": [{"value": value}]})

    def test_decode_rejects_nonfinite_literals_and_exponent_overflow(self):
        for value in (b"NaN", b"Infinity", b"-Infinity", b"1e9999", b"-1e9999"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.decode(signed_body(b'{"nested":[' + value + b']}'))
        self.assertEqual(self.decode(signed_body(b'{"x":1e308}'))[1], {"x": 1e308})

    def test_decode_rejects_non_dict_invalid_utf8_and_json_tail(self):
        for body in (b"[]", b"null", b"true", b"42", b'"string"', b'{"x":}',
                     b"{}{}", b"{}garbage", b'{"x":"\xff"}'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.decode(signed_body(body))

    def test_decode_rejects_zlib_tail_concatenation_and_incomplete_stream(self):
        data = zlib.compress(b"{}")
        for compressed in (data + b"tail", data + data, data[:-1], data[:3], b"not-zlib"):
            with self.subTest(compressed=compressed), self.assertRaises(ValueError):
                self.decode(signed_body(compressed, compressed=True))

    def test_encode_oversize_does_not_truncate_events(self):
        rng = random.Random(7)
        payload = {"events": [{"text": bytes(rng.getrandbits(8) for _ in range(2500)).hex()}]}
        before = json.dumps(payload)
        with self.assertRaises(t.PacketTooLarge):
            t.encode(NODE, KEY, payload)
        self.assertEqual(json.dumps(payload), before)
        self.assertTrue(issubclass(t.PacketTooLarge, ValueError))

    def test_decode_oversize_rejected_before_key_lookup(self):
        lookup = mock.Mock(return_value=KEY)
        with self.assertRaises(t.PacketTooLarge):
            t.decode(b"x" * (t.MAX_PACKET + 1), lookup)
        lookup.assert_not_called()

    def test_exact_packet_limit_is_accepted(self):
        rng = random.Random(12)
        noise = bytes(rng.getrandbits(8) for _ in range(1100)).hex()
        for length in range(1700, len(noise) + 1):
            payload = {"x": noise[:length]}
            body = json.dumps(payload, separators=(",", ":")).encode()
            node_size = t.MAX_PACKET - 36 - len(zlib.compress(body))
            if 1 <= node_size <= 64:
                node = "n" * node_size
                packet = t.encode(node, KEY, payload)
                self.assertEqual(len(packet), t.MAX_PACKET)
                self.assertEqual(t.decode(packet, lambda node: KEY), (node, payload))
                with self.assertRaises(t.PacketTooLarge):
                    t.decode(packet + b"x", lambda node: KEY)
                break
        else:
            self.fail("failed to construct boundary frame")

    def test_exact_body_limit_roundtrips_and_one_byte_more_fails(self):
        payload = {"x": "a" * (t.MAX_BODY - 8)}
        packet = t.encode(NODE, KEY, payload)
        self.assertLessEqual(len(packet), t.MAX_PACKET)
        self.assertEqual(self.decode(packet), (NODE, payload))
        payload["x"] += "a"
        with self.assertRaises(t.PacketTooLarge):
            t.encode(NODE, KEY, payload)
        body = b'{"x":"' + b"a" * (t.MAX_BODY - 7) + b'"}'
        with self.assertRaises(t.PacketTooLarge):
            self.decode(signed_body(body))

    def test_decompression_bomb_is_bounded(self):
        frame = signed_body(b'{"x":"' + b"a" * 1000000 + b'"}')
        self.assertLessEqual(len(frame), t.MAX_PACKET)
        real_factory = zlib.decompressobj
        calls = []
        class Guard:
            def __init__(self):
                self.inner = real_factory()
            def decompress(self, data, max_length=0):
                calls.append(max_length)
                if max_length != t.MAX_BODY + 1:
                    raise AssertionError("unbounded decompression")
                return self.inner.decompress(data, max_length)
            def __getattr__(self, name):
                return getattr(self.inner, name)
            def flush(self, *args):
                raise AssertionError("unbounded flush")
        with mock.patch.object(t.zlib, "decompressobj", Guard):
            with self.assertRaises(t.PacketTooLarge):
                self.decode(frame)
        self.assertEqual(calls, [t.MAX_BODY + 1])

    def test_circular_encode_and_deep_decode_fail_as_valueerror(self):
        payload = {}
        payload["self"] = payload
        with self.assertRaises(ValueError):
            t.encode(NODE, KEY, payload)
        with self.assertRaises(ValueError):
            self.decode(signed_body(b'{"x":' + b"[" * 3000 + b"0" + b"]" * 3000 + b"}"))

    def test_invalid_packet_types(self):
        for packet in (None, "TA1", bytearray(b"TA1"), 123):
            with self.subTest(packet_type=type(packet)), self.assertRaises(ValueError):
                self.decode(packet)


class ScriptedSocket:
    def __init__(self, replies=()):
        self.replies = iter(replies)
        self.sent, self.timeouts, self.receive_sizes = [], [], []
        self.connected = None
        self.closed = 0
        self.connect_error = self.send_error = None
        self.short_send = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        self.connected = address
        if self.connect_error:
            raise self.connect_error

    def send(self, packet):
        self.sent.append(packet)
        if self.send_error:
            raise self.send_error
        return len(packet) - int(self.short_send)

    def recv(self, size):
        self.receive_sizes.append(size)
        response = next(self.replies, TimeoutError("test timeout"))
        if isinstance(response, Exception):
            raise response
        return response(self) if callable(response) else response

    def close(self):
        self.closed += 1


def good_reply(sock):
    return t.encode(NODE, KEY, ack_for(sock.sent[0]))


class ExchangeTests(unittest.TestCase):
    address = ("127.0.0.1", 12345)

    def exchange_with(self, sock, **kwargs):
        with mock.patch.object(t.socket, "socket", return_value=sock) as factory:
            try:
                return t.exchange(self.address, NODE, KEY, REQUEST, **kwargs)
            finally:
                factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
                self.assertEqual(sock.closed, 1)

    def test_connected_ipv4_one_datagram_correct_ack_and_cleanup(self):
        sock = ScriptedSocket([good_reply])
        result = self.exchange_with(sock)
        self.assertEqual(sock.connected, self.address)
        self.assertEqual(len(sock.sent), 1)
        self.assertEqual(t.decode(sock.sent[0], lambda node: KEY), (NODE, REQUEST))
        self.assertEqual(result, ack_for(sock.sent[0]))
        self.assertEqual(sock.receive_sizes, [t.MAX_PACKET + 1])

    def test_request_and_ack_do_not_require_sent_at(self):
        payload = {"events": [{"type": "test"}]}
        sock = ScriptedSocket([good_reply])
        with mock.patch.object(t.socket, "socket", return_value=sock):
            result = t.exchange(self.address, NODE, KEY, payload)
        self.assertEqual(set(result), {"accepted", "ack"})
        self.assertEqual(result, ack_for(sock.sent[0]))
        self.assertEqual(t.decode(sock.sent[0], lambda node: KEY), (NODE, payload))
        self.assertEqual(sock.closed, 1)

    def test_wrong_hash_then_correct_ack(self):
        bad = t.encode(NODE, KEY, {"ack": "0" * 64, "accepted": 1})
        sock = ScriptedSocket([bad, good_reply])
        self.assertEqual(self.exchange_with(sock)["accepted"], 1)
        self.assertEqual(len(sock.receive_sizes), 2)

    def test_old_request_ack_then_correct_ack(self):
        old = t.encode(NODE, KEY, {"events": [{"old": True}]})
        sock = ScriptedSocket([t.encode(NODE, KEY, ack_for(old)), good_reply])
        self.assertEqual(self.exchange_with(sock), ack_for(sock.sent[0]))
        self.assertEqual(len(sock.receive_sizes), 2)

    def test_wrong_node_then_correct_ack(self):
        sock = ScriptedSocket([lambda s: t.encode("other-node", KEY, ack_for(s.sent[0])), good_reply])
        self.exchange_with(sock)
        self.assertEqual(len(sock.receive_sizes), 2)

    def test_bad_mac_and_malformed_ack_then_correct_ack(self):
        sock = ScriptedSocket([b"not a frame", lambda s: t.encode(NODE, b"wrong", ack_for(s.sent[0])),
                               signed_body(b"[]"), good_reply])
        self.exchange_with(sock)
        self.assertEqual(len(sock.receive_sizes), 4)

    def test_accepted_requires_exact_int_count(self):
        for accepted in (True, False, 1.0, "1", None, -1, 0, 2):
            with self.subTest(accepted=accepted):
                sock = ScriptedSocket([lambda s: t.encode(NODE, KEY, ack_for(s.sent[0], accepted=accepted)),
                                       good_reply])
                self.exchange_with(sock)
                self.assertEqual(len(sock.receive_sizes), 2)

    def test_missing_ack_fields_then_correct_ack(self):
        sock = ScriptedSocket([t.encode(NODE, KEY, {}), t.encode(NODE, KEY, {"accepted": 1}),
                               lambda s: t.encode(NODE, KEY, {"ack": hashlib.sha256(s.sent[0]).hexdigest()}),
                               good_reply])
        self.exchange_with(sock)
        self.assertEqual(len(sock.receive_sizes), 4)

    def test_oversized_datagram_and_emsgsize_are_ignored(self):
        sock = ScriptedSocket([b"x" * (t.MAX_PACKET + 1), OSError(errno.EMSGSIZE, "large"), good_reply])
        self.exchange_with(sock)
        self.assertEqual(len(sock.receive_sizes), 3)

    def test_timeout_closes_socket_without_changing_request(self):
        before = json.dumps(REQUEST)
        sock = ScriptedSocket()
        with self.assertRaises(TimeoutError):
            self.exchange_with(sock, timeout=0.1)
        self.assertEqual(json.dumps(REQUEST), before)
        self.assertEqual(len(sock.sent), 1)

    def test_bad_ack_only_never_confirms(self):
        sock = ScriptedSocket([t.encode(NODE, KEY, {"ack": "old", "accepted": 1})])
        with self.assertRaises(TimeoutError):
            self.exchange_with(sock)

    def test_bad_ack_traffic_cannot_extend_absolute_deadline(self):
        clock = [0.0]
        def bad_reply(sock):
            clock[0] += 0.4
            return t.encode(NODE, KEY, {"ack": "wrong", "accepted": 1})
        sock = ScriptedSocket([bad_reply] * 10)
        with mock.patch.object(t.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(TimeoutError):
                self.exchange_with(sock, timeout=1)
        self.assertEqual(len(sock.receive_sizes), 3)
        self.assertAlmostEqual(sock.timeouts[-1], 0.2)

    def test_matching_ack_after_deadline_is_not_accepted(self):
        clock = [0.0]
        def late_reply(sock):
            clock[0] = 2.0
            return good_reply(sock)
        sock = ScriptedSocket([late_reply])
        with mock.patch.object(t.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(TimeoutError):
                self.exchange_with(sock, timeout=1)

    def test_connect_send_receive_errors_and_short_send_close_socket(self):
        for stage in ("connect", "send", "receive", "short_send"):
            with self.subTest(stage=stage):
                sock = ScriptedSocket([OSError("receive failure")])
                if stage == "connect":
                    sock.connect_error = OSError("connect failure")
                elif stage == "send":
                    sock.send_error = OSError("send failure")
                elif stage == "short_send":
                    sock.short_send = True
                with self.assertRaises(OSError):
                    self.exchange_with(sock)

    def test_invalid_timeout_or_events_never_opens_socket(self):
        with mock.patch.object(t.socket, "socket") as factory:
            for timeout in (0, -1, True, None, "3", float("nan"), float("inf")):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    t.exchange(self.address, NODE, KEY, REQUEST, timeout)
            for payload in ({}, {"events": None}, {"events": {}}, {"events": "x"}, []):
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    t.exchange(self.address, NODE, KEY, payload)
        factory.assert_not_called()

    def test_oversized_request_never_opens_socket(self):
        with mock.patch.object(t.socket, "socket") as factory:
            with self.assertRaises(t.PacketTooLarge):
                t.exchange(self.address, NODE, KEY, {"events": ["x" * t.MAX_BODY]})
        factory.assert_not_called()

    def test_empty_batch_requires_zero_accepted(self):
        sock = ScriptedSocket([lambda s: t.encode(NODE, KEY, ack_for(s.sent[0], accepted=0))])
        with mock.patch.object(t.socket, "socket", return_value=sock):
            self.assertEqual(t.exchange(self.address, NODE, KEY, {"events": []})["accepted"], 0)
        self.assertEqual(sock.closed, 1)


class LocalUDPTests(unittest.TestCase):
    @contextmanager
    def server(self, handler):
        errors, requests = [], []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(2)
            def run():
                try:
                    request, peer = server.recvfrom(65535)
                    requests.append(request)
                    handler(server, request, peer)
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            try:
                yield server.getsockname(), requests
            finally:
                thread.join(3)
                self.assertFalse(thread.is_alive(), "local UDP server leaked")
                if errors:
                    raise errors[0]

    def test_real_udp_wrong_hash_then_signed_correct_ack(self):
        def handler(server, request, peer):
            self.assertEqual(t.decode(request, lambda node: KEY), (NODE, REQUEST))
            server.sendto(t.encode(NODE, KEY, ack_for(request, ack="0" * 64)), peer)
            server.sendto(t.encode(NODE, KEY, ack_for(request)), peer)
        with self.server(handler) as (address, requests):
            result = t.exchange(address, NODE, KEY, REQUEST, timeout=1)
        self.assertEqual(result, ack_for(requests[0]))

    def test_real_udp_oversized_datagram_then_correct_ack(self):
        def handler(server, request, peer):
            server.sendto(b"x" * 2000, peer)
            server.sendto(t.encode(NODE, KEY, ack_for(request)), peer)
        with self.server(handler) as (address, requests):
            result = t.exchange(address, NODE, KEY, REQUEST, timeout=1)
        self.assertEqual(result, ack_for(requests[0]))

    def test_real_udp_wrong_source_is_filtered_by_connect(self):
        def handler(server, request, peer):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong_source:
                wrong_source.bind(("127.0.0.1", 0))
                wrong_source.sendto(t.encode(NODE, KEY, ack_for(request, marker="wrong_source")), peer)
            server.sendto(t.encode(NODE, KEY, ack_for(request, marker="expected_source")), peer)
        with self.server(handler) as (address, requests):
            result = t.exchange(address, NODE, KEY, REQUEST, timeout=1)
        self.assertEqual(result["marker"], "expected_source")

    def test_real_udp_no_reply_times_out(self):
        with self.server(lambda server, request, peer: None) as (address, requests):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                t.exchange(address, NODE, KEY, REQUEST, timeout=0.05)
            self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()
