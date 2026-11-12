"""Synthetic packets and mocked libpcap only; never open an actual interface."""
import ctypes
import hashlib
import json
import random
import socket
import struct
import threading
import time
import types
import unittest
from collections import deque
from unittest import mock

import capture as cap

EPOCH = 1790985600.0
CLIENT, SERVER = "192.0.2.10", "198.51.100.20"
SYN, ACK, FIN, RST = 2, 16, 1, 4


def ip_packet(segment, protocol=6, src=CLIENT, dst=SERVER, fragment=0, options=b""):
    assert len(options) % 4 == 0
    ihl = 20 + len(options)
    return (struct.pack("!BBHHHBBH4s4s", 0x40 | (ihl // 4), 0, ihl + len(segment), 7,
                        fragment, 64, protocol, 0, socket.inet_aton(src), socket.inet_aton(dst))
            + options + segment)


def link_frame(ip, link=cap.DLT_EN10MB, *, outgoing=False, loopback=False, padding=b""):
    hardware, packet_type = (772 if loopback else 1), (4 if outgoing else 0)
    if link == cap.DLT_EN10MB:
        header = b"\x01" * 6 + b"\x02" * 6 + b"\x08\x00"
    elif link == cap.DLT_LINUX_SLL:
        header = struct.pack("!HHH8sH", packet_type, hardware, 6, b"\0" * 8, 0x0800)
    elif link == cap.DLT_LINUX_SLL2:
        header = struct.pack("!HHIHBB8s", 0x0800, 0, 3, hardware, packet_type, 6, b"\0" * 8)
    elif link in (cap.DLT_RAW, 14, 101):
        header = b""
    else:
        raise ValueError("test_linktype")
    return header + ip + padding


def tcp(seq=1000, payload=b"", flags=ACK, *, ack=0, reverse=False, sport=40000, dport=443,
        src=CLIENT, dst=SERVER, link=cap.DLT_EN10MB, fragment=0, ip_options=b"", tcp_options=b"",
        outgoing=False, loopback=False, padding=b""):
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    offset = (20 + len(tcp_options)) // 4
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                          offset << 4, flags, 32768, 0, 0) + tcp_options + payload
    return link_frame(ip_packet(segment, src=src, dst=dst, fragment=fragment, options=ip_options),
                      link, outgoing=outgoing, loopback=loopback, padding=padding)


def udp(payload=b"data", *, reverse=False, sport=40000, dport=53, src=CLIENT, dst=SERVER,
        link=cap.DLT_EN10MB, fragment=0, outgoing=False, loopback=False, padding=b""):
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return link_frame(ip_packet(segment, 17, src, dst, fragment), link,
                      outgoing=outgoing, loopback=loopback, padding=padding)


class PacketTests(unittest.TestCase):
    def test_opt_in_stream_blocks_match_nat_and_segment_boundaries(self):
        first, second = [], []
        edge = cap.Capture('edge0', [443], [], first.append, tcp_stream_fingerprints=True)
        terminal = cap.Capture('term0', [443], [], second.append, tcp_stream_fingerprints=True)
        payload = bytes(range(192))
        edge.feed_packet(tcp(1000, payload[:48]), cap.DLT_EN10MB, EPOCH, now=0)
        edge.feed_packet(tcp(1048, payload[48:]), cap.DLT_EN10MB, EPOCH + .01, now=.01)
        terminal.feed_packet(tcp(1000, payload, src='203.0.113.2', sport=50000),
                             cap.DLT_EN10MB, EPOCH + .02, now=.02)
        a = {e['fingerprint'] for e in first if e['type'] == 'fingerprint'}
        b = {e['fingerprint'] for e in second if e['type'] == 'fingerprint'}
        self.assertTrue(a & b)
        self.assertEqual(len(a), 3)
        edge.feed_packet(tcp(2000, payload), cap.DLT_EN10MB, EPOCH + 1, now=1)
        self.assertEqual(len([e for e in first if e['type'] == 'fingerprint']), 3)
        edge.feed_packet(tcp(2000, payload), cap.DLT_EN10MB, EPOCH + 10, now=10)
        self.assertEqual(len([e for e in first if e['type'] == 'fingerprint']), 6)
        self.assertTrue(all(e['coverage'] == 'midstream' for e in first if e['type'] == 'fingerprint'))

    def test_stream_blocks_require_complete_bytes_and_keep_directions_separate(self):
        events = []
        capture = cap.Capture('eth0', [443], [], events.append, tcp_stream_fingerprints=True)
        capture.feed_packet(tcp(1024, b'x' * 31), cap.DLT_EN10MB, EPOCH, now=0)
        self.assertFalse([e for e in events if e['type'] == 'fingerprint'])
        capture.feed_packet(tcp(1024, b'x' * 96, reverse=True), cap.DLT_EN10MB, EPOCH + 1, now=1)
        downstream = [e['fingerprint'] for e in events if e['type'] == 'fingerprint']
        self.assertEqual(len(downstream), 3)
        capture.feed_packet(tcp(1024, b'x' * 96), cap.DLT_EN10MB, EPOCH + 10, now=10)
        upstream = [e['fingerprint'] for e in events if e['type'] == 'fingerprint'][3:]
        self.assertFalse(set(downstream) & set(upstream))
        peer_events = []
        peer = cap.Capture('other0', [443], [], peer_events.append, tcp_stream_fingerprints=True)
        peer.feed_packet(tcp(1024, b'x' * 96, reverse=True, src='203.0.113.2', sport=50000),
                         cap.DLT_EN10MB, EPOCH + 1, now=1)
        self.assertEqual(downstream, [e['fingerprint'] for e in peer_events if e['type'] == 'fingerprint'])
        with self.assertRaises(ValueError):
            cap.Capture('eth0', [443], [], events.append, tcp_stream_fingerprints='true')

    def setUp(self):
        self.events, self.now = [], 0.0
        self.capture = cap.Capture("eth0", [443], [53], self.events.append)

    def send(self, packet, *, link=cap.DLT_EN10MB, now=None, ts=None, **kwargs):
        self.now = self.now + 0.01 if now is None else now
        self.capture.feed_packet(packet, link, EPOCH + self.now if ts is None else ts,
                                 now=self.now, **kwargs)

    def events_of(self, kind):
        return [event for event in self.events if event["type"] == kind]

    def flush(self, now=None):
        self.capture.flush(now=self.now if now is None else now)

    def totals(self):
        self.flush()
        return tuple(sum(e[field] for e in self.events_of("wire_delta")) for field in
                     ("up_bytes", "down_bytes", "up_packets", "down_packets"))

    def test_segmented_out_of_order_retransmitted_tcp(self):
        payload = bytes(range(96))
        self.send(tcp(flags=SYN))
        self.send(tcp(1033, payload[32:64]))
        self.send(tcp(1033, payload[32:64]))
        self.send(tcp(1065, payload[64:]))
        self.assertEqual([], self.events_of("fingerprint"))
        self.send(tcp(1001, payload[:32]))
        self.send(tcp(1001, payload))
        fingerprints = self.events_of("fingerprint")
        self.assertEqual(len(fingerprints), 1)
        self.assertEqual(fingerprints[0]["fingerprint"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(self.totals(), (6 * 40 + 4 * 32 + 96, 0, 6, 0))
        self.assertGreater(self.capture._counts["tcp_prefix_gap_observations"], 0)
        self.assertEqual(self.events[0]["type"], "flow_open")
        self.assertEqual(self.events[0]["coverage"], "syn")

    def test_sequence_wrap(self):
        isn, payload = 0xFFFFFFE0, b"wrap" * 24
        base = (isn + 1) & 0xFFFFFFFF
        self.send(tcp(isn, flags=SYN))
        self.send(tcp(base + 48, payload[48:]))
        self.send(tcp(base, payload[:48]))
        self.assertEqual(self.events_of("fingerprint")[0]["fingerprint"], hashlib.sha256(payload).hexdigest())

    def test_overlap_and_pre_syn_bytes_are_trimmed(self):
        payload = b"x" * 96
        self.send(tcp(flags=SYN))
        self.send(tcp(999, b"zz" + payload[:60]))
        self.send(tcp(1041, payload[40:]))
        self.assertEqual(self.events_of("fingerprint")[0]["fingerprint"], hashlib.sha256(payload).hexdigest())

    def test_syn_retransmission_does_not_rotate(self):
        self.send(tcp(flags=SYN))
        first = self.events_of("flow_open")[0]["flow_id"]
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"a" * 96))
        self.send(tcp(flags=SYN))
        self.assertEqual(len(self.events_of("flow_open")), 1)
        self.assertEqual(len(self.events_of("fingerprint")), 1)
        self.assertEqual(self.events_of("fingerprint")[0]["flow_id"], first)
        self.assertEqual(self.capture._counts["tcp_syn_retransmissions"], 2)
        self.assertEqual(self.totals(), (256, 0, 4, 0))

    def test_tuple_reuse_closes_before_new_open(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"a" * 96))
        self.send(tcp(5000, flags=SYN))
        self.send(tcp(5001, b"b" * 96))
        opened, closed = self.events_of("flow_open"), self.events_of("flow_close")
        self.assertEqual(len(opened), 2)
        self.assertNotEqual(opened[0]["flow_id"], opened[1]["flow_id"])
        self.assertEqual(closed[0]["flow_id"], opened[0]["flow_id"])
        self.assertEqual(closed[0]["reason"], "tuple_reuse")
        self.assertEqual(closed[0]["capture_ts"], opened[1]["capture_ts"])
        index = self.events.index(closed[0])
        self.assertEqual(self.events[index - 1]["type"], "wire_delta")
        self.assertTrue(self.events[index - 1]["final"])
        self.assertEqual(self.events[index + 1], opened[1])
        self.assertEqual(len(self.events_of("fingerprint")), 2)

    def test_midstream_counts_but_never_fingerprints(self):
        self.send(tcp(2300, b"untrusted stream start" * 20))
        self.send(tcp(7200, b"reply", reverse=True))
        self.send(tcp(2700, flags=RST))
        self.assertEqual(self.events_of("flow_open")[0]["coverage"], "midstream")
        self.assertEqual(self.events_of("fingerprint"), [])
        self.assertEqual(self.events_of("flow_close")[0]["coverage"], "midstream")
        self.assertEqual(self.totals()[2:], (2, 1))
        self.assertEqual(self.capture._counts["tcp_without_syn_packets"], 3)

    def test_midstream_syn_replaces_instead_of_promoting(self):
        self.send(tcp(7000, b"old"))
        old = self.events_of("flow_open")[0]["flow_id"]
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"new" * 32))
        self.assertEqual([e["coverage"] for e in self.events_of("flow_open")], ["midstream", "syn"])
        self.assertEqual(self.events_of("flow_close")[0]["flow_id"], old)
        self.assertNotEqual(self.events_of("fingerprint")[0]["flow_id"], old)

    def test_syn_ack_is_not_client_syn(self):
        self.send(tcp(9000, flags=SYN | ACK, ack=1001, reverse=True))
        self.send(tcp(1001, b"a" * 96))
        self.assertEqual(self.events_of("flow_open")[0]["coverage"], "midstream")
        self.assertEqual(self.events_of("fingerprint"), [])
        self.assertEqual(self.events_of("flow_open")[0]["src_ip"], CLIENT)

    def test_reverse_count_and_ip_length_not_padding(self):
        self.send(tcp(flags=SYN, padding=b"pad" * 10))
        self.send(tcp(6000, b"response", reverse=True, padding=b"p" * 50))
        self.assertEqual(self.totals(), (40, 48, 1, 1))
        event = self.events_of("wire_delta")[0]
        self.assertEqual((event["src_ip"], event["src_port"], event["dst_ip"], event["dst_port"]),
                         (CLIENT, 40000, SERVER, 443))

    def test_both_service_ports_reverse_is_existing_flow(self):
        self.capture = cap.Capture("eth0", [443, 40000], [], self.events.append)
        self.send(tcp(flags=SYN))
        self.send(tcp(3000, flags=SYN | ACK, reverse=True))
        self.assertEqual(len(self.events_of("flow_open")), 1)
        self.assertEqual(self.totals(), (40, 40, 1, 1))

    def test_fin_half_close_counts_response_and_final_ack(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"hello", FIN | ACK, ack=9001))
        self.assertEqual(self.events_of("fingerprint")[0]["bytes_hashed"], 5)
        self.assertEqual(self.events_of("flow_close"), [])
        self.send(tcp(9001, b"response", reverse=True, ack=1007))
        self.send(tcp(9009, flags=FIN | ACK, reverse=True, ack=1007))
        self.assertEqual(self.events_of("flow_close"), [])
        self.send(tcp(1007, ack=9010))
        self.assertEqual(self.events_of("flow_close")[0]["reason"], "fin_acknowledged")
        self.assertEqual(self.totals(), (125, 88, 3, 2))

    def test_out_of_order_fin_waits_for_short_prefix(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1006, flags=FIN | ACK))
        self.assertEqual(self.events_of("fingerprint"), [])
        self.send(tcp(1001, b"hello"))
        self.assertEqual(self.events_of("fingerprint")[0]["fingerprint"], hashlib.sha256(b"hello").hexdigest())

    def test_rst_flushes_and_closes_even_after_manual_flush(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"short"))
        self.flush()
        self.send(tcp(1006, flags=RST))
        self.assertEqual(self.events_of("fingerprint")[0]["bytes_hashed"], 5)
        close = self.events_of("flow_close")[0]
        self.assertEqual(close["reason"], "rst")
        self.assertTrue(self.events[self.events.index(close) - 1]["final"])
        self.assertEqual(self.totals(), (125, 0, 3, 0))

    def test_unfilled_gap_never_hashes_on_reset(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"a" * 20))
        self.send(tcp(1041, b"b" * 56))
        self.send(tcp(1097, flags=RST))
        self.assertEqual(self.events_of("fingerprint"), [])
        self.assertEqual(self.capture._counts["tcp_prefix_gaps_on_close"], 1)

    def test_conflicting_retransmission_suppresses_fingerprint(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"a" * 20))
        self.send(tcp(1001, b"b" * 20))
        self.send(tcp(1021, b"c" * 76))
        self.send(tcp(1097, flags=RST))
        self.assertEqual(self.events_of("fingerprint"), [])
        self.assertEqual(self.capture._counts["tcp_conflicting_retransmissions"], 1)

    def test_syn_fast_open_payload_consumes_syn_sequence(self):
        self.send(tcp(1000, b"f" * 40, SYN))
        self.send(tcp(1000, b"f" * 40, SYN))
        self.send(tcp(1041, b"f" * 56))
        self.assertEqual(self.events_of("fingerprint")[0]["fingerprint"], hashlib.sha256(b"f" * 96).hexdigest())

    def test_udp_first_three_full_datagrams_only(self):
        payloads = [b"a", bytes(range(256)) * 20, b"third"]
        self.send(udp(b""))
        self.send(udp(b"server", reverse=True))
        truncated = udp(b"partial" * 20)
        self.send(truncated[:-20], wirelen=len(truncated))
        for payload in payloads + [b"fourth", b"fifth"]:
            self.send(udp(payload))
        fps = self.events_of("fingerprint")
        self.assertEqual([e["fingerprint"] for e in fps], [hashlib.sha256(p).hexdigest() for p in payloads])
        self.assertEqual([e["sample_index"] for e in fps], [1, 2, 3])
        self.assertEqual(len({e["flow_id"] for e in fps}), 1)
        self.assertEqual(self.capture._counts["udp_incomplete_datagrams"], 1)
        self.assertEqual(self.totals()[2:], (7, 1))

    def test_udp_timeout_closes_before_new_generation(self):
        self.send(udp(), now=0)
        self.send(udp(), now=119)
        self.send(udp(), now=239)
        self.assertEqual(len(self.events_of("flow_open")), 2)
        close, opened = self.events_of("flow_close")[0], self.events_of("flow_open")[1]
        self.assertEqual(close["reason"], "idle_timeout")
        self.assertEqual(close["capture_ts"], EPOCH + 239)
        self.assertLess(self.events.index(close), self.events.index(opened))
        self.assertNotEqual(close["flow_id"], opened["flow_id"])

    def test_tcp_timeout_does_not_fabricate_short_hash(self):
        self.send(tcp(flags=SYN), now=0)
        self.send(tcp(1001, b"short"), now=1)
        self.flush(3601)
        self.assertEqual(self.events_of("fingerprint"), [])
        self.assertEqual(self.events_of("flow_close")[0]["capture_ts"], EPOCH + 3601)
        self.assertEqual(self.events_of("flow_close")[0]["reason"], "idle_timeout")

    def test_combined_capacity_lru_always_closes(self):
        self.capture = cap.Capture("eth0", [443], [53], self.events.append, max_flows=2)
        self.send(tcp(flags=SYN), now=1)
        self.send(udp(), now=2)
        self.send(tcp(1001, b"a"), now=3)
        self.send(udp(sport=40001), now=4)
        self.assertEqual(sum(map(len, self.capture._flows.values())), 2)
        close = self.events_of("flow_close")[0]
        self.assertEqual((close["transport"], close["src_port"], close["reason"]), ("udp", 40000, "capacity"))
        self.assertEqual(self.capture._counts["flows_evicted"], 1)

    def test_ipv4_fragments_never_create_flows(self):
        for fragment in (0x2000, 1, 0x2001):
            self.send(tcp(flags=SYN, fragment=fragment))
            self.send(udp(fragment=fragment))
        self.assertEqual(self.events_of("flow_open"), [])
        self.flush()
        self.assertEqual(self.events_of("health")[-1]["counters"]["packets_fragmented"], 6)

    def test_truncated_tcp_known_prefix_and_original_wire_bytes(self):
        self.send(tcp(flags=SYN))
        packet = tcp(1001, b"p" * 200)
        self.send(packet[:54 + 40], wirelen=len(packet))
        self.assertEqual(self.events_of("fingerprint"), [])
        self.send(tcp(1041, b"p" * 56))
        self.assertEqual(self.events_of("fingerprint")[0]["bytes_hashed"], 96)
        self.assertEqual(self.totals(), (40 + 240 + 96, 0, 3, 0))

    def test_tcp_snaplen_prefix_with_max_options_and_original_wire_counts(self):
        prefix = bytes(range(96))
        for link in (1, 12, 14, 101, 113, 276):
            for explicit_caplen in (False, True):
                with self.subTest(link=link, explicit_caplen=explicit_caplen):
                    events = []
                    collector = cap.Capture("lo", [443], [], events.append)
                    self.assertEqual(collector.snaplen, 256)
                    options = dict(link=link, ip_options=b"\x01" * 40,
                                   tcp_options=b"\x01" * 40, loopback=True)
                    frames = [tcp(flags=SYN, **options), tcp(1001, prefix[:32], **options),
                              tcp(1033, prefix[32:] + b"x" * 1000, **options),
                              tcp(1033, prefix[32:] + b"x" * 1000, **options),
                              tcp(9000, b"r" * 4096, reverse=True, **options)]
                    for index, frame in enumerate(frames):
                        captured = min(256, len(frame))
                        data = frame if explicit_caplen else frame[:captured]
                        collector.feed_packet(data, link, EPOCH + index,
                                              wirelen=len(frame),
                                              caplen=captured if explicit_caplen else None,
                                              now=index)
                    collector.flush(now=len(frames))
                    fingerprints = [e for e in events if e["type"] == "fingerprint"]
                    self.assertEqual(len(fingerprints), 1)
                    self.assertEqual(fingerprints[0]["fingerprint"], hashlib.sha256(prefix).hexdigest())
                    self.assertEqual(fingerprints[0]["bytes_hashed"], 96)
                    deltas = [e for e in events if e["type"] == "wire_delta"]
                    totals = tuple(sum(e[field] for e in deltas) for field in
                                   ("up_bytes", "down_bytes", "up_packets", "down_packets"))
                    self.assertEqual(totals, (120 + 152 + 2 * 1184, 4216, 4, 1))
                    counters = next(e["counters"] for e in reversed(events)
                                    if e.get("status") == "coverage")
                    self.assertEqual(counters["packets_snaplen_limited"], 3)
                    self.assertEqual(counters["packets_truncated"], 0)
                    self.assertEqual(counters["tcp_prefix_gap_observations"], 0)
                    self.assertFalse(any(e.get("status") == "pcap_drops" for e in events))

    def test_tcp_small_snaplen_keeps_unexpected_and_header_truncation_visible(self):
        self.capture = cap.Capture("lo", [443], [], self.events.append)
        self.send(tcp(flags=SYN))
        frame = tcp(1001, b"p" * 1000)
        self.send(frame[:94], wirelen=len(frame))  # only 40 prefix bytes, not 256
        self.assertEqual(self.events_of("fingerprint"), [])
        self.send(frame[:53], wirelen=len(frame))  # incomplete TCP header
        self.send(frame[:255], wirelen=len(frame))  # not our requested clipping boundary
        self.assertEqual(self.events_of("fingerprint")[0]["bytes_hashed"], 96)
        self.flush()
        counters = self.events_of("health")[-1]["counters"]
        self.assertEqual(counters["packets_truncated"], 3)
        self.assertEqual(counters["packets_snaplen_limited"], 0)
        self.assertGreater(counters["tcp_prefix_gap_observations"], 0)

    def test_expected_snaplen_clipping_does_not_hide_real_tcp_prefix_gap(self):
        self.capture = cap.Capture("lo", [443], [], self.events.append)
        self.send(tcp(flags=SYN))
        frame = tcp(1101, b"x" * 1000)  # first 100 stream bytes were NOT observed
        self.send(frame[:256], wirelen=len(frame))
        self.send(tcp(2101, flags=RST))
        self.assertEqual(self.events_of("fingerprint"), [])
        self.flush()
        counters = self.events_of("health")[-1]["counters"]
        self.assertEqual(counters["packets_snaplen_limited"], 1)
        self.assertEqual(counters["packets_truncated"], 0)
        self.assertGreater(counters["tcp_prefix_gap_observations"], 0)
        self.assertEqual(counters["tcp_prefix_gaps_on_close"], 1)

    def test_udp_enabled_keeps_large_datagram_and_real_truncation_semantics(self):
        for tcp_ports in ([], [443]):
            with self.subTest(tcp_ports=tcp_ports):
                self.events.clear()
                self.capture = cap.Capture("eth0", tcp_ports, [53], self.events.append)
                self.assertEqual(self.capture.snaplen, 65535)
                payload = bytes(range(256)) * 4
                frame = udp(payload)
                self.send(frame)
                self.send(frame[:256], wirelen=len(frame))
                fingerprints = self.events_of("fingerprint")
                self.assertEqual(len(fingerprints), 1)
                self.assertEqual(fingerprints[0]["fingerprint"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(fingerprints[0]["bytes_hashed"], 1024)
                if tcp_ports:
                    self.send(tcp(flags=SYN))
                    frame = tcp(1001, b"t" * 1000)
                    self.send(frame[:256], wirelen=len(frame))
                self.flush()
                counters = self.events_of("health")[-1]["counters"]
                self.assertEqual(counters["packets_snaplen_limited"], 0)
                self.assertEqual(counters["packets_truncated"], 2 if tcp_ports else 1)
                self.assertEqual(counters["udp_incomplete_datagrams"], 1)

    def test_all_supported_linktypes_and_ip_tcp_options(self):
        for link in (1, 12, 14, 101, 113, 276):
            with self.subTest(link=link):
                events = []
                collector = cap.Capture("test0", [443], [], events.append)
                for seq, flags, payload in ((1000, SYN, b""), (1001, ACK, b"x" * 96)):
                    frame = tcp(seq, payload, flags, link=link, ip_options=b"\x01" * 4, tcp_options=b"\x01" * 4)
                    collector.feed_packet(frame, link, EPOCH, now=0)
                self.assertEqual(len([e for e in events if e["type"] == "fingerprint"]), 1)

    def test_cooked_loopback_dedup_keeps_fingerprints_and_real_retransmits(self):
        for link in (113, 276):
            with self.subTest(link=link):
                self.events.clear()
                self.capture = cap.Capture("lo", [443], [53], self.events.append)
                for seq, flags, payload in ((1000, SYN, b""), (1001, ACK, b"x" * 96), (1001, ACK, b"x" * 96)):
                    for outgoing in (True, False):
                        self.send(tcp(seq, payload, flags, link=link, loopback=True, outgoing=outgoing), link=link)
                self.assertEqual(len(self.events_of("fingerprint")), 1)
                self.assertEqual(self.totals(), (312, 0, 3, 0))
                self.assertEqual(self.capture._counts["packets_loopback_duplicate"], 3)

    def test_physical_cooked_outbound_is_not_deduplicated(self):
        self.send(udp(link=113, outgoing=True), link=113)
        self.assertEqual(len(self.events_of("fingerprint")), 1)
        self.assertEqual(self.totals()[2], 1)

    def test_cross_nat_and_interface_fingerprint_equality(self):
        digests, flow_ids = [], []
        for interface, src in (("lo", "127.0.0.1"), ("etneta0", "10.0.0.1"), ("eth0", CLIENT)):
            events = []
            collector = cap.Capture(interface, [443], [], events.append)
            collector.feed_packet(tcp(flags=SYN, src=src), 1, EPOCH, now=0)
            collector.feed_packet(tcp(1001, b"q" * 96, src=src), 1, EPOCH + 1, now=1)
            event = next(e for e in events if e["type"] == "fingerprint")
            digests.append(event["fingerprint"])
            flow_ids.append(event["flow_id"])
        self.assertEqual(len(set(digests)), 1)
        self.assertEqual(len(set(flow_ids)), 3)

    def test_truncation_and_malformed_lengths_fail_closed(self):
        valid = tcp(flags=SYN)
        for size in (0, 10, 13, 14, 25, 33, 34, 40, 53):
            self.send(valid[:size], wirelen=len(valid))
        self.send(valid, caplen=len(valid) + 1)
        self.send(valid, caplen=-1)
        self.send(valid, wirelen=len(valid) - 1)
        for index, value in ((14, 0x44), (16, 0), (46, 0x40)):
            mutated = bytearray(valid)
            if index == 16:
                mutated[16:18] = b"\x00\x10"
            else:
                mutated[index] = value
            self.send(mutated)
        invalid_udp = bytearray(udp())
        invalid_udp[38:40] = b"\x00\x07"
        self.send(invalid_udp)
        self.send(valid, link=9999)
        self.assertEqual(self.events_of("flow_open"), [])
        self.assertGreater(self.capture._counts["packets_invalid"], 0)
        self.assertGreater(self.capture._counts["packets_truncated"], 0)

    def test_caplen_limits_view_even_when_buffer_contains_more(self):
        self.send(tcp(flags=SYN))
        frame = tcp(1001, b"x" * 96)
        self.send(frame, caplen=54 + 10, wirelen=len(frame))
        self.assertEqual(self.events_of("fingerprint"), [])
        flow = next(iter(self.capture._flows["tcp"].values()))
        self.assertEqual(flow.mask.bit_count(), 10)

    def test_unrelated_protocol_ports_and_ipv6_filtered(self):
        self.send(tcp(flags=SYN, dport=444))
        self.send(udp(dport=54))
        self.send(link_frame(ip_packet(b"\0" * 30, protocol=1)))
        ipv6 = bytearray(tcp(flags=SYN))
        ipv6[12:14] = b"\x86\xdd"
        self.send(ipv6)
        self.assertEqual(self.events_of("flow_open"), [])

    def test_invalid_timestamp_does_not_create_flow(self):
        for stamp in (float("nan"), float("inf"), "secret", True):
            self.send(tcp(flags=SYN), ts=stamp)
        self.assertEqual(self.events_of("flow_open"), [])

    def test_wall_clock_reordering_does_not_expire_flows(self):
        self.send(udp(), now=1, ts=EPOCH + 100)
        self.send(udp(), now=2, ts=EPOCH - 100)
        self.assertEqual(len(self.events_of("flow_open")), 1)
        self.assertEqual(self.events_of("flow_close"), [])

    def test_events_have_audit_compatible_schema_no_payload(self):
        secret = b"never expose this literal payload" * 3
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, secret))
        self.send(tcp(1001 + len(secret), flags=RST))
        self.send(udp(secret))
        self.flush(200)
        encoded = json.dumps(self.events, allow_nan=False)
        self.assertNotIn("never expose this literal payload", encoded)
        for event in self.events:
            self.assertIn("type", event)
            self.assertGreaterEqual(event["capture_ts"], EPOCH)
            self.assertLess(len(json.dumps(event)), 8192)
            if event["type"] in ("health", "capture_stats"):
                continue
            self.assertIn(event["coverage"], ("syn", "midstream", "udp"))
            self.assertIsInstance(event["flow_id"], str)
            self.assertEqual(event["transport"], "udp" if event["dst_port"] == 53 else "tcp")
            for field in ("src_ip", "src_port", "dst_ip", "dst_port"):
                self.assertIn(field, event)

    def test_callback_failure_is_counted_not_leaked(self):
        def failing(event):
            raise ValueError("private payload do not disclose")
        self.capture.callback = failing
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"x" * 96))
        self.capture.callback = self.events.append
        self.flush()
        self.assertGreater(self.capture._counts["callback_errors"], 0)
        self.assertNotIn("private payload", json.dumps(self.events))

    def test_offline_reentry_rejected_flush_request_is_safe(self):
        seen = []
        def callback(event):
            self.events.append(event)
            if event["type"] == "flow_open":
                self.capture.flush()
                try:
                    self.capture.feed_packet(udp(), 1, EPOCH, now=0)
                except cap.CaptureError as error:
                    seen.append(str(error))
        self.capture.callback = callback
        self.send(udp())
        self.assertEqual(seen, ["capture_busy"])
        self.assertEqual(len(self.events_of("wire_delta")), 1)

    def test_payload_memory_bounded_and_detached_from_input(self):
        self.capture = cap.Capture("eth0", [443], [53], self.events.append, max_flows=8)
        for port in range(40000, 40020):
            self.send(tcp(flags=SYN, sport=port))
            packet = bytearray(tcp(1001, b"a" * 30, sport=port))
            self.send(packet)
            packet[:] = b"z" * len(packet)
        flows = list(self.capture._flows["tcp"].values())
        self.assertEqual(len(flows), 8)
        self.assertEqual(sum(len(f.prefix) for f in flows), 8 * 96)
        self.assertTrue(all(f.prefix[:30] == b"a" * 30 for f in flows))
        self.assertLessEqual(len(self.capture._dirty), 8)
        self.assertEqual(len(self.events_of("flow_close")), 12)

    def test_random_segment_orders_and_retransmissions(self):
        rng = random.Random(20261003)
        for case in range(40):
            with self.subTest(case=case):
                events = []
                collector = cap.Capture("eth0", [443], [], events.append)
                payload = bytes(rng.randrange(256) for _ in range(160))
                isn = rng.randrange(2**32)
                collector.feed_packet(tcp(isn, flags=SYN), 1, EPOCH, now=0)
                cuts = sorted({0, 160} | {rng.randrange(1, 160) for _ in range(12)})
                segments = [(cuts[i], payload[cuts[i]:cuts[i + 1]]) for i in range(len(cuts) - 1)]
                segments += rng.sample(segments, min(4, len(segments)))
                rng.shuffle(segments)
                for offset, segment in segments:
                    collector.feed_packet(tcp(isn + 1 + offset, segment), 1, EPOCH, now=0)
                fps = [e for e in events if e["type"] == "fingerprint"]
                self.assertEqual([e["fingerprint"] for e in fps], [hashlib.sha256(payload[:96]).hexdigest()])

    def test_random_malformed_frames_never_raise_or_create_flow(self):
        rng = random.Random(7)
        for link in (1, 12, 113, 276):
            for _ in range(150):
                raw = bytes(rng.randrange(256) for _ in range(rng.randrange(100)))
                self.send(raw, link=link)
        self.assertEqual(self.events_of("flow_open"), [])


    def test_zero_port_rejected_for_audit_schema(self):
        self.send(udp(sport=0))
        self.send(tcp(flags=SYN, sport=0))
        self.assertEqual(self.events_of("flow_open"), [])
        self.assertEqual(self.capture._counts["packets_invalid"], 2)

    def test_fin_reveals_gap_even_without_captured_payload(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1008, flags=FIN | ACK))
        self.flush(3601)
        self.assertEqual(self.events_of("fingerprint"), [])
        self.assertGreater(self.capture._counts["tcp_prefix_gap_observations"], 0)
        self.assertEqual(self.capture._counts["tcp_prefix_gaps_on_close"], 1)

    def test_contradictory_fin_cannot_shorten_observed_prefix(self):
        self.send(tcp(flags=SYN))
        self.send(tcp(1001, b"x" * 20))
        self.send(tcp(1006, flags=FIN | ACK))
        self.assertEqual(self.events_of("fingerprint"), [])


    def test_cached_expiry_skips_lru_walks_before_deadline(self):
        self.send(tcp(flags=SYN), now=0)
        class CountingTable(cap.OrderedDict):
            head_reads = 0
            def values(self):
                self.head_reads += 1
                return super().values()
        table = CountingTable(self.capture._flows["tcp"])
        self.capture._flows["tcp"] = table
        for _ in range(100):
            self.send(tcp(1001), now=1)
        self.assertEqual(table.head_reads, 0)
        self.flush(3600)  # Original deadline became stale after the packet at t=1.
        self.assertGreater(table.head_reads, 0)
        self.assertEqual(self.events_of("flow_close"), [])
        self.flush(3601)
        self.assertEqual(len(self.events_of("flow_close")), 1)

    def test_new_udp_shortens_cached_tcp_expiry(self):
        self.send(tcp(flags=SYN), now=0)
        self.send(udp(), now=10)
        self.flush(129)
        self.assertEqual(self.events_of("flow_close"), [])
        self.flush(130)
        self.assertEqual([(e["transport"], e["reason"]) for e in self.events_of("flow_close")],
                         [("udp", "idle_timeout")])
        self.assertEqual(len(self.capture._flows["tcp"]), 1)

    def test_lru_refresh_does_not_postpone_another_udp_flow_expiry(self):
        self.send(udp(sport=40000), now=0)
        self.send(udp(sport=40001), now=20)
        self.send(udp(sport=40000, reverse=True), now=50)
        self.flush(120)
        self.assertEqual(self.events_of("flow_close"), [])
        self.flush(140)
        self.assertEqual([e["src_port"] for e in self.events_of("flow_close")], [40001])
        self.flush(170)
        self.assertEqual([e["src_port"] for e in self.events_of("flow_close")], [40001, 40000])



class ConfigurationTests(unittest.TestCase):
    def test_narrow_bpf(self):
        self.assertEqual(cap.build_bpf([443, 80, 443], [53]),
                         "ip and ((tcp and (port 80 or port 443)) or (udp and (port 53)))")
        self.assertEqual(cap.build_bpf([], [53]), "ip and ((udp and (port 53)))")
        self.assertEqual(cap.build_bpf([443], []), "ip and ((tcp and (port 443)))")

    def test_invalid_configuration(self):
        for interface in ("", "any", "ANY", "eth0\0payload", None, "x" * 256):
            with self.subTest(interface=interface), self.assertRaises(ValueError):
                cap.Capture(interface, [443], [], lambda e: None)
        for ports in ([0], [-1], [65536], [True], ["443"], "443", 443, range(1, 258)):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                cap.build_bpf(ports, [])
        with self.assertRaises(ValueError):
            cap.build_bpf([], [])
        for options in ({"max_flows": 20001}, {"max_flows": 0}, {"max_flows": True},
                        {"tcp_idle_ttl": 3601}, {"udp_idle_ttl": 121},
                        {"flush_interval": 0}, {"flush_interval": float("nan")}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                cap.Capture("eth0", [443], [], lambda e: None, **options)


class FakeFunction:
    def __init__(self, result=0, action=None):
        self.result, self.action, self.calls = result, action, []

    def __call__(self, *args):
        self.calls.append(args)
        return self.action(*args) if self.action is not None else self.result


def fake_library(link=1, direction=0):
    library = types.SimpleNamespace()
    names = ("pcap_create", "pcap_close", "pcap_activate", "pcap_next_ex", "pcap_stats",
             "pcap_datalink", "pcap_setnonblock", "pcap_compile", "pcap_setfilter", "pcap_freecode",
             "pcap_setdirection", "pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout",
             "pcap_set_immediate_mode", "pcap_set_buffer_size")
    for name in names:
        setattr(library, name, FakeFunction())
    library.pcap_create.result = 123
    library.pcap_datalink.result = link
    library.pcap_setdirection.result = direction
    return library


class NativeAdapterTests(unittest.TestCase):
    def open_backend(self, library, interface="eth0", *, tcp_ports=(443,), udp_ports=(53,)):
        collector = cap.Capture(interface, tcp_ports, udp_ports, lambda event: None)
        with mock.patch.object(cap.ctypes.util, "find_library", return_value="fake"), \
                mock.patch.object(cap.ctypes, "CDLL", return_value=library):
            return cap._Pcap(interface, collector.bpf, collector.snaplen)

    def test_narrow_native_setup_and_nonpromiscuous(self):
        library = fake_library()
        backend = self.open_backend(library)
        self.addCleanup(backend.close)
        expected = {"pcap_set_snaplen": 65535, "pcap_set_promisc": 0,
                    "pcap_set_timeout": 100, "pcap_set_immediate_mode": 1,
                    "pcap_set_buffer_size": 8 * 1024 * 1024}
        for name, value in expected.items():
            self.assertEqual(getattr(library, name).calls, [(123, value)])
        self.assertEqual(library.pcap_setnonblock.calls[0][1], 1)
        self.assertEqual(library.pcap_compile.calls[0][2], cap.build_bpf([443], [53]).encode())
        self.assertEqual(len(library.pcap_freecode.calls), 1)
        self.assertEqual(library.pcap_setdirection.calls, [])
        self.assertEqual(backend._create.restype, ctypes.c_void_p)


    def test_eight_mib_buffer_is_requested_before_activation(self):
        library = fake_library()
        order = []
        library.pcap_set_buffer_size.action = lambda handle, size: order.append(("buffer", size)) or 0
        library.pcap_activate.action = lambda handle: order.append(("activate", None)) or 0
        backend = self.open_backend(library)
        self.addCleanup(backend.close)
        self.assertEqual(order, [("buffer", 8 * 1024 * 1024), ("activate", None)])

    def test_snaplen_selection_is_applied_before_activation_with_eight_mib(self):
        for tcp_ports, udp_ports, expected in (([443], [], 256),
                                              ([443], [53], 65535), ([], [53], 65535)):
            with self.subTest(tcp_ports=tcp_ports, udp_ports=udp_ports):
                library, order = fake_library(), []
                library.pcap_set_snaplen.action = lambda handle, size: order.append(("snaplen", size)) or 0
                library.pcap_set_buffer_size.action = lambda handle, size: order.append(("buffer", size)) or 0
                library.pcap_activate.action = lambda handle: order.append(("activate", None)) or 0
                backend = self.open_backend(library, tcp_ports=tcp_ports, udp_ports=udp_ports)
                self.addCleanup(backend.close)
                self.assertEqual(order, [("snaplen", expected), ("buffer", 8 * 1024 * 1024),
                                         ("activate", None)])

    def test_native_tcp_clipped_view_preserves_wirelen_and_checks_small_snaplen(self):
        library = fake_library()
        frame = tcp(1001, b"p" * 4096)
        raw = (ctypes.c_ubyte * 256).from_buffer_copy(frame[:256])
        header = cap._PcapHeader(cap._Timeval(int(EPOCH), 0), 256, len(frame))
        def read(handle, header_out, data_out):
            ctypes.cast(header_out, ctypes.POINTER(ctypes.POINTER(cap._PcapHeader)))[0] = ctypes.pointer(header)
            ctypes.cast(data_out, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)))[0] = ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte))
            return 1
        library.pcap_next_ex.action = read
        backend = self.open_backend(library, udp_ports=())
        self.addCleanup(backend.close)
        data, stamp, captured, wire = backend.next_packet()
        self.assertEqual(len(data), 256)
        self.assertEqual((stamp, captured, wire), (EPOCH, 256, len(frame)))
        raw[-1] ^= 1
        self.assertEqual(data[-1], raw[-1])  # borrowed view, no full-frame copy
        header.caplen = 257
        with self.assertRaisesRegex(cap._PcapError, "pcap_invalid_packet_header"):
            backend.next_packet()

    def test_loopback_direction_is_inbound_not_payload_dedup(self):
        library = fake_library()
        backend = self.open_backend(library, "lo")
        self.addCleanup(backend.close)
        self.assertEqual(library.pcap_setdirection.calls, [(123, 1)])
        self.assertEqual(backend.loopback_dedup, "pcap_inbound")

    def test_renamed_loopback_detected_by_pcap_flags(self):
        library = fake_library()
        device = cap._PcapDevice()
        device.name, device.flags = b"renamed0", 1
        def find(output, error):
            ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(cap._PcapDevice)))[0] = ctypes.pointer(device)
            return 0
        library.pcap_findalldevs = FakeFunction(action=find)
        library.pcap_freealldevs = FakeFunction()
        backend = self.open_backend(library, "renamed0")
        self.addCleanup(backend.close)
        self.assertTrue(backend.loopback)
        self.assertEqual(backend.loopback_dedup, "pcap_inbound")
        self.assertEqual(len(library.pcap_freealldevs.calls), 1)

    def test_loopback_cooked_fallback_or_fail_closed(self):
        for link in (113, 276):
            library = fake_library(link, direction=-1)
            backend = self.open_backend(library, "lo")
            self.assertEqual(backend.loopback_dedup, "cooked_direction")
            backend.close()
        library = fake_library(1, direction=-1)
        with self.assertRaisesRegex(cap._PcapError, "loopback_direction_unavailable"):
            self.open_backend(library, "lo")
        self.assertEqual(library.pcap_close.calls, [(123,)])

    def test_setup_failure_closes_and_never_falls_back_to_broad_filter(self):
        for symbol in ("pcap_activate", "pcap_setnonblock", "pcap_compile", "pcap_setfilter",
                       "pcap_set_immediate_mode", "pcap_set_snaplen"):
            with self.subTest(symbol=symbol):
                library = fake_library()
                getattr(library, symbol).result = -1
                with self.assertRaises(cap._PcapError):
                    self.open_backend(library)
                self.assertEqual(library.pcap_close.calls, [(123,)])
                self.assertEqual(library.pcap_next_ex.calls, [])
                if symbol == "pcap_setfilter":
                    self.assertEqual(len(library.pcap_freecode.calls), 1)

    def test_missing_immediate_symbol_is_sanitized(self):
        library = fake_library()
        del library.pcap_set_immediate_mode
        with self.assertRaisesRegex(cap._PcapError, "pcap_missing_symbol"):
            self.open_backend(library)
        self.assertEqual(library.pcap_create.calls, [])

    def test_native_packet_view_timestamp_and_stats(self):
        library = fake_library()
        frame = udp()
        raw = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        header = cap._PcapHeader(cap._Timeval(int(EPOCH), 123456), len(frame), len(frame))
        def read(handle, header_out, data_out):
            ctypes.cast(header_out, ctypes.POINTER(ctypes.POINTER(cap._PcapHeader)))[0] = ctypes.pointer(header)
            ctypes.cast(data_out, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)))[0] = ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte))
            return 1
        def stats(handle, output):
            result = ctypes.cast(output, ctypes.POINTER(cap._PcapStat)).contents
            result.ps_recv, result.ps_drop, result.ps_ifdrop = 100, 2, 3
            return 0
        library.pcap_next_ex.action, library.pcap_stats.action = read, stats
        backend = self.open_backend(library)
        self.addCleanup(backend.close)
        data, stamp, captured, wire = backend.next_packet()
        self.assertEqual(bytes(data), frame)
        self.assertAlmostEqual(stamp, EPOCH + .123456, places=5)
        self.assertEqual((captured, wire), (len(frame), len(frame)))
        raw[-1] ^= 1
        self.assertEqual(data[-1], raw[-1])  # borrowed, NOT a whole-frame copy
        self.assertEqual(backend.stats()["packets_dropped"], 2)
        header.caplen = 65536
        with self.assertRaisesRegex(cap._PcapError, "pcap_invalid_packet_header"):
            backend.next_packet()

    def test_wrong_thread_cannot_touch_handle(self):
        library = fake_library()
        backend = self.open_backend(library)
        self.addCleanup(backend.close)
        errors = []
        def wrong_thread():
            for operation in (backend.next_packet, backend.stats, backend.close):
                try:
                    operation()
                except cap._PcapError as error:
                    errors.append(error.code)
        thread = threading.Thread(target=wrong_thread)
        thread.start()
        thread.join(1)
        self.assertEqual(errors, ["pcap_wrong_thread"] * 3)
        self.assertEqual(library.pcap_next_ex.calls, [])

class RunTests(unittest.TestCase):
    def test_idle_stop_and_external_flush_stay_on_owner_thread(self):
        events, calls, errors = [], [], []
        ready, flushed, stop = threading.Event(), threading.Event(), threading.Event()
        frames = deque([tcp(flags=SYN), tcp(1001, b"x" * 96)])
        class Backend:
            linktype, loopback, loopback_dedup, activation_warning = 1, False, "not_loopback", 0
            def __init__(self, *args):
                calls.append(("open", threading.get_ident()))
            def next_packet(self):
                calls.append(("read", threading.get_ident()))
                if frames:
                    frame = frames.popleft()
                    return frame, EPOCH, len(frame), len(frame)
                ready.set()
                return None
            def stats(self):
                calls.append(("stats", threading.get_ident()))
                return {"packets_received": 2, "packets_dropped": 0,
                        "packets_if_dropped": 0, "stats_available": True}
            def close(self):
                calls.append(("close", threading.get_ident()))
        def callback(event):
            events.append(event)
            if event["type"] == "wire_delta":
                flushed.set()
        collector = cap.Capture("eth0", [443], [], callback)
        def run():
            try:
                collector.run(stop)
            except Exception as error:
                errors.append(error)
        with mock.patch.object(cap, "_Pcap", Backend):
            thread = threading.Thread(target=run)
            thread.start()
            try:
                self.assertTrue(ready.wait(2))
                with self.assertRaisesRegex(cap.CaptureError, "capture_busy"):
                    collector.feed_packet(udp(), 1, EPOCH)
                with self.assertRaisesRegex(cap.CaptureError, "capture_busy"):
                    collector.run(stop)
                collector.flush()
                self.assertTrue(flushed.wait(2))
            finally:
                stop.set()
                thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual({thread_id for _, thread_id in calls}, {thread.ident})
        self.assertEqual(sum(name == "open" for name, _ in calls), 1)
        self.assertEqual(sum(name == "close" for name, _ in calls), 1)
        self.assertEqual([e["reason"] for e in events if e["type"] == "flow_close"], ["stop"])
        self.assertEqual(sum(e["up_bytes"] for e in events if e["type"] == "wire_delta"), 176)
        self.assertTrue(all(e["capture_ts"] > 1_000_000_000 for e in events))


    def test_empty_live_read_waits_ten_ms_and_remains_stoppable(self):
        events, waits, closed = [], [], []
        class Stop:
            stopped = False
            def is_set(self):
                return self.stopped
            def wait(self, timeout):
                waits.append(timeout)
                self.stopped = True
                return True
        class Backend:
            linktype, loopback, loopback_dedup, activation_warning = 1, False, "not_loopback", 0
            def __init__(self, *args):
                pass
            def next_packet(self):
                return None
            def stats(self):
                return {"packets_received": 0, "packets_dropped": 0,
                        "packets_if_dropped": 0, "stats_available": True}
            def close(self):
                closed.append(True)
        with mock.patch.object(cap, "_Pcap", Backend):
            cap.Capture("eth0", [443], [], events.append).run(Stop())
        self.assertEqual(waits, [0.01])
        self.assertEqual(closed, [True])
        self.assertEqual(events[-1]["status"], "stopped")

    def test_burst_drains_across_batches_without_polling_sleeps(self):
        events, waits, reads = [], [], []
        count = 1024
        frames = deque([tcp(flags=SYN), tcp(1001, b"x" * 96)] +
                       [tcp(8000, b"r" * 1024, reverse=True)] * count)
        class Stop:
            stopped = False
            def is_set(self):
                return self.stopped
            def wait(self, timeout):
                waits.append((timeout, len(frames)))
                self.stopped = True
                return True
        class Backend:
            linktype, loopback, loopback_dedup, activation_warning = 1, False, "not_loopback", 0
            def __init__(self, *args):
                pass
            def next_packet(self):
                reads.append(len(frames))
                if frames:
                    frame = frames.popleft()
                    return frame, EPOCH, len(frame), len(frame)
                return None
            def stats(self):
                return {"packets_received": count + 2, "packets_dropped": 0,
                        "packets_if_dropped": 0, "stats_available": True}
            def close(self):
                pass
        collector = cap.Capture("eth0", [443], [], events.append)
        with mock.patch.object(cap, "_Pcap", Backend), \
                mock.patch.object(cap.time, "monotonic", return_value=0):
            collector.run(Stop())
        self.assertEqual(len(reads), count + 3)  # all frames then a single empty read
        self.assertEqual(waits, [(0.01, 0)])
        self.assertEqual(len([e for e in events if e["type"] == "fingerprint"]), 1)
        deltas = [e for e in events if e["type"] == "wire_delta"]
        self.assertEqual(sum(e["up_bytes"] for e in deltas), 176)
        self.assertEqual(sum(e["down_bytes"] for e in deltas), count * (1024 + 40))
        self.assertEqual(sum(e["down_packets"] for e in deltas), count)
        self.assertEqual([e["reason"] for e in events if e["type"] == "flow_close"], ["stop"])

    def test_run_passes_and_reports_selected_snaplen(self):
        for tcp_ports, udp_ports, expected in (([443], [], 256),
                                              ([443], [53], 65535), ([], [53], 65535)):
            with self.subTest(tcp_ports=tcp_ports, udp_ports=udp_ports):
                events, stop = [], threading.Event()
                backend = types.SimpleNamespace(
                    linktype=1, loopback=False, loopback_dedup="not_loopback", activation_warning=0,
                    next_packet=lambda: stop.set(), close=lambda: None,
                    stats=lambda: {"packets_received": 0, "packets_dropped": 0,
                                   "packets_if_dropped": 0, "stats_available": True})
                collector = cap.Capture("eth0", tcp_ports, udp_ports, events.append)
                with mock.patch.object(cap, "_Pcap", return_value=backend) as factory:
                    collector.run(stop)
                factory.assert_called_once_with("eth0", collector.bpf, expected)
                started = next(e for e in events if e.get("status") == "started")
                self.assertEqual(started["snaplen"], expected)

    def test_already_stopped_never_loads_libpcap(self):
        stop, events = threading.Event(), []
        stop.set()
        with mock.patch.object(cap, "_Pcap") as factory:
            cap.Capture("eth0", [443], [], events.append).run(stop)
            factory.assert_not_called()
        self.assertEqual(events[-1]["status"], "stopped")

    def test_read_failure_closes_flows_and_sanitizes_exception(self):
        events, closed = [], []
        frames = deque([tcp(flags=SYN)])
        class Backend:
            linktype, loopback, loopback_dedup, activation_warning = 1, False, "not_loopback", 0
            def __init__(self, *args):
                pass
            def next_packet(self):
                if frames:
                    frame = frames.popleft()
                    return frame, EPOCH, len(frame), len(frame)
                raise ValueError("do not leak captured private payload")
            def stats(self):
                raise ValueError("do not leak stats text")
            def close(self):
                closed.append(True)
        collector = cap.Capture("eth0", [443], [], events.append)
        with mock.patch.object(cap, "_Pcap", Backend):
            with self.assertRaisesRegex(cap.CaptureError, "^internal_error$"):
                collector.run(threading.Event())
        self.assertEqual(closed, [True])
        self.assertEqual([e["reason"] for e in events if e["type"] == "flow_close"], ["capture_error"])
        self.assertNotIn("do not leak", json.dumps(events))
        self.assertTrue(any(e.get("status") == "pcap_stats_unavailable" for e in events))
        self.assertTrue(collector._gate.acquire(False))
        collector._gate.release()

    def test_setup_failure_sanitized(self):
        events = []
        collector = cap.Capture("eth0", [443], [], events.append)
        with mock.patch.object(cap, "_Pcap", side_effect=cap._PcapError("pcap_library_unavailable")):
            with self.assertRaisesRegex(cap.CaptureError, "pcap_library_unavailable"):
                collector.run(threading.Event())
        self.assertTrue(any(e.get("error_code") == "pcap_library_unavailable" for e in events))

    def test_pcap_drops_emit_health_without_repeated_unchanged_warning(self):
        events = []
        collector = cap.Capture("eth0", [443], [], events.append)
        backend = types.SimpleNamespace(stats=lambda: {"packets_received": 100, "packets_dropped": 4,
                                                       "packets_if_dropped": 2, "stats_available": True})
        collector._capture_stats(backend)
        collector._capture_stats(backend)
        self.assertEqual(len([e for e in events if e.get("status") == "pcap_drops"]), 1)
        self.assertEqual(len([e for e in events if e["type"] == "capture_stats"]), 2)

    def test_udp_hash_updates_are_bounded_to_96_bytes(self):
        events, sizes = [], []
        original = hashlib.sha256
        class Digest:
            def __init__(self, value=b""):
                self.hash = original(value)
                sizes.append(len(value))
            def update(self, value):
                sizes.append(len(value))
                self.hash.update(value)
            def hexdigest(self):
                return self.hash.hexdigest()
        collector = cap.Capture("eth0", [], [53], events.append)
        payload = b"u" * 60000
        with mock.patch.object(cap.hashlib, "sha256", Digest):
            collector.feed_packet(udp(payload), 1, EPOCH, now=0)
        self.assertLessEqual(max(sizes), 96)
        self.assertEqual(next(e["fingerprint"] for e in events if e["type"] == "fingerprint"),
                         original(payload).hexdigest())
        flow = next(iter(collector._flows["udp"].values()))
        self.assertIsNone(flow.prefix)


    def test_drop_health_survives_later_coverage_and_stats_failure(self):
        events = []
        collector = cap.Capture("eth0", [443], [], events.append)
        backend = types.SimpleNamespace(stats=lambda: {"packets_received": 100, "packets_dropped": 4,
                                                       "packets_if_dropped": 2, "stats_available": True})
        collector._capture_stats(backend)
        collector.flush(now=0)
        self.assertEqual(events[-1]["packets_dropped"], 4)
        backend.stats = mock.Mock(side_effect=ValueError("private error"))
        collector._capture_stats(backend)
        self.assertEqual(events[-1]["packets_dropped"], 4)
        self.assertFalse(events[-1]["stats_available"])


if __name__ == "__main__":
    unittest.main()
