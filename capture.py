"""Passive IPv4 flow generations / fingerprints; standard library + ctypes pcap.

Capture(interface, tcp_ports, udp_ports, callback).run(stop_event) blocks: use a
thread. Its persistent pcap handle is opened/read/closed ONLY in that thread.
One explicit interface per instance (not 'any'): a physical entry interface, or
each termination/listener interface including loopback. Only entry wire_delta
is additive; multiple interfaces/instances must NOT be summed for wire totals.

Every flow emits flow_open BEFORE fingerprint/wire_delta, and a final wire_delta
BEFORE flow_close. All use 'type', a canonical CLIENT -> SERVER five-tuple,
flow_id, coverage ('syn', 'midstream', 'udp'), and capture_ts in UNIX epoch
seconds. IDs are instance-local generations, NOT cross-NAT correlation keys.
A new client SYN replaces a tuple's old generation; identical SYN sequence
numbers are retransmissions and do not replace an active SYN-derived flow.
Without SYN, TCP is explicitly midstream. Optional tcp_stream_fingerprints
matches aligned encrypted stream blocks, with at most three per flow per ten
seconds. The default keeps SYN-only prefix fingerprints.
Destination service ports identify clients; existing reverse tuples disambiguate
replies when both ports match. Configure only the intended local listener ports.

SYN-derived TCP hashes exactly the first 96 client stream bytes, reassembled by
sequence, including wrap, deduplication and out-of-order segments. Shorter prefixes
require client FIN or RST and no gaps. Conflicting overlap suppresses hashing.
FIN is half-close: retain both directions until both FINs are acknowledged;
RST closes immediately. TCP idle TTL is 3600s, UDP 120s, combined cap 20000.
All expiry/eviction/shutdown paths emit flow_close (with a reason). Timer-driven
close timestamps project the latest capture epoch using elapsed monotonic time.
UDP hashes the entire payload of each of its first THREE complete nonempty CLIENT
datagrams, in <=96-byte hash updates. Replies/empty/truncated datagrams do not
consume fingerprint slots. No later hashes until a new generation.

wire_delta uses IPv4 total_length, including IP/transport headers/retransmissions,
not Ethernet headers, padding, captured length, or a billing metric. Fragments
are excluded rather than misparsed; incomplete UDP cannot be hashed. Truncated
TCP with complete headers can contribute wire bytes and known prefix bytes.
TCP-only handles use snaplen 256 (enough for supported link headers, maximum
IPv4/TCP options and 96 payload bytes); any configured UDP port keeps 65535.
Expected TCP-only tail clipping exactly at snaplen increments the informational
packets_snaplen_limited counter, NOT packets_truncated or pcap drop counters.
Unexpected/header truncation and actual missing TCP prefix bytes still report
truncation/gaps; a snaplen-limited packet does not imply data loss.
Checksum offload is tolerated (checksums are not validated). health reports
fragment/truncation/gap/midstream/callback coverage counters; capture_stats reports
libpcap drops, also flagged in health. Out-of-order gaps may subsequently heal.

No payload/pcap is written, logged or put in events. TCP retains <=96 payload
bytes per collecting flow; UDP retains none. Live frames borrow libpcap's buffer,
never copy a whole packet, and expire before its next read. Tables are bounded;
each pcap handle requests an 8 MiB capture buffer before activation to absorb
bursts (not a shared process-wide budget). An empty nonblocking read waits up to
10 ms; queued packets are drained without polling sleeps. The earliest expiry
is cached, avoiding per-packet LRU-head walks before any flow can expire.
Callbacks are synchronous, MUST return promptly, and exceptions are counted
without emitting their text; a blocked callback cannot be interrupted. flush()
requests an owner-thread flush during run (normally <=10ms when idle);
offline it is synchronous. feed_packet() is an offline/synthetic entry point,
never loads pcap, and rejects concurrent/reentrant input. Offline Ethernet
loopback must already be direction-filtered. Live loopback requires PCAP_D_IN or
cooked packet direction; no payload-based dedup that would discard real retries.
"""

import ctypes
import ctypes.util
import hashlib
import math
import os
import socket
import struct
import threading
import time
import uuid
from collections import OrderedDict

__all__ = ["Capture", "CaptureError", "build_bpf"]
DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_LINUX_SLL2 = 1, 12, 113, 276
_RAW_TYPES = frozenset((DLT_RAW, 14, 101))  # OpenBSD RAW / savefile LINKTYPE_RAW
_LINK_TYPES = _RAW_TYPES | {DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2}
SNAPLEN, PREFIX_BYTES, MAX_FLOWS = 65535, 96, 20000
_TCP_SNAPLEN = 256
TCP_IDLE_TTL, UDP_IDLE_TTL = 3600.0, 120.0
_MAX_PORTS, _POLL_INTERVAL, _STATS_INTERVAL = 256, 0.01, 10.0
_PCAP_BUFFER_SIZE = 8 * 1024 * 1024
_SYN, _ACK, _FIN, _RST, _MASK32 = 0x02, 0x10, 0x01, 0x04, 0xFFFFFFFF


class CaptureError(RuntimeError):
    """Fixed diagnostic code, never packet/libpcap/callback error text."""


def _ports(values):
    result = set()
    if values is None:
        return frozenset()
    try:
        for index, port in enumerate(values):
            if index >= _MAX_PORTS:
                raise ValueError("too_many_ports")
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("invalid_port")
            result.add(port)
    except TypeError:
        raise ValueError("invalid_ports") from None
    return frozenset(result)


def build_bpf(tcp_ports, udp_ports):
    """Narrow IPv4, bidirectional service-port filter; never broadens on failure."""
    tcp, udp = _ports(tcp_ports), _ports(udp_ports)
    if not tcp and not udp:
        raise ValueError("at_least_one_port_required")
    if len(tcp) + len(udp) > _MAX_PORTS:
        raise ValueError("too_many_ports")
    terms = []
    for transport, ports in (("tcp", tcp), ("udp", udp)):
        if ports:
            terms.append("(%s and (%s))" % (
                transport, " or ".join("port %d" % p for p in sorted(ports))))
    return "ip and (" + " or ".join(terms) + ")"


def _seq_delta(sequence, base):
    return ((sequence - base + 0x80000000) & _MASK32) - 0x80000000


class _Packet:
    # No repr of borrowed payload; this object never becomes persistent state.
    __slots__ = ("transport", "src_ip", "src_port", "dst_ip", "dst_port",
                 "ip_length", "seq", "ack", "flags", "payload", "payload_length",
                 "truncated", "loopback", "outgoing")


def _parse_packet(data, linktype, caplen, wirelen):
    try:
        view = memoryview(data).cast("B")
    except (TypeError, ValueError):
        return None, "invalid"
    caplen = len(view) if caplen is None else caplen
    wirelen = caplen if wirelen is None else wirelen
    if (type(caplen) is not int or type(wirelen) is not int or
            caplen < 0 or caplen > len(view) or caplen > SNAPLEN or wirelen < caplen):
        return None, "invalid"
    view = view[:caplen]
    loopback = outgoing = False
    if type(linktype) is not int:
        return None, "unsupported_linktype"
    if linktype == DLT_EN10MB:
        offset = 14
        if caplen < offset:
            return None, "truncated"
        protocol = struct.unpack_from("!H", view, 12)[0]
    elif linktype == DLT_LINUX_SLL:
        offset = 16
        if caplen < offset:
            return None, "truncated"
        packet_type, hardware = struct.unpack_from("!HH", view)
        protocol = struct.unpack_from("!H", view, 14)[0]
        loopback, outgoing = hardware == 772, packet_type == 4
    elif linktype == DLT_LINUX_SLL2:
        offset = 20
        if caplen < offset:
            return None, "truncated"
        protocol = struct.unpack_from("!H", view)[0]
        hardware = struct.unpack_from("!H", view, 8)[0]
        loopback, outgoing = hardware == 772, view[10] == 4
    elif linktype in _RAW_TYPES:
        offset, protocol = 0, 0x0800
    else:
        return None, "unsupported_linktype"
    if loopback and outgoing:
        return None, "loopback_duplicate"
    if protocol != 0x0800:
        return None, "filtered"
    if caplen < offset + 20:
        return None, "truncated"
    if view[offset] >> 4 != 4:
        return None, "filtered"
    ihl = (view[offset] & 15) * 4
    total = struct.unpack_from("!H", view, offset + 2)[0]
    if ihl < 20 or total < ihl or offset + total > wirelen:
        return None, "invalid"
    if caplen < offset + ihl:
        return None, "truncated"
    fragment = struct.unpack_from("!H", view, offset + 6)[0]
    if fragment & 0x8000:
        return None, "invalid"
    if fragment & 0x3FFF:  # MF or any nonzero offset, including first fragments
        return None, "fragmented"
    protocol = view[offset + 9]
    if protocol not in (6, 17):
        return None, "filtered"
    pos = offset + ihl
    end = min(caplen, offset + total)
    minimum = 20 if protocol == 6 else 8
    if total - ihl < minimum:
        return None, "invalid"
    if end < pos + minimum:
        return None, "truncated"
    packet = _Packet()
    packet.transport = "tcp" if protocol == 6 else "udp"
    packet.src_ip = socket.inet_ntoa(view[offset + 12:offset + 16])
    packet.dst_ip = socket.inet_ntoa(view[offset + 16:offset + 20])
    packet.src_port, packet.dst_port = struct.unpack_from("!HH", view, pos)
    if not packet.src_port or not packet.dst_port:
        return None, "invalid"
    packet.ip_length = total
    packet.truncated = caplen < offset + total
    packet.loopback, packet.outgoing = loopback, outgoing
    packet.seq = packet.ack = packet.flags = 0
    if protocol == 6:
        header_length = (view[pos + 12] >> 4) * 4
        if header_length < 20 or header_length > total - ihl:
            return None, "invalid"
        if end < pos + header_length:
            return None, "truncated"
        packet.seq, packet.ack = struct.unpack_from("!II", view, pos + 4)
        packet.flags = view[pos + 13]
        packet.payload_length = total - ihl - header_length
        packet.payload = view[pos + header_length:end]
    else:
        udp_length = struct.unpack_from("!H", view, pos + 4)[0]
        if udp_length < 8 or udp_length > total - ihl:
            return None, "invalid"
        packet.payload_length = udp_length - 8
        packet.payload = view[pos + 8:min(end, pos + udp_length)]
    return packet, None


class _Flow:
    __slots__ = ("key", "flow_id", "coverage", "last_seen", "last_ts", "start_ts", "isn",
                 "prefix", "mask", "seen_end", "poisoned", "fingerprinted",
                 "client_length", "fin_end", "fin_acked", "udp_samples",
                 "stream_window", "stream_samples", "stream_sequence",
                 "up_bytes", "down_bytes", "up_packets", "down_packets")

    def __init__(self, key, flow_id, now, capture_ts, isn=None):
        self.key, self.flow_id = key, flow_id
        self.coverage = "udp" if key[0] == "udp" else ("syn" if isn is not None else "midstream")
        self.last_seen, self.last_ts, self.start_ts = now, capture_ts, capture_ts
        self.isn = isn
        self.prefix = bytearray(PREFIX_BYTES) if isn is not None else None
        self.mask = self.seen_end = 0
        self.poisoned = self.fingerprinted = False
        self.client_length = None
        self.fin_end, self.fin_acked = [None, None], [False, False]
        self.udp_samples = 0
        self.stream_window, self.stream_samples, self.stream_sequence = None, 0, None
        self.up_bytes = self.down_bytes = self.up_packets = self.down_packets = 0


_COUNTERS = (
    "packets_seen", "packets_parsed", "packets_filtered", "packets_invalid",
    "packets_truncated", "packets_snaplen_limited", "packets_fragmented", "packets_unsupported_linktype",
    "packets_loopback_duplicate", "tcp_without_syn_packets", "tcp_without_syn_bytes",
    "tcp_syn_retransmissions", "tcp_conflicting_retransmissions", "tcp_incomplete_prefixes",
    "tcp_prefix_gap_observations", "tcp_prefix_gaps_on_close", "midstream_flows",
    "udp_incomplete_datagrams", "flows_created", "flows_expired", "flows_evicted",
    "callback_errors", "tcp_stream_fingerprints",
)


class Capture:
    """Required API plus flush() / feed_packet() for deterministic offline input.

    Optional max_flows/tcp_idle_ttl/udp_idle_ttl only lower the hard limits.
    flush_interval is 0.05..60 seconds, default 1.0. Offline now is monotonic;
    capture_ts is always epoch seconds, never a monotonic value.
    snaplen is selected automatically: 256 for TCP-only, 65535 with UDP ports.
    """

    def __init__(self, interface, tcp_ports, udp_ports, callback, *,
                 max_flows=MAX_FLOWS, tcp_idle_ttl=TCP_IDLE_TTL,
                 udp_idle_ttl=UDP_IDLE_TTL, flush_interval=1.0,
                 tcp_stream_fingerprints=False):
        if type(tcp_stream_fingerprints) is not bool:
            raise ValueError("invalid_tcp_stream_fingerprints")
        self.tcp_stream_fingerprints = tcp_stream_fingerprints
        if (not isinstance(interface, str) or not interface or "\0" in interface or
                interface.lower() == "any"):
            raise ValueError("explicit_interface_required")
        try:
            encoded = interface.encode("utf-8")
        except UnicodeError:
            raise ValueError("invalid_interface") from None
        if len(encoded) > 255:
            raise ValueError("invalid_interface")
        if not callable(callback):
            raise ValueError("callback_required")
        if type(max_flows) is not int or not 1 <= max_flows <= MAX_FLOWS:
            raise ValueError("invalid_flow_limit")
        for value, ceiling, name in ((tcp_idle_ttl, TCP_IDLE_TTL, "tcp_idle_ttl"),
                                     (udp_idle_ttl, UDP_IDLE_TTL, "udp_idle_ttl"),
                                     (flush_interval, 60.0, "flush_interval")):
            if (isinstance(value, bool) or not isinstance(value, (float, int)) or
                    not math.isfinite(value) or not 0 < value <= ceiling):
                raise ValueError("invalid_" + name)
        if flush_interval < 0.05:
            raise ValueError("invalid_flush_interval")
        self.interface, self.callback = interface, callback
        self.tcp_ports, self.udp_ports = _ports(tcp_ports), _ports(udp_ports)
        self.bpf = build_bpf(self.tcp_ports, self.udp_ports)
        self.snaplen = SNAPLEN if self.udp_ports else _TCP_SNAPLEN
        self.max_flows = max_flows
        self._ttls = {"tcp": float(tcp_idle_ttl), "udp": float(udp_idle_ttl)}
        self.flush_interval = float(flush_interval)
        self._flows = {"tcp": OrderedDict(), "udp": OrderedDict()}
        self._next_expiry = float("inf")
        self._dirty = set()
        self._instance, self._generation = uuid.uuid4().hex, 0
        self._counts = dict.fromkeys(_COUNTERS, 0)
        self._gate, self._flush_requested = threading.Lock(), threading.Event()
        self._last_now = self._last_flush = None
        self._last_capture_ts = self._capture_mono = None
        self._coverage_snapshot = self._drop_snapshot = None
        self._pcap_stats = {}

    def _emit(self, event):
        try:
            self.callback(event)
        except Exception:
            self._counts["callback_errors"] += 1

    def _epoch(self, now=None):
        if self._last_capture_ts is None:
            return time.time()
        if now is None:
            now = self._last_now
        return self._last_capture_ts + max(0, now - self._capture_mono)

    def _base(self, flow, event_type, capture_ts=None):
        transport, src_ip, src_port, dst_ip, dst_port = flow.key
        return {"type": event_type, "interface": self.interface,
                "transport": transport, "src_ip": src_ip, "src_port": src_port,
                "dst_ip": dst_ip, "dst_port": dst_port, "flow_id": flow.flow_id,
                "capture_ts": flow.last_ts if capture_ts is None else capture_ts,
                "flow_start_ts": flow.start_ts, "coverage": flow.coverage}

    def _health(self, status, **fields):
        event = {"type": "health", "interface": self.interface,
                 "status": status, "capture_ts": self._epoch()}
        # audit.py retains the latest health OR stats event per interface.
        # Preserve drop counters in later coverage/stopped health updates.
        event.update(self._pcap_stats)
        event.update(fields)
        self._emit(event)

    def _coverage(self):
        snapshot = tuple(self._counts[name] for name in _COUNTERS)
        if snapshot != self._coverage_snapshot:
            self._coverage_snapshot = snapshot
            self._health("coverage", counters=dict(self._counts),
                         active_flows=sum(len(table) for table in self._flows.values()),
                         tcp_fingerprint_requires_syn=not self.tcp_stream_fingerprints,
                         wire_basis="ipv4_total_length",
                         wire_aggregation="single_front_interface_only")

    def _clock(self, now):
        now = time.monotonic() if now is None else now
        if isinstance(now, bool) or not isinstance(now, (float, int)) or not math.isfinite(now):
            raise ValueError("invalid_monotonic_time")
        self._last_now = now if self._last_now is None else max(now, self._last_now)
        return self._last_now

    def _wire(self, flow, reason, final=False):
        if final or flow.up_packets or flow.down_packets:
            event = self._base(flow, "wire_delta")
            event.update(up_bytes=flow.up_bytes, down_bytes=flow.down_bytes,
                         up_packets=flow.up_packets, down_packets=flow.down_packets,
                         final=final, reason=reason, wire_basis="ipv4_total_length")
            flow.up_bytes = flow.down_bytes = flow.up_packets = flow.down_packets = 0
            self._dirty.discard(flow.key)
            self._emit(event)

    def _has_gap(self, flow):
        return (flow.coverage == "syn" and not flow.fingerprinted and not flow.poisoned and
                flow.mask & ((1 << flow.seen_end) - 1) != (1 << flow.seen_end) - 1)

    def _tcp_fingerprint(self, flow, capture_ts, short_length=None):
        if flow.coverage != "syn" or flow.fingerprinted or flow.poisoned:
            return
        if short_length is not None and short_length < flow.seen_end:
            return  # contradictory FIN must not turn a longer stream into a short hash
        length = PREFIX_BYTES if short_length is None else min(PREFIX_BYTES, max(0, short_length))
        if not length or flow.mask & ((1 << length) - 1) != (1 << length) - 1:
            return
        digest = hashlib.sha256(memoryview(flow.prefix)[:length]).hexdigest()
        flow.fingerprinted, flow.prefix, flow.mask = True, None, 0
        event = self._base(flow, "fingerprint", capture_ts)
        event.update(fingerprint=digest, bytes_hashed=length, sample_index=1, sample_kind="tcp_prefix")
        self._emit(event)

    def _finish(self, flow, reason, capture_ts=None):
        if flow.coverage == "syn":
            self._tcp_fingerprint(flow, flow.last_ts, flow.client_length)
            if not flow.fingerprinted:
                self._counts["tcp_incomplete_prefixes"] += 1
                if self._has_gap(flow):
                    self._counts["tcp_prefix_gaps_on_close"] += 1
        self._flows[flow.key[0]].pop(flow.key, None)
        flow.prefix = None
        self._wire(flow, reason, final=True)
        event = self._base(flow, "flow_close", self._epoch() if capture_ts is None else capture_ts)
        event["reason"] = reason
        self._emit(event)

    def _expire(self, now):
        if now < self._next_expiry:
            return
        self._next_expiry = float("inf")
        for transport, table in self._flows.items():
            while table:
                flow = next(iter(table.values()))
                deadline = flow.last_seen + self._ttls[transport]
                if now < deadline:
                    self._next_expiry = min(self._next_expiry, deadline)
                    break
                self._counts["flows_expired"] += 1
                self._finish(flow, "idle_timeout", self._epoch(now))
        # Touching/removing an existing flow can only postpone this lower bound.
        # A new flow must lower it explicitly, especially UDP after a TCP flow.

    def _new_flow(self, key, now, capture_ts, isn=None):
        if sum(len(table) for table in self._flows.values()) >= self.max_flows:
            oldest = min((next(iter(table.values())) for table in self._flows.values() if table),
                         key=lambda flow: flow.last_seen)
            self._counts["flows_evicted"] += 1
            self._finish(oldest, "capacity", capture_ts)
        self._generation += 1
        flow = _Flow(key, "%s:%x" % (self._instance, self._generation), now, capture_ts, isn)
        self._flows[key[0]][key] = flow
        self._next_expiry = min(self._next_expiry, now + self._ttls[key[0]])
        self._counts["flows_created"] += 1
        if flow.coverage == "midstream":
            self._counts["midstream_flows"] += 1
        self._emit(self._base(flow, "flow_open"))
        return flow

    def _orientation(self, packet, opening_syn):
        ports = self.tcp_ports if packet.transport == "tcp" else self.udp_ports
        forward = (packet.transport, packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
        reverse = (packet.transport, packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port)
        table = self._flows[packet.transport]
        # An opening client SYN targets the listener, even on an occupied tuple.
        if not opening_syn:
            if packet.dst_port in ports and forward in table:
                return forward, True
            if packet.src_port in ports and reverse in table:
                return reverse, False
        if packet.dst_port in ports:
            return forward, True
        if packet.src_port in ports:
            return reverse, False
        return None, False

    def _tcp_payload(self, flow, packet, capture_ts):
        if flow.coverage != "syn" or flow.fingerprinted or flow.poisoned:
            return
        sequence = (packet.seq + bool(packet.flags & _SYN)) & _MASK32
        offset = _seq_delta(sequence, (flow.isn + 1) & _MASK32)
        declared_end = offset + packet.payload_length
        if packet.payload_length and declared_end > 0:
            flow.seen_end = max(flow.seen_end, min(PREFIX_BYTES, declared_end))
        start, end = max(0, offset), min(PREFIX_BYTES, offset + len(packet.payload))
        for index in range(start, end):
            value, bit = packet.payload[index - offset], 1 << index
            if flow.mask & bit and flow.prefix[index] != value:
                flow.poisoned, flow.prefix, flow.mask = True, None, 0
                self._counts["tcp_conflicting_retransmissions"] += 1
                return
            flow.prefix[index] = value
            flow.mask |= bit
        if self._has_gap(flow):
            self._counts["tcp_prefix_gap_observations"] += 1
        self._tcp_fingerprint(flow, capture_ts)
        if flow.client_length is not None:
            self._tcp_fingerprint(flow, capture_ts, flow.client_length)

    def _tcp_stream_fingerprint(self, flow, packet, upstream, capture_ts):
        if not self.tcp_stream_fingerprints or flow.poisoned:
            return
        sequence = (packet.seq + bool(packet.flags & _SYN)) & _MASK32
        window = int(capture_ts // 10)
        if flow.stream_window != window:
            flow.stream_window, flow.stream_samples = window, 0
        for offset in range((-sequence) % 32, len(packet.payload) - 31, 32):
            if flow.stream_samples >= 3:
                return
            block_sequence = (sequence + offset) & _MASK32
            position = (upstream, block_sequence)
            if flow.stream_sequence == position:
                continue
            digest = hashlib.sha256(b"traffic-audit/tcp-stream/v1\0" +
                                    struct.pack("!?I", upstream, block_sequence))
            digest.update(packet.payload[offset:offset + 32])
            flow.stream_sequence = position
            flow.stream_samples += 1
            self._counts["tcp_stream_fingerprints"] += 1
            event = self._base(flow, "fingerprint", capture_ts)
            event.update(fingerprint=digest.hexdigest(), bytes_hashed=32,
                         sample_index=flow.stream_samples, sample_kind="tcp_stream_block")
            self._emit(event)

    def _tcp(self, flow, packet, upstream, capture_ts):
        if upstream:
            self._tcp_payload(flow, packet, capture_ts)
        self._tcp_stream_fingerprint(flow, packet, upstream, capture_ts)
        direction, opposite = (0, 1) if upstream else (1, 0)
        if packet.flags & _ACK and flow.fin_end[opposite] is not None:
            if _seq_delta(packet.ack, flow.fin_end[opposite]) >= 0:
                flow.fin_acked[opposite] = True
        if packet.flags & _RST:
            self._tcp_fingerprint(flow, capture_ts, flow.seen_end)
            self._finish(flow, "rst", capture_ts)
            return
        if packet.flags & _FIN:
            end = (packet.seq + bool(packet.flags & _SYN) + packet.payload_length) & _MASK32
            if upstream and flow.coverage == "syn":
                length = _seq_delta(end, (flow.isn + 1) & _MASK32)
                if length < 0:  # old FIN preceding this generation's SYN
                    return
                if flow.client_length is None:
                    flow.client_length = length
                flow.seen_end = max(flow.seen_end, min(PREFIX_BYTES, length))
                if self._has_gap(flow):
                    self._counts["tcp_prefix_gap_observations"] += 1
                self._tcp_fingerprint(flow, capture_ts, flow.client_length)
            if flow.fin_end[direction] is None:
                flow.fin_end[direction] = (end + 1) & _MASK32
            # Prompt FIN delta, but no close until half-close traffic is finished.
            self._wire(flow, "fin")
        # An ACK flag becomes true only after the corresponding FIN was seen.
        if flow.fin_acked[0] and flow.fin_acked[1]:
            self._finish(flow, "fin_acknowledged", capture_ts)

    def _udp(self, flow, packet, upstream, capture_ts):
        if not upstream or flow.udp_samples >= 3 or not packet.payload_length:
            return
        if packet.truncated or len(packet.payload) != packet.payload_length:
            self._counts["udp_incomplete_datagrams"] += 1
            return
        digest = hashlib.sha256()
        for offset in range(0, packet.payload_length, PREFIX_BYTES):
            digest.update(packet.payload[offset:offset + PREFIX_BYTES])
        flow.udp_samples += 1
        event = self._base(flow, "fingerprint", capture_ts)
        event.update(fingerprint=digest.hexdigest(), bytes_hashed=packet.payload_length,
                     sample_index=flow.udp_samples, sample_kind="udp_datagram")
        self._emit(event)

    def _consume(self, data, linktype, capture_ts, wirelen, caplen, now):
        self._counts["packets_seen"] += 1
        if (isinstance(capture_ts, bool) or not isinstance(capture_ts, (float, int)) or
                not math.isfinite(capture_ts)):
            self._counts["packets_invalid"] += 1
            return
        self._last_capture_ts, self._capture_mono = capture_ts, now
        packet, reason = _parse_packet(data, linktype, caplen, wirelen)
        if packet is None:
            self._counts["packets_" + reason] += 1
            return
        self._counts["packets_parsed"] += 1
        if packet.truncated:
            captured = caplen if caplen is not None else memoryview(data).nbytes
            # Complete TCP headers at the configured small snaplen: deliberately
            # omitted tail, not packet loss. Reassembly still reports real gaps.
            expected_clip = (packet.transport == "tcp" and self.snaplen == _TCP_SNAPLEN
                             and captured == self.snaplen)
            self._counts["packets_snaplen_limited" if expected_clip else "packets_truncated"] += 1
        opening_syn = (packet.transport == "tcp" and packet.flags & _SYN and
                       not packet.flags & (_ACK | _RST | _FIN))
        key, upstream = self._orientation(packet, opening_syn)
        if key is None:
            self._counts["packets_filtered"] += 1
            return
        table = self._flows[packet.transport]
        flow = table.get(key)
        if packet.transport == "tcp" and upstream and opening_syn:
            if flow is not None and (flow.coverage != "syn" or flow.isn != packet.seq):
                self._finish(flow, "tuple_reuse", capture_ts)
                flow = None
            if flow is None:
                flow = self._new_flow(key, now, capture_ts, packet.seq)
            else:
                self._counts["tcp_syn_retransmissions"] += 1
        elif flow is None:
            flow = self._new_flow(key, now, capture_ts)
        if flow.coverage == "midstream":
            self._counts["tcp_without_syn_packets"] += 1
            self._counts["tcp_without_syn_bytes"] += packet.ip_length
        flow.last_seen, flow.last_ts = now, capture_ts
        table.move_to_end(key)
        if upstream:
            flow.up_bytes += packet.ip_length
            flow.up_packets += 1
        else:
            flow.down_bytes += packet.ip_length
            flow.down_packets += 1
        self._dirty.add(key)
        if packet.transport == "tcp":
            self._tcp(flow, packet, upstream, capture_ts)
        else:
            self._udp(flow, packet, upstream, capture_ts)

    def _flush(self, now, reason):
        self._flush_requested.clear()
        self._expire(now)
        for key in tuple(self._dirty):  # bounded snapshot, no callback mutation
            flow = self._flows[key[0]].get(key)
            if flow is not None:
                self._wire(flow, reason)
        self._last_flush = now
        self._coverage()

    def _tick(self, now):
        self._expire(now)
        if self._last_flush is None:
            self._last_flush = now
        if self._flush_requested.is_set() or now - self._last_flush >= self.flush_interval:
            self._flush(now, "interval")

    def feed_packet(self, data, linktype, capture_ts, wirelen=None, caplen=None, *, now=None):
        """Process one offline packet; no supplied buffer is retained after return."""
        if not self._gate.acquire(False):
            raise CaptureError("capture_busy")
        try:
            now = self._clock(now)
            self._expire(now)
            self._consume(data, linktype, capture_ts, wirelen, caplen, now)
            self._tick(now)
        finally:
            self._gate.release()

    def flush(self, *, now=None):
        """Emit pending deltas and expire idle flows, or request an owner-thread flush."""
        if not self._gate.acquire(False):
            self._flush_requested.set()
            return
        try:
            self._flush(self._clock(now), "manual")
        finally:
            self._gate.release()

    def _capture_stats(self, backend):
        try:
            stats = backend.stats()
        except Exception:
            stats = {"packets_received": None, "packets_dropped": None,
                     "packets_if_dropped": None, "stats_available": False}
        if stats.get("stats_available"):
            self._pcap_stats = dict(stats)
        else:
            # A failed read is unknown, not evidence that earlier drops vanished.
            stats = dict(stats, **{key: value for key, value in self._pcap_stats.items()
                                 if key != "stats_available"})
            self._pcap_stats = dict(stats)
        event = {"type": "capture_stats", "interface": self.interface,
                 "capture_ts": self._epoch(),
                 "active_flows": sum(len(table) for table in self._flows.values()),
                 "counters": dict(self._counts)}
        event.update(stats)
        self._emit(event)
        if stats.get("stats_available"):
            drops = (stats["packets_dropped"], stats["packets_if_dropped"])
            previous = self._drop_snapshot or (0, 0)
            if any(new > old for new, old in zip(drops, previous)):
                self._health("pcap_drops", packets_dropped=drops[0], packets_if_dropped=drops[1])
            self._drop_snapshot = drops
        else:
            self._health("pcap_stats_unavailable")

    def run(self, stop_event):
        """Block until stopped. Only the owner thread accesses the pcap handle.

        Setup/read failures close flows/resources, emit sanitized health and raise
        CaptureError. An already-set stop_event skips libpcap entirely.
        """
        if not self._gate.acquire(False):
            raise CaptureError("capture_busy")
        backend, failure, reason = None, None, "stop"
        try:
            if not stop_event.is_set():
                backend = _Pcap(self.interface, self.bpf, self.snaplen)
                self._health("started", linktype=backend.linktype, snaplen=self.snaplen,
                             loopback=backend.loopback, loopback_dedup=backend.loopback_dedup,
                             immediate_mode=True, nonblocking=True,
                             activation_warning=backend.activation_warning,
                             tcp_fingerprint_requires_syn=not self.tcp_stream_fingerprints,
                             wire_aggregation="single_front_interface_only")
                last_stats = time.monotonic()
                while not stop_event.is_set():
                    idle = False
                    for _ in range(256):  # stop/timers get serviced even under flood
                        if stop_event.is_set():
                            break
                        record = backend.next_packet()
                        if record is None:
                            idle = True
                            break
                        data, capture_ts, caplen, wirelen = record
                        now = self._clock(None)
                        self._expire(now)
                        self._consume(data, backend.linktype, capture_ts, wirelen, caplen, now)
                        del data, record  # borrowed views expire before next pcap read
                    now = self._clock(None)
                    self._tick(now)
                    if now - last_stats >= _STATS_INTERVAL:
                        self._capture_stats(backend)
                        last_stats = now
                    if idle:
                        stop_event.wait(_POLL_INTERVAL)
        except _PcapError as error:
            failure, reason = error.code, "capture_error"
        except Exception:
            failure, reason = "internal_error", "capture_error"
        finally:
            try:
                self._clock(None)
                if failure is not None:
                    self._health("error", error_code=failure)
                for table in self._flows.values():
                    while table:
                        self._finish(next(iter(table.values())), reason)
                self._coverage()
                if backend is not None:
                    self._capture_stats(backend)
                self._health("stopped", reason=reason, counters=dict(self._counts))
            finally:
                try:
                    if backend is not None:
                        backend.close()
                finally:
                    self._gate.release()
        if failure is not None:
            raise CaptureError(failure) from None

# timeval uses C long, including Windows' 32-bit long ABI.
class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _PcapHeader(ctypes.Structure):
    _fields_ = [("ts", _Timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


class _PcapStat(ctypes.Structure):
    _fields_ = [("ps_recv", ctypes.c_uint), ("ps_drop", ctypes.c_uint), ("ps_ifdrop", ctypes.c_uint)]
    if os.name == "nt":
        _fields_ += [("ps_capt", ctypes.c_uint), ("ps_sent", ctypes.c_uint), ("ps_netdrop", ctypes.c_uint)]


class _PcapDevice(ctypes.Structure):
    pass


_PcapDevice._fields_ = [("next", ctypes.POINTER(_PcapDevice)), ("name", ctypes.c_char_p),
                       ("description", ctypes.c_char_p), ("addresses", ctypes.c_void_p),
                       ("flags", ctypes.c_uint)]


class _PcapError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _bind(library, name, restype, argtypes, optional=False):
    function = getattr(library, name, None)
    if function is None:
        if optional:
            return None
        raise _PcapError("pcap_missing_symbol")
    function.restype, function.argtypes = restype, argtypes
    return function


class _Pcap:
    """Owner-thread-only backend; never emits native error buffer contents."""

    def __init__(self, interface, bpf, snaplen=SNAPLEN):
        self.owner, self.handle = threading.get_ident(), None
        self.snaplen = snaplen
        try:
            name = ctypes.util.find_library("wpcap" if os.name == "nt" else "pcap")
            self.lib = ctypes.CDLL(name or ("wpcap.dll" if os.name == "nt" else "libpcap.so.1"))
        except Exception:
            raise _PcapError("pcap_library_unavailable") from None
        integer, pointer, string = ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p
        self._create = _bind(self.lib, "pcap_create", pointer, [string, string])
        self._close = _bind(self.lib, "pcap_close", None, [pointer])
        self._activate = _bind(self.lib, "pcap_activate", integer, [pointer])
        self._next = _bind(self.lib, "pcap_next_ex", integer,
                           [pointer, ctypes.POINTER(ctypes.POINTER(_PcapHeader)),
                            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))])
        self._stats = _bind(self.lib, "pcap_stats", integer, [pointer, ctypes.POINTER(_PcapStat)])
        self._datalink = _bind(self.lib, "pcap_datalink", integer, [pointer])
        self._nonblock = _bind(self.lib, "pcap_setnonblock", integer, [pointer, integer, string])
        self._compile = _bind(self.lib, "pcap_compile", integer,
                              [pointer, ctypes.POINTER(_BpfProgram), string, integer, ctypes.c_uint32])
        self._filter = _bind(self.lib, "pcap_setfilter", integer, [pointer, ctypes.POINTER(_BpfProgram)])
        self._freecode = _bind(self.lib, "pcap_freecode", None, [ctypes.POINTER(_BpfProgram)])
        self._direction = _bind(self.lib, "pcap_setdirection", integer, [pointer, integer], optional=True)
        setters = [(name, _bind(self.lib, name, integer, [pointer, integer]), value)
                   for name, value in (("pcap_set_snaplen", self.snaplen), ("pcap_set_promisc", 0),
                                       ("pcap_set_timeout", 100), ("pcap_set_immediate_mode", 1),
                                       ("pcap_set_buffer_size", _PCAP_BUFFER_SIZE))]
        self.loopback = self._is_loopback(interface)
        self.loopback_dedup = "not_loopback"
        error_buffer = ctypes.create_string_buffer(256)
        try:
            self.handle = self._create(interface.encode("utf-8"), error_buffer)
            if not self.handle:
                raise _PcapError("pcap_create_failed")
            for name, setter, value in setters:
                if setter(self.handle, value) != 0:
                    raise _PcapError(name + "_failed")
            self.activation_warning = self._activate(self.handle)
            if self.activation_warning < 0:
                raise _PcapError("pcap_activate_failed")
            self.linktype = self._datalink(self.handle)
            if self.linktype not in _LINK_TYPES:
                raise _PcapError("unsupported_linktype")
            if self._nonblock(self.handle, 1, error_buffer) != 0:
                raise _PcapError("pcap_nonblock_failed")
            if self.loopback:
                if self._direction is not None and self._direction(self.handle, 1) == 0:
                    self.loopback_dedup = "pcap_inbound"  # PCAP_D_IN, NOT server-only traffic
                elif self.linktype in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
                    self.loopback_dedup = "cooked_direction"
                else:
                    raise _PcapError("loopback_direction_unavailable")
            program = _BpfProgram()
            if self._compile(self.handle, ctypes.byref(program), bpf.encode("ascii"), 1, _MASK32) != 0:
                raise _PcapError("pcap_compile_failed")
            try:
                if self._filter(self.handle, ctypes.byref(program)) != 0:
                    raise _PcapError("pcap_filter_failed")
            finally:
                self._freecode(ctypes.byref(program))
        except Exception:
            self.close()
            raise

    def _is_loopback(self, interface):
        known = interface == "lo" or (interface.startswith("lo") and interface[2:].isdigit())
        known = known or interface.lower() == r"\device\npf_loopback"
        find = _bind(self.lib, "pcap_findalldevs", ctypes.c_int,
                     [ctypes.POINTER(ctypes.POINTER(_PcapDevice)), ctypes.c_char_p], optional=True)
        free = _bind(self.lib, "pcap_freealldevs", None, [ctypes.POINTER(_PcapDevice)], optional=True)
        if find is None or free is None:
            return known
        devices = ctypes.POINTER(_PcapDevice)()
        error_buffer = ctypes.create_string_buffer(256)
        try:
            if find(ctypes.byref(devices), error_buffer) != 0:
                raise _PcapError("pcap_interface_discovery_failed")
            device = devices
            for _ in range(4096):
                if not device:
                    break
                if device.contents.name == interface.encode("utf-8"):
                    return bool(device.contents.flags & 1) or known  # PCAP_IF_LOOPBACK
                device = device.contents.next
            return known
        finally:
            if devices:
                free(devices)

    def _owner_check(self):
        if threading.get_ident() != self.owner:
            raise _PcapError("pcap_wrong_thread")

    def next_packet(self):
        self._owner_check()
        header = ctypes.POINTER(_PcapHeader)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        result = self._next(self.handle, ctypes.byref(header), ctypes.byref(data))
        if result == 0:
            return None
        if result != 1:
            raise _PcapError("pcap_read_failed")
        if not header or not data:
            raise _PcapError("pcap_invalid_packet_header")
        captured, wire = header.contents.caplen, header.contents.len
        stamp = header.contents.ts
        if captured > self.snaplen or captured > wire or not 0 <= stamp.tv_usec < 1000000:
            raise _PcapError("pcap_invalid_packet_header")
        frame = (ctypes.c_ubyte * captured).from_address(ctypes.addressof(data.contents))
        return memoryview(frame).cast("B"), stamp.tv_sec + stamp.tv_usec / 1000000.0, captured, wire

    def stats(self):
        self._owner_check()
        stats = _PcapStat()
        if self._stats(self.handle, ctypes.byref(stats)) != 0:
            raise _PcapError("pcap_stats_failed")
        return {"packets_received": stats.ps_recv, "packets_dropped": stats.ps_drop,
                "packets_if_dropped": stats.ps_ifdrop, "stats_available": True}

    def close(self):
        self._owner_check()
        if self.handle:
            handle, self.handle = self.handle, None
            self._close(handle)
