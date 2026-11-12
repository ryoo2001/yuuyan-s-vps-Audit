import ctypes
import ctypes.util
import socket
import struct
import unittest

from edge_front import front_bpf


class Timeval(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("micros", ctypes.c_long)]


class PacketHeader(ctypes.Structure):
    _fields_ = [("time", Timeval), ("caplen", ctypes.c_uint32), ("length", ctypes.c_uint32)]


class BpfProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint), ("instructions", ctypes.c_void_p)]


class FrontCaptureTests(unittest.TestCase):
    def test_both_protocols_are_bound_to_front_endpoint(self):
        value = front_bpf("172.29.78.213", [28900], [28900])
        self.assertIn("dst host 172.29.78.213 and (dst port 28900)", value)
        self.assertIn("src host 172.29.78.213 and (src port 28900)", value)
        self.assertIn("tcp and", value)
        self.assertIn("udp and", value)

    def test_invalid_address_cannot_inject_filter(self):
        for value in ["172.29.78.213 or ip", "::1", "hostname", "999.1.1.1"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                front_bpf(value, [28900], [])

    def test_invalid_or_empty_ports_fail_closed(self):
        for value in [[True], [0], [65536], ["28900"], []]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                front_bpf("172.29.78.213", value, [])

    def test_single_protocol_and_deduplicated_ports(self):
        value = front_bpf("172.29.78.213", [28901, 28900, 28900], [])
        self.assertNotIn("udp", value)
        self.assertEqual(value.count("dst port 28900"), 1)
        self.assertIn("dst port 28900 or dst port 28901", value)

    @unittest.skipUnless(ctypes.util.find_library("pcap"), "requires native libpcap")
    def test_libpcap_excludes_both_snat_legs_for_tcp_and_udp(self):
        lib = ctypes.CDLL(ctypes.util.find_library("pcap"))
        lib.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
        lib.pcap_open_dead.restype = ctypes.c_void_p
        lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
        lib.pcap_offline_filter.argtypes = [ctypes.POINTER(BpfProgram), ctypes.POINTER(PacketHeader), ctypes.c_void_p]
        lib.pcap_freecode.argtypes = [ctypes.POINTER(BpfProgram)]
        lib.pcap_close.argtypes = [ctypes.c_void_p]
        handle = lib.pcap_open_dead(1, 65535)
        self.assertTrue(handle)
        program = BpfProgram()
        compiled = False
        try:
            self.assertEqual(lib.pcap_compile(handle, ctypes.byref(program), front_bpf("172.29.78.213", [28900], [28900]).encode(), 1, 0xffffffff), 0)
            compiled = True
            for transport, protocol in [("tcp", 6), ("udp", 17)]:
                cases = [
                    ("198.51.100.7", 41000, "172.29.78.213", 28900, True),
                    ("172.29.78.213", 28900, "198.51.100.7", 41000, True),
                    ("172.29.78.213", 41000, "203.0.113.104", 28900, False),
                    ("203.0.113.104", 28900, "172.29.78.213", 41000, False),
                ]
                for src, sport, dst, dport, expected in cases:
                    payload = struct.pack("!HH", sport, dport) + bytes(16 if protocol == 6 else 4)
                    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0, socket.inet_aton(src), socket.inet_aton(dst))
                    packet = bytes(12) + b"\x08\x00" + ipv4 + payload
                    header = PacketHeader(Timeval(0, 0), len(packet), len(packet))
                    buffer = ctypes.create_string_buffer(packet)
                    with self.subTest(transport=transport, src=src, sport=sport, dst=dst, dport=dport):
                        self.assertEqual(bool(lib.pcap_offline_filter(ctypes.byref(program), ctypes.byref(header), buffer)), expected)
        finally:
            if compiled:
                lib.pcap_freecode(ctypes.byref(program))
            lib.pcap_close(handle)


if __name__ == "__main__":
    unittest.main()
