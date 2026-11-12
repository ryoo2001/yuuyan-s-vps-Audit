#!/usr/bin/env python3
"""Edge-only capture adapter for public DNAT on a single interface.

Keep the deployed collector unchanged. Capture only the client-facing endpoint,
so the SNAT leg on the same interface cannot create duplicate fingerprints or
double-count ingress wire bytes.
"""
import argparse
import ipaddress
import json
from pathlib import Path


def front_bpf(address, tcp_ports, udp_ports):
    address = str(ipaddress.IPv4Address(address))
    clauses = []
    for transport, ports in (("tcp", tcp_ports), ("udp", udp_ports)):
        if not isinstance(ports, (list, tuple, set, frozenset)):
            raise ValueError("invalid_front_ports")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("invalid_front_ports")
        ports = sorted(set(ports))
        if ports:
            incoming = " or ".join("dst port " + str(port) for port in ports)
            outgoing = " or ".join("src port " + str(port) for port in ports)
            clauses.append(
                "(" + transport + " and ((dst host " + address + " and (" + incoming +
                ")) or (src host " + address + " and (" + outgoing + "))))"
            )
    if not clauses:
        raise ValueError("front_ports_required")
    return " or ".join(clauses)


def capture_front(self, spec):
    from capture import Capture
    collector = Capture(
        spec["interface"], spec.get("tcp_ports", []), spec.get("udp_ports", []),
        lambda event: self.capture_event(dict(event, interface=spec["interface"])),
        tcp_stream_fingerprints=self.config.get("tcp_stream_recovery", False)
    )
    collector.bpf = front_bpf(spec["front_address"], collector.tcp_ports, collector.udp_ports)
    from audit import STOP
    collector.run(STOP)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/traffic-audit/config.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    if config.get("mode") != "edge" or not config.get("captures"):
        raise ValueError("front_adapter_requires_edge_captures")
    for spec in config["captures"]:
        front_bpf(spec["front_address"], spec.get("tcp_ports", []), spec.get("udp_ports", []))
    import audit
    audit.Audit.capture = capture_front
    audit.main()


if __name__ == "__main__":
    main()
