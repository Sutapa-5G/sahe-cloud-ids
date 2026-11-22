"""Live packet-to-flow adapter for SAHE Cloud IDS/IPS.

This tool is intentionally separate from the FastAPI process. It captures only
traffic on an interface selected by the operator, aggregates packets into
bidirectional flows, and submits completed flow features to POST /detect.

Safety: use only on an interface/network you own or are explicitly authorized
to monitor. It does not generate traffic and it does not perform blocking.

Windows prerequisites:
  1. Install Wireshark with Npcap.
  2. In the project environment: python -m pip install scapy requests

Example:
  python tools/live_capture.py --interface "Wi-Fi" --api-url http://127.0.0.1:8000
  python tools/live_capture.py --list-interfaces
  python tools/live_capture.py --interface 1 --bpf "tcp or udp" --flow-timeout 5
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import requests
    from scapy.all import IP, IPv6, TCP, UDP, sniff, get_if_list
except ImportError as exc:  # pragma: no cover - exercised on a fresh machine
    missing = "requests and scapy"
    raise SystemExit(
        f"Missing live-capture dependency ({missing}). Install with: "
        "python -m pip install scapy requests"
    ) from exc


@dataclass
class Flow:
    first_seen: float
    last_seen: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    forward_lengths: list[int] = field(default_factory=list)
    backward_lengths: list[int] = field(default_factory=list)

    def add(self, timestamp: float, length: int, forward: bool) -> None:
        self.last_seen = timestamp
        if forward:
            self.forward_packets += 1
            self.forward_bytes += length
            self.forward_lengths.append(length)
        else:
            self.backward_packets += 1
            self.backward_bytes += length
            self.backward_lengths.append(length)

    def features(self) -> dict[str, float]:
        # CICFlowMeter-style Flow Duration is represented in microseconds in
        # the project's training fixture. Keep that unit for compatibility.
        duration_seconds = max(self.last_seen - self.first_seen, 1e-6)
        duration_us = duration_seconds * 1_000_000.0
        total_packets = self.forward_packets + self.backward_packets
        total_bytes = self.forward_bytes + self.backward_bytes
        return {
            "source_port": float(self.source_port),
            "destination_port": float(self.destination_port),
            "protocol": float(self.protocol),
            "flow_duration": float(duration_us),
            "total_fwd_packets": float(self.forward_packets),
            "total_backward_packets": float(self.backward_packets),
            "total_length_of_fwd_packets": float(self.forward_bytes),
            "total_length_of_bwd_packets": float(self.backward_bytes),
            "fwd_packet_length_mean": float(self.forward_bytes / self.forward_packets) if self.forward_packets else 0.0,
            "bwd_packet_length_mean": float(self.backward_bytes / self.backward_packets) if self.backward_packets else 0.0,
            "flow_bytes_s": float(total_bytes / duration_seconds),
            "flow_packets_s": float(total_packets / duration_seconds),
        }


class LiveCapture:
    def __init__(self, api_url: str, flow_timeout: float, dry_run: bool, token: str | None) -> None:
        self.api_url = api_url.rstrip("/") + "/detect"
        self.flow_timeout = flow_timeout
        self.dry_run = dry_run
        self.token = token
        self.flows: dict[tuple[Any, ...], Flow] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.submitted = 0
        self.failed = 0

    @staticmethod
    def _packet_info(packet: Any) -> tuple[str, str, int, int, int, int] | None:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return None
        src = str(ip_layer.src)
        dst = str(ip_layer.dst)
        proto = int(ip_layer.nh if packet.haslayer(IPv6) else ip_layer.proto)
        if packet.haslayer(TCP):
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        else:
            src_port = 0
            dst_port = 0
        return src, dst, src_port, dst_port, proto, len(packet)

    @staticmethod
    def _canonical_key(src: str, dst: str, sport: int, dport: int, proto: int) -> tuple[Any, ...]:
        left = (src, sport)
        right = (dst, dport)
        endpoints = tuple(sorted((left, right)))
        return proto, endpoints[0], endpoints[1]

    def on_packet(self, packet: Any) -> None:
        info = self._packet_info(packet)
        if info is None:
            return
        src, dst, sport, dport, proto, length = info
        now = float(getattr(packet, "time", time.time()))
        key = self._canonical_key(src, dst, sport, dport, proto)
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(now, now, src, dst, sport, dport, proto)
                self.flows[key] = flow
                forward = True
            else:
                forward = (src, sport) == (flow.source_ip, flow.source_port)
            flow.add(now, length, forward)

    def flush_expired(self) -> None:
        while not self.stop_event.wait(1.0):
            cutoff = time.time() - self.flow_timeout
            expired: list[Flow] = []
            with self.lock:
                for key, flow in list(self.flows.items()):
                    if flow.last_seen <= cutoff:
                        expired.append(self.flows.pop(key))
            for flow in expired:
                self.submit(flow)

    def flush_all(self) -> None:
        with self.lock:
            flows = list(self.flows.values())
            self.flows.clear()
        for flow in flows:
            self.submit(flow)

    def submit(self, flow: Flow) -> None:
        body = {"features": flow.features(), "source_ip": flow.source_ip}
        if self.dry_run:
            print(json.dumps(body, separators=(",", ":")))
            return
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = requests.post(self.api_url, json=body, headers=headers, timeout=10)
            response.raise_for_status()
            self.submitted += 1
            result = response.json()
            print(
                f"[DETECTION] {flow.source_ip}:{flow.source_port} -> "
                f"{flow.destination_ip}:{flow.destination_port} | "
                f"{result.get('attack_type')} | severity={result.get('severity')} | "
                f"malicious={result.get('is_malicious')}"
            )
        except requests.RequestException as exc:
            self.failed += 1
            print(f"[WARN] Could not submit flow to {self.api_url}: {exc}", file=sys.stderr)

    def run(self, interface: str, bpf: str | None) -> None:
        cleaner = threading.Thread(target=self.flush_expired, daemon=True)
        cleaner.start()
        print(f"[LIVE] Capturing on interface={interface!r}; flow timeout={self.flow_timeout}s")
        print("[LIVE] Press Ctrl+C to stop. Use only on an authorized network.")
        try:
            sniff(
                iface=interface,
                filter=bpf,
                prn=self.on_packet,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set(),
            )
        except PermissionError:
            raise SystemExit("Capture permission denied. Run the terminal with capture privileges and verify Npcap is installed.")
        finally:
            self.stop_event.set()
            self.flush_all()
            print(f"[LIVE] submitted={self.submitted}, failed={self.failed}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture authorized traffic, aggregate flows, and call SAHE /detect")
    parser.add_argument("--interface", help="Npcap interface name or number")
    parser.add_argument("--list-interfaces", action="store_true", help="List Scapy interface names and exit")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="SAHE backend base URL")
    parser.add_argument("--flow-timeout", type=float, default=5.0, help="Seconds of inactivity before a flow is submitted")
    parser.add_argument("--bpf", default="tcp or udp", help="Capture filter, for example 'tcp or udp'")
    parser.add_argument("--token", help="Optional bearer token for protected deployments")
    parser.add_argument("--dry-run", action="store_true", help="Print feature JSON instead of calling /detect")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.list_interfaces:
        for name in get_if_list():
            print(name)
        return 0
    if not args.interface:
        raise SystemExit("--interface is required; use --list-interfaces to see available interfaces")
    LiveCapture(args.api_url, args.flow_timeout, args.dry_run, args.token).run(args.interface, args.bpf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
