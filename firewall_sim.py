#!/usr/bin/env python3
"""
firewall_sim.py — a tiny, stateful firewall + traffic simulator
Author: Mahamadou DANSOKO
"""

from __future__ import annotations
from colorama import Fore, Style, init as colorama_init
import argparse
import ipaddress
import random
import time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Iterable, Optional
colorama_init(autoreset=True)

# ---------- Domain models ----------

Protocol = str  # "TCP" | "UDP" | "ICMP"

@dataclass(frozen=True)
class Packet:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: Protocol
    mac: str
    ts: float = field(default_factory=time.time)

@dataclass
class Rule:
    action: str                # "allow" or "block"
    src: ipaddress._BaseNetwork
    proto: Optional[Protocol]  # None = any
    port: Optional[int]        # None = any
    note: str = ""

    def matches(self, pkt: Packet) -> bool:
        if ipaddress.ip_address(pkt.src_ip) not in self.src:
            return False
        if self.proto and self.proto != pkt.proto:
            return False
        if self.port and self.port != pkt.dst_port:
            return False
        return True

class Firewall:
    def __init__(self, default_action: str = "allow"):
        self.rules: List[Rule] = []
        self.default_action = default_action
        self.log: List[Tuple[str, Packet, str]] = []  # (action, pkt, reason)
        # simple state: rate-limits per (src_ip, dst_port)
        self.counters: Dict[Tuple[str, int], int] = {}

    def add_rule(self, cidr: str, action: str, proto: Optional[str] = None,
                 port: Optional[int] = None, note: str = "") -> None:
        self.rules.append(
            Rule(action=action,
                 src=ipaddress.ip_network(cidr, strict=False),
                 proto=proto, port=port, note=note)
        )

    def evaluate(self, pkt: Packet) -> str:
        # Stateful rate limit: if > N hits to the same port from same IP, block
        key = (pkt.src_ip, pkt.dst_port)
        self.counters[key] = self.counters.get(key, 0) + 1
        if self.counters[key] > 20 and pkt.proto != "ICMP":
            action = "block"
            reason = f"rate-limit {key} count={self.counters[key]}"
            self.log.append((action, pkt, reason))
            return action

        # Rule evaluation (first-match)
        for rule in self.rules:
            if rule.matches(pkt):
                self.log.append((rule.action, pkt, f"rule: {rule.note}"))
                return rule.action

        # Default
        self.log.append((self.default_action, pkt, "default"))
        return self.default_action

    def report(self) -> Dict[str, int]:
        stats = {"allow": 0, "block": 0}
        for action, _, _ in self.log:
            stats[action] = stats.get(action, 0) + 1
        return stats

# ---------- Traffic generation ----------

def rand_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

def generate_packet(src_pool: Iterable[str], dst_ip: str) -> Packet:
    src = random.choice(list(src_pool))
    proto = random.choices(["TCP", "UDP", "ICMP"], weights=[6, 3, 1])[0]
    port = 0 if proto == "ICMP" else random.choice([22, 53, 80, 123, 443, 8080, 3389])
    return Packet(src_ip=src, dst_ip=dst_ip, dst_port=port, proto=proto, mac=rand_mac())
# printing header once if verbose


    if args.verbose:
        reason = fw.log[-1][2]  # reason we appended in evaluate()
        _row(pkt, action, reason, rand)


def ip_pool(cidr: str, n: int) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    random.shuffle(hosts)
    return hosts[:min(n, len(hosts))]

# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Mini firewall + traffic simulator")
    p.add_argument("--src-cidr", default="192.168.1.0/24", help="Source network")
    p.add_argument("--dst-ip", default="10.0.0.10", help="Destination IP")
    p.add_argument("--sources", type=int, default=30, help="Number of source hosts")
    p.add_argument("--packets", type=int, default=300, help="Packets to simulate")
    p.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    p.add_argument("--verbose", "-v", action="store_true", help="Print decisions")
    return p


# ---------- Pretty printing helpers ----------

def _color_action(action: str) -> str:
    if action.lower() == "block":
        return Fore.RED + "BLOCK" + Style.RESET_ALL
    return Fore.GREEN + "ALLOW" + Style.RESET_ALL

def _header() -> None:
    print("\n=== Firewall Simulator Run ===\n")
    print(
        f"{Style.BRIGHT}"
        f"{'IP Address':<15} {'Action':<7} {'Proto':<5} {'Port':<5} {'Reason':<24} {'Rand':>5}"
        f"{Style.RESET_ALL}"
    )
    print("-" * 70)

def _row(pkt, action: str, reason: str, rand: int) -> None:
    print(
        f"{pkt.src_ip:<15} "
        f"{_color_action(action):<7} "
        f"{pkt.proto:<5} "
        f"{pkt.dst_port:<5} "
        f"{(reason[:22] + '…' if len(reason) > 23 else reason):<24} "
        f"{rand:>5}"
    )

def _bar(count: int, total: int, width: int = 30) -> str:
    total = max(total, 1)
    fill = int(width * count / total)
    return "[" + "#" * fill + " " * (width - fill) + "]"


def main():
    args = build_parser().parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    fw = Firewall(default_action="allow")

    # Example custom rules
    fw.add_rule("192.168.1.0/28", "block", proto="TCP", port=22, note="Block SSH from first /28")
    fw.add_rule("192.168.1.50/32", "block", note="Quarantined host")
    fw.add_rule("192.168.1.128/25", "block", proto="UDP", port=53, note="Block DNS from upper half")
    fw.add_rule("0.0.0.0/0", "allow", proto="ICMP", note="Always allow ICMP echo")

    sources = ip_pool(args.src_cidr, args.sources)

    # Pretty table header
    if args.verbose:
        _header()

    # Generate packets & evaluate
    for i in range(args.packets):
        pkt = generate_packet(sources, args.dst_ip)
        action = fw.evaluate(pkt)
        rand = random.randint(0, 9999)

        if args.verbose:
            reason = fw.log[-1][2]  # reason logged
            _row(pkt, action, reason, rand)

    # Summary
    stats = fw.report()
    total = sum(stats.values())

    print("\n=== Summary ===")
    print(f"ALLOW {_bar(stats.get('allow', 0), total)} {stats.get('allow', 0)}")
    print(f"BLOCK {_bar(stats.get('block', 0), total)} {stats.get('block', 0)}")
    print(f"rules: {len(fw.rules)}  packets: {args.packets}  sources: {len(sources)}\n")

if __name__ == "__main__":
    main()
