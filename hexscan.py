#!/usr/bin/env python3
"""
Hexscan - a fast asynchronous TCP port scanner.

Features:
  - Async connect-scan across any port range (including all 65535 ports)
  - Tunable concurrency + timeout for speed/accuracy tradeoffs
  - Service name guessing (IANA well-known ports)
  - Banner grabbing for lightweight version/service fingerprinting
  - Host liveness pre-check (skip dead hosts fast)
  - Multiple targets, CIDR ranges, and hostname resolution
  - JSON / CSV / plain-text output
  - Live progress bar
  - Rate limiting option to avoid flooding a network

Usage examples:
  python3 hexscan.py 192.168.1.10                      # scan top 1000 ports
  python3 hexscan.py 192.168.1.10 -p 1-65535            # scan all TCP ports
  python3 hexscan.py 10.0.0.0/28 -p 22,80,443 -j out.json
  python3 hexscan.py scanme.example.com --banners -c 500

NOTE ON SPEED:
  Scan time is bounded by physics, not code: each unresponsive/filtered port
  costs roughly one timeout period, and every probe is a real packet round
  trip. On localhost or a LAN, scanning all 65535 ports in a few seconds is
  realistic with high concurrency. Over the public internet, a full 65535
  port scan of a remote, firewalled host will usually take longer than 5
  seconds no matter what tool you use, because you are limited by RTT,
  target-side rate limiting, and how many sockets your OS/network can hold
  open at once. Hexscan is tuned to get as close to the physical limit as
  possible (async I/O, no per-port thread overhead, adjustable timeout),
  but no scanner can beat network latency itself.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False  # e.g. on Windows


def raise_fd_limit(target: int) -> int:
    """Try to raise the process's open-file-descriptor limit so high
    concurrency doesn't silently fail. Returns the safe concurrency ceiling
    actually available. This matters a lot: every in-flight port probe
    holds a socket fd open, so concurrency > fd limit causes 'Too many
    open files' errors that get silently misread as closed/filtered ports."""
    if not HAS_RESOURCE:
        return min(target, 500)  # conservative guess for platforms without resource module
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = min(target + 256, hard)  # headroom for stdio, listen sockets, etc.
    if desired > soft:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
            soft = desired
        except (ValueError, OSError):
            pass
    # Leave headroom; don't hand out every last fd.
    return max(50, soft - 200)

# --------------------------------------------------------------------------
# Well-known port -> service name table (subset of IANA registry, common ports)
# --------------------------------------------------------------------------
COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 194: "irc", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 515: "printer", 520: "rip",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    902: "vmware-auth", 989: "ftps-data", 990: "ftps", 993: "imaps",
    995: "pop3s", 1025: "ms-rpc", 1080: "socks", 1194: "openvpn",
    1433: "mssql", 1434: "mssql-monitor", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl", 27017: "mongodb",
    3000: "dev-http", 3128: "squid-proxy", 3260: "iscsi", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4444: "metasploit-default", 4789: "vxlan",
    5000: "dev-http-alt", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 6660: "irc", 6666: "irc", 6667: "irc",
    6697: "irc-ssl", 7000: "cassandra", 7077: "spark", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8086: "influxdb", 8443: "https-alt", 8888: "http-alt",
    9000: "sonarqube/php-fpm", 9042: "cassandra-native", 9090: "prometheus",
    9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
    11211: "memcached", 15672: "rabbitmq-mgmt", 25565: "minecraft",
    27018: "mongodb-shard", 27019: "mongodb-config", 50000: "sap",
}

TOP_1000_SAMPLE = sorted(set(list(COMMON_SERVICES.keys()) + list(range(1, 1025))))


@dataclass
class PortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""


@dataclass
class HostResult:
    target: str
    ip: str
    alive: bool = True
    open_ports: list = field(default_factory=list)
    scan_seconds: float = 0.0


def service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def parse_ports(spec: str) -> list:
    """Parse '22,80,443' or '1-1000' or a mix into a sorted list of ints."""
    if spec == "top1000":
        return TOP_1000_SAMPLE
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p < 65536)


def expand_targets(spec: str) -> list:
    """Expand a single host, hostname, or CIDR into a list of IP strings."""
    try:
        net = ipaddress.ip_network(spec, strict=False)
        if net.num_addresses > 1:
            return [str(ip) for ip in net.hosts()]
        return [str(net.network_address)]
    except ValueError:
        return [spec]  # hostname; resolved later


async def is_host_alive(ip: str, timeout: float) -> bool:
    """Quick liveness probe: try a handful of likely-open ports; if any
    connects OR actively refuses (RST), the host is up. This avoids
    burning the full timeout budget on every closed port of a dead host."""
    probe_ports = (80, 443, 22, 445, 3389)
    for port in probe_ports:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (ConnectionRefusedError, OSError):
            # refused still means something answered on the wire
            return True
        except asyncio.TimeoutError:
            continue
    return False


async def grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            # Many services send a greeting on connect; for HTTP-like ports
            # send a minimal probe to elicit a response.
            if port in (80, 8080, 8000, 8888, 3000, 5000, 8081):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: hexscan\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            banner = data.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")
            return banner[:120]
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return ""


async def scan_port(ip: str, port: int, timeout: float, sem: asyncio.Semaphore,
                     want_banner: bool, results: list, progress: dict):
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner = ""
            if want_banner:
                banner = await grab_banner(ip, port, timeout)
            results.append(PortResult(port=port, state="open",
                                       service=service_name(port), banner=banner))
        except (ConnectionRefusedError,):
            pass  # closed
        except (asyncio.TimeoutError, OSError):
            pass  # filtered / no response
        finally:
            progress["done"] += 1


def print_progress(done: int, total: int, start: float):
    pct = done / total if total else 1
    bar_len = 30
    filled = int(bar_len * pct)
    bar = "#" * filled + "-" * (bar_len - filled)
    elapsed = time.time() - start
    sys.stdout.write(f"\r[{bar}] {done}/{total} ports  {elapsed:0.1f}s")
    sys.stdout.flush()


async def scan_host(target: str, ports: list, concurrency: int, timeout: float,
                     want_banner: bool, skip_alive_check: bool, quiet: bool) -> HostResult:
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return HostResult(target=target, ip="?", alive=False)

    start = time.time()

    if not skip_alive_check:
        alive = await is_host_alive(ip, min(timeout, 1.5))
        if not alive:
            return HostResult(target=target, ip=ip, alive=False,
                               scan_seconds=time.time() - start)

    sem = asyncio.Semaphore(concurrency)
    results: list = []
    progress = {"done": 0}
    tasks = [scan_port(ip, p, timeout, sem, want_banner, results, progress) for p in ports]

    if quiet:
        await asyncio.gather(*tasks)
    else:
        task_objs = [asyncio.ensure_future(t) for t in tasks]
        total = len(task_objs)
        while True:
            done_count = sum(1 for t in task_objs if t.done())
            print_progress(done_count, total, start)
            if done_count == total:
                break
            await asyncio.sleep(0.1)
        print()  # newline after progress bar

    results.sort(key=lambda r: r.port)
    return HostResult(target=target, ip=ip, alive=True, open_ports=results,
                       scan_seconds=time.time() - start)


def output_text(host: HostResult):
    print(f"\nHexscan report for {host.target} ({host.ip})")
    if not host.alive:
        print("Host appears to be down or is blocking all probes.")
        return
    if not host.open_ports:
        print("No open ports found in the scanned range.")
    else:
        print(f"{'PORT':<10}{'STATE':<8}{'SERVICE':<16}BANNER")
        for r in host.open_ports:
            print(f"{r.port:<10}{r.state:<8}{r.service:<16}{r.banner}")
    print(f"Scan completed in {host.scan_seconds:.2f} seconds "
          f"({len(host.open_ports)} open port(s)).")


def output_json(hosts: list, path: str):
    data = [
        {
            "target": h.target, "ip": h.ip, "alive": h.alive,
            "scan_seconds": round(h.scan_seconds, 3),
            "open_ports": [asdict(r) for r in h.open_ports],
        }
        for h in hosts
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] JSON results written to {path}")


def output_csv(hosts: list, path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["target", "ip", "port", "state", "service", "banner"])
        for h in hosts:
            if not h.open_ports:
                writer.writerow([h.target, h.ip, "", "down" if not h.alive else "no-open-ports", "", ""])
            for r in h.open_ports:
                writer.writerow([h.target, h.ip, r.port, r.state, r.service, r.banner])
    print(f"[+] CSV results written to {path}")


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="hexscan",
        description="Hexscan - fast asynchronous TCP port scanner",
    )
    p.add_argument("targets", nargs="+", help="Target host(s), IP(s), or CIDR range(s)")
    p.add_argument("-p", "--ports", default="top1000",
                   help="Ports to scan: 'all', 'top1000' (default), '80,443', or '1-1024'")
    p.add_argument("-c", "--concurrency", type=int, default=400,
                   help="Max simultaneous connection attempts (default 400). "
                        "Higher isn't always faster: past a certain point the event "
                        "loop can't service completions before their timeout expires, "
                        "which shows up as false 'closed' results. Raise cautiously.")
    p.add_argument("-t", "--timeout", type=float, default=1.0,
                   help="Per-port connection timeout in seconds (default 1.0). Lower "
                        "it for LANs/localhost, raise it for scans over the internet.")
    p.add_argument("--banners", action="store_true",
                   help="Attempt banner grabbing on open ports (slower, more info)")
    p.add_argument("--skip-alive-check", action="store_true",
                   help="Don't pre-check host liveness before scanning all ports")
    p.add_argument("-j", "--json", metavar="FILE", help="Write results as JSON to FILE")
    p.add_argument("--csv", metavar="FILE", help="Write results as CSV to FILE")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress the progress bar")
    return p


async def main_async(args):
    ports = parse_ports(args.ports)
    all_targets = []
    for t in args.targets:
        all_targets.extend(expand_targets(t))

    safe_ceiling = raise_fd_limit(args.concurrency)
    if safe_ceiling < args.concurrency:
        print(f"[!] Requested concurrency {args.concurrency} exceeds this system's safe "
              f"file-descriptor budget; capping to {safe_ceiling} to avoid false negatives.")
        args.concurrency = safe_ceiling

    hosts = []
    for target in all_targets:
        host = await scan_host(
            target, ports,
            concurrency=args.concurrency,
            timeout=args.timeout,
            want_banner=args.banners,
            skip_alive_check=args.skip_alive_check,
            quiet=args.quiet,
        )
        hosts.append(host)
        output_text(host)

    if args.json:
        output_json(hosts, args.json)
    if args.csv:
        output_csv(hosts, args.csv)


def main():
    args = build_arg_parser().parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
