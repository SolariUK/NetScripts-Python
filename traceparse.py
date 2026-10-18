#!/usr/bin/env python3

"""
Resolve hops from Cisco/Juniper traceroute output.

Resolution methods:
    dns  - Perform a reverse DNS lookup
    snmp - Query sysName.0 using SNMPv2c

Lookups are performed concurrently, while output is displayed
in the original traceroute order.
"""

import argparse
import asyncio
import ipaddress
import socket
import sys


SYSNAME_OID = "1.3.6.1.2.1.1.5.0"
MAX_CONCURRENT = 20


#
# pysnmp is optional.
#
# Don't terminate the script if it isn't installed, because DNS mode
# doesn't require it.
#

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    HAVE_PYSNMP = True

except ImportError:
    HAVE_PYSNMP = False


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Resolve hops from Cisco/Juniper traceroute output."
    )

    parser.add_argument(
        "-m",
        "--method",
        choices=("dns", "snmp"),
        default="dns",
        help="resolution method (default: dns)",
    )

    parser.add_argument(
        "-c",
        "--community",
        default="public",
        help="SNMP v2c community string (default: public)",
    )

    parser.add_argument(
        "-s",
        "--dns-server",
        metavar="SERVER",
        help="DNS server to use for reverse lookups",
    )

    args = parser.parse_args()

    if args.dns_server and args.method != "dns":
        parser.error("--dns-server can only be used with --method dns")

    return args


def read_traceroute():
    """
    Read traceroute output from stdin.

    Input ends after two consecutive blank lines.
    """

    lines = []
    blank_count = 0

    print("Paste the Cisco/Juniper traceroute output below.")
    print("Press Enter twice when finished.")
    print()

    while True:
        try:
            line = input()

        except EOFError:
            # Also allow Ctrl-D or redirected stdin to terminate input.
            break

        if not line.strip():
            blank_count += 1

            if blank_count >= 2:
                break

            continue

        blank_count = 0
        lines.append(line)

    return lines


def find_ipv4(line):
    """
    Return the first IPv4 address found in a traceroute line.

    Returns None if the line contains no IPv4 address.
    """

    for field in line.split():

        # Remove common punctuation that may surround an address.
        candidate = field.strip("(),[]")

        try:
            address = ipaddress.ip_address(candidate)

        except ValueError:
            continue

        if isinstance(address, ipaddress.IPv4Address):
            return str(address)

    return None


async def resolve_snmp(ip, community):
    """Resolve an IP address using SNMP sysName.0."""

    if not HAVE_PYSNMP:
        return "<pysnmp not installed>"

    try:
        target = await UdpTransportTarget.create(
            (ip, 161),
            timeout=2,
            retries=0,
        )

        error_indication, error_status, error_index, var_binds = (
            await get_cmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(SYSNAME_OID)),
            )
        )

        if error_indication:
            return "<no SNMP response>"

        if error_status:
            return "<SNMP error>"

        if not var_binds:
            return "<no SNMP response>"

        return str(var_binds[0][1])

    except Exception:
        return "<no SNMP response>"


def resolve_dns_system_sync(ip):
    """Blocking system DNS lookup."""

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname

    except (socket.herror, socket.gaierror, OSError):
        return "<unresolved>"


async def resolve_dns_system(ip):
    """
    Resolve an IP using the operating system's configured resolver.

    socket.gethostbyaddr() is blocking, so run it in a worker thread
    rather than blocking the asyncio event loop.
    """

    return await asyncio.to_thread(resolve_dns_system_sync, ip)


def resolve_dns_server_sync(ip, dns_server):
    """
    Blocking reverse lookup using a specifically requested DNS server.

    Requires dnspython.
    """

    try:
        import dns.resolver
        import dns.reversename

    except ImportError:
        return "<dnspython not installed>"

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_server]
        resolver.timeout = 2
        resolver.lifetime = 2

        reverse_name = dns.reversename.from_address(ip)
        answer = resolver.resolve(reverse_name, "PTR")

        if not answer:
            return "<unresolved>"

        return str(answer[0]).rstrip(".")

    except Exception:
        return "<unresolved>"


async def resolve_dns_server(ip, dns_server):
    """
    Resolve an IP using a specifically requested DNS server.

    dnspython's normal Resolver interface is blocking, so run the
    request in a worker thread.
    """

    return await asyncio.to_thread(
        resolve_dns_server_sync,
        ip,
        dns_server,
    )


async def resolve_hop(ip, args, semaphore):
    """
    Resolve one hop.

    The semaphore limits the number of simultaneous lookups.
    """

    async with semaphore:

        if args.method == "snmp":
            return await resolve_snmp(ip, args.community)

        if args.dns_server:
            return await resolve_dns_server(ip, args.dns_server)

        return await resolve_dns_system(ip)


async def main():
    """Main program."""

    args = parse_arguments()

    #
    # Warn about optional dependencies before asking for input.
    #

    if args.method == "snmp" and not HAVE_PYSNMP:
        print(
            "Warning: pysnmp is not installed.",
            file=sys.stderr,
        )
        print(
            "SNMP lookups will not be available.",
            file=sys.stderr,
        )
        print(
            "Install it with: pip install pysnmp",
            file=sys.stderr,
        )
        print(file=sys.stderr)

    traceroute_lines = read_traceroute()

    #
    # Build a list containing only traceroute lines which have
    # an IPv4 hop address.
    #
    # Keeping line and hop together means we can perform all lookups
    # concurrently while preserving the original display order.
    #

    hops = []

    for line in traceroute_lines:

        hop = find_ipv4(line)

        if hop is None:
            continue

        hops.append((line, hop))

    print()
    print("Checking...")
    print()

    if not hops:
        return

    #
    # Limit the number of lookups running at the same time.
    #

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    #
    # Create one asynchronous lookup for each hop.
    #

    tasks = [
        resolve_hop(hop, args, semaphore)
        for line, hop in hops
    ]

    #
    # Run all lookups concurrently.
    #
    # asyncio.gather() returns the results in the same order as the
    # tasks supplied to it, even if individual queries finish in a
    # different order.
    #

    results = await asyncio.gather(*tasks)

    #
    # Display results in original traceroute order.
    #

    for (line, hop), hopname in zip(hops, results):
        print(f"{line} - {hopname}")


if __name__ == "__main__":
    asyncio.run(main())