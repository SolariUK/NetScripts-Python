#!/usr/bin/env python3
"""
hwaudit v3.0

Poll Cisco network devices over SNMP for:
  sysName
  Serial number (chassis, via ENTITY-MIB)
  Uptime (snmpEngineTime with sysUpTime fallback)
  PSU status
  Fan status
  Software version
  Stack member state (optional, --stack)

Output is a colour terminal table and, optionally, a self-contained HTML
report (--html FILE) that uses the same colour semantics.

Requirements:
  Python 3.10+
  pysnmp 7.x            (pip install pysnmp)
  cryptography          (only needed for SNMPv3 with AES/DES privacy)

Exit codes:
  0  All requested targets completed successfully
  1  One or more targets failed
  2  Usage, configuration or dependency error
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import html
import ipaddress
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Any

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        Udp6TransportTarget,
        UdpTransportTarget,
        UsmUserData,
        bulk_walk_cmd,
        get_cmd,
        usm3DESEDEPrivProtocol,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmHMAC128SHA224AuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
    )
    from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

    PYSNMP_IMPORT_ERROR: ImportError | None = None
except ImportError as exc:  # reported later so that --help still works
    PYSNMP_IMPORT_ERROR = exc

PROGRAM_NAME = Path(sys.argv[0]).name or "hwaudit.py"
VERSION = "3.0"

###############################################################################
# OIDs
###############################################################################

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# SNMP-FRAMEWORK-MIB snmpEngineTime
OID_SNMP_ENGINE_TIME = "1.3.6.1.6.3.10.2.1.3.0"

# ENTITY-MIB
OID_ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
OID_ENT_PHYSICAL_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_CLASS_CHASSIS = 3

# CISCO-ENTITY-FRU-CONTROL-MIB
OID_CEFC_PSU_STATUS = "1.3.6.1.4.1.9.9.117.1.1.2.1.2"
OID_CEFC_FAN_STATUS = "1.3.6.1.4.1.9.9.117.1.4.1.1.1"

# CISCO-ENVMON-MIB fallback for PSU status
OID_ENVMON_PSU_STATUS = "1.3.6.1.4.1.9.9.13.1.5.1.3"

# CISCO-STACKWISE-MIB stack member state
OID_STACK_MEMBER_STATE = "1.3.6.1.4.1.9.9.500.1.2.1.1.6"
STACK_STATE_READY = 4

PSU_STATES = {
    1: "offEnvOther",
    2: "on",
    3: "offAdmin",
    4: "offDenied",
    5: "offEnvPower",
    6: "offEnvTemp",
    7: "offEnvFan",
}
PSU_HEALTHY = 2

ENVMON_PSU_STATES = {
    1: "normal",
    2: "warning",
    3: "critical",
    4: "shutdown",
    5: "notPresent",
    6: "notFunctioning",
}
ENVMON_PSU_HEALTHY = 1

FAN_STATES = {1: "unknown", 2: "up", 3: "down", 4: "warning"}
FAN_HEALTHY = 2

###############################################################################
# Configuration
###############################################################################


@dataclass
class Config:
    hosts: list[str]
    snmp_version: str = "2c"
    community: str = "public"
    v3_user: str = ""
    v3_level: str = "authPriv"
    v3_auth_protocol: str = "SHA"
    v3_auth_password: str = ""
    v3_priv_protocol: str = "AES"
    v3_priv_password: str = ""
    timeout: float = 2.0
    retries: int = 0
    jobs: int = 10
    check_stack: bool = False
    sysuptime_only: bool = False
    continue_on_error: bool = False
    color: str = "auto"  # auto | yes | no
    html_path: str | None = None
    quiet: bool = False


def die(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(2)


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


###############################################################################
# Argument handling
###############################################################################


def positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive number") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return value


def non_negative_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be zero or a positive integer") from None
    if value < 0:
        raise argparse.ArgumentTypeError("must be zero or a positive integer")
    return value


def positive_int(text: str) -> int:
    value = non_negative_int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Poll Cisco devices over SNMP for serial, uptime, PSU, "
        "fan and software version.",
        epilog="""\
Environment variables:
  SNMP_COMMUNITY, SNMPV3_USER, SNMPV3_LEVEL, SNMPV3_AUTH_PROTOCOL,
  SNMPV3_AUTH_PASSWORD, SNMPV3_PRIV_PROTOCOL, SNMPV3_PRIV_PASSWORD, NO_COLOR

Host-file format:
  One host per line. Blank lines and '#' comments (including inline) are
  ignored. Targets may be written host, host:port, or [ipv6]:port.

Examples:
  %(prog)s -c COMMUNITY --hosts host1.lab.local host2.lab.local

  SNMP_COMMUNITY=COMMUNITY %(prog)s --host-file switches.txt

  %(prog)s -v 3 -u snmp-readonly -l authPriv -a SHA -A 'auth-pass' \\
      -x AES -X 'priv-pass' --hosts host1.lab.local

  %(prog)s -c COMMUNITY --host-file switches.txt --html audit.html

  %(prog)s -c COMMUNITY --host-file switches.txt --html - > audit.html
""",
    )

    t = p.add_argument_group("target options")
    t.add_argument("--hosts", nargs="+", action="extend", default=[],
                   metavar="HOST", help="one or more hostnames or IP addresses")
    t.add_argument("--host-file", metavar="FILE",
                   help="file containing hosts, one per line")

    s = p.add_argument_group("SNMP version")
    s.add_argument("-v", "--snmp-version", choices=("2c", "3"), default="2c",
                   help="SNMP version (default: 2c)")

    c = p.add_argument_group("SNMPv2c")
    c.add_argument("-c", "--community", metavar="STRING",
                   help="SNMP community (default: $SNMP_COMMUNITY, else 'public')")

    v3 = p.add_argument_group("SNMPv3")
    v3.add_argument("-u", "--v3-user", metavar="USER",
                    default=os.environ.get("SNMPV3_USER", ""),
                    help="security name")
    v3.add_argument("-l", "--v3-level",
                    choices=("noAuthNoPriv", "authNoPriv", "authPriv"),
                    default=os.environ.get("SNMPV3_LEVEL", "authPriv"),
                    help="security level (default: authPriv)")
    v3.add_argument("-a", "--auth-protocol", metavar="PROTO",
                    default=os.environ.get("SNMPV3_AUTH_PROTOCOL", "SHA"),
                    help="MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512 "
                    "(default: SHA)")
    v3.add_argument("-A", "--auth-password", metavar="PASS",
                    default=os.environ.get("SNMPV3_AUTH_PASSWORD", ""),
                    help="authentication password")
    v3.add_argument("-x", "--priv-protocol", metavar="PROTO",
                    default=os.environ.get("SNMPV3_PRIV_PROTOCOL", "AES"),
                    help="DES, 3DES, AES, AES-192, AES-256 (default: AES)")
    v3.add_argument("-X", "--priv-password", metavar="PASS",
                    default=os.environ.get("SNMPV3_PRIV_PASSWORD", ""),
                    help="privacy password")

    b = p.add_argument_group("polling behaviour")
    b.add_argument("-t", "--timeout", type=positive_float, default=2.0,
                   metavar="SECONDS", help="SNMP request timeout (default: 2)")
    b.add_argument("-r", "--retries", type=non_negative_int, default=0,
                   metavar="COUNT", help="SNMP retries (default: 0)")
    b.add_argument("-j", "--jobs", type=positive_int, default=10, metavar="N",
                   help="targets to poll concurrently (default: 10; "
                   "use 1 for strictly sequential polling)")
    b.add_argument("--continue-on-error", action="store_true",
                   help="continue if a target's sysName poll fails")
    b.add_argument("--stack", action="store_true",
                   help="check stackwise member states")
    b.add_argument("--sysuptime", action="store_true",
                   help="force sysUpTime for uptime")

    o = p.add_argument_group("output options")
    o.add_argument("--html", metavar="FILE",
                   help="also write a self-contained HTML report to FILE "
                   "('-' writes HTML to stdout and suppresses the table)")
    o.add_argument("-q", "--quiet", action="store_true",
                   help="do not print the terminal table (useful with --html)")
    o.add_argument("--color", "--colour", dest="color", action="store_const",
                   const="yes", default="auto", help="force ANSI colour output")
    o.add_argument("--no-color", "--no-colour", dest="color",
                   action="store_const", const="no",
                   help="disable ANSI colour output")
    return p


def load_host_file(path: str) -> list[str]:
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        die(f"Cannot read host file: {path} ({exc.strerror})")
    hosts = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            hosts.append(line)
    return hosts


def build_config(args: argparse.Namespace) -> Config:
    hosts = list(args.hosts)
    if args.host_file:
        hosts.extend(load_host_file(args.host_file))
    if not hosts:
        die("No targets supplied. Use --hosts or --host-file.")

    community = args.community
    if community is None:
        community = os.environ.get("SNMP_COMMUNITY", "public")

    cfg = Config(
        hosts=hosts,
        snmp_version=args.snmp_version,
        community=community,
        v3_user=args.v3_user,
        v3_level=args.v3_level,
        v3_auth_protocol=args.auth_protocol,
        v3_auth_password=args.auth_password,
        v3_priv_protocol=args.priv_protocol,
        v3_priv_password=args.priv_password,
        timeout=args.timeout,
        retries=args.retries,
        jobs=args.jobs,
        check_stack=args.stack,
        sysuptime_only=args.sysuptime,
        continue_on_error=args.continue_on_error,
        color=args.color,
        html_path=args.html,
        quiet=args.quiet,
    )

    if cfg.snmp_version == "2c":
        if not cfg.community:
            die("SNMPv2c requires --community or SNMP_COMMUNITY")
    else:
        if not cfg.v3_user:
            die("SNMPv3 requires --v3-user or SNMPV3_USER")
        if cfg.v3_level in ("authNoPriv", "authPriv") and not cfg.v3_auth_password:
            die(f"{cfg.v3_level} requires an authentication password")
        if cfg.v3_level == "authPriv" and not cfg.v3_priv_password:
            die("authPriv requires a privacy password")
        if cfg.v3_level != "noAuthNoPriv":
            if _protocol_key(cfg.v3_auth_protocol) not in _auth_protocols():
                die(f"Unsupported authentication protocol: {cfg.v3_auth_protocol}")
        if cfg.v3_level == "authPriv":
            if _protocol_key(cfg.v3_priv_protocol) not in _priv_protocols():
                die(f"Unsupported privacy protocol: {cfg.v3_priv_protocol}")

    if cfg.html_path and cfg.html_path != "-":
        parent = Path(cfg.html_path).expanduser().resolve().parent
        if not parent.is_dir():
            die(f"HTML output directory does not exist: {parent}")

    return cfg


###############################################################################
# SNMP layer
###############################################################################


def _protocol_key(name: str) -> str:
    return name.upper().replace("-", "").replace("_", "")


def _auth_protocols() -> dict[str, Any]:
    return {
        "MD5": usmHMACMD5AuthProtocol,
        "SHA": usmHMACSHAAuthProtocol,
        "SHA1": usmHMACSHAAuthProtocol,
        "SHA224": usmHMAC128SHA224AuthProtocol,
        "SHA256": usmHMAC192SHA256AuthProtocol,
        "SHA384": usmHMAC256SHA384AuthProtocol,
        "SHA512": usmHMAC384SHA512AuthProtocol,
    }


def _priv_protocols() -> dict[str, Any]:
    return {
        "DES": usmDESPrivProtocol,
        "3DES": usm3DESEDEPrivProtocol,
        "AES": usmAesCfb128Protocol,
        "AES128": usmAesCfb128Protocol,
        "AES192": usmAesCfb192Protocol,
        "AES256": usmAesCfb256Protocol,
    }


def build_auth(cfg: Config) -> Any:
    if cfg.snmp_version == "2c":
        return CommunityData(cfg.community, mpModel=1)

    if cfg.v3_level == "noAuthNoPriv":
        return UsmUserData(cfg.v3_user)

    auth_proto = _auth_protocols()[_protocol_key(cfg.v3_auth_protocol)]
    if cfg.v3_level == "authNoPriv":
        return UsmUserData(
            cfg.v3_user,
            authKey=cfg.v3_auth_password,
            authProtocol=auth_proto,
        )

    priv_proto = _priv_protocols()[_protocol_key(cfg.v3_priv_protocol)]
    return UsmUserData(
        cfg.v3_user,
        authKey=cfg.v3_auth_password,
        privKey=cfg.v3_priv_password,
        authProtocol=auth_proto,
        privProtocol=priv_proto,
    )


def split_target(target: str) -> tuple[str, int]:
    """Split 'host', 'host:port', '[v6]' or '[v6]:port' into (host, port)."""
    m = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", target)
    if m:
        return m.group(1), int(m.group(2) or 161)
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        if port.isdigit():
            return host, int(port)
    return target, 161


def is_missing(value: Any) -> bool:
    return isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView))


class Session:
    """SNMP access to a single target. get/walk never raise; they return
    None / [] on any failure and record the reason in ``last_error``."""

    def __init__(self, engine: Any, auth: Any, transport: Any,
                 max_repetitions: int = 20) -> None:
        self.engine = engine
        self.auth = auth
        self.transport = transport
        self.max_repetitions = max_repetitions
        self.last_error = ""

    async def get(self, oid: str) -> Any | None:
        try:
            err_ind, err_stat, _idx, var_binds = await get_cmd(
                self.engine, self.auth, self.transport, ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        except Exception as exc:  # noqa: BLE001 - never let a poll crash a run
            self.last_error = str(exc)
            return None

        if err_ind:
            self.last_error = str(err_ind)
            return None
        if err_stat:
            self.last_error = err_stat.prettyPrint()
            return None
        for var_bind in var_binds:
            value = var_bind[1]
            return None if is_missing(value) else value
        return None

    async def walk(self, oid: str, limit: int = 1000) -> list[tuple[str, Any]]:
        rows: list[tuple[str, Any]] = []
        try:
            gen = bulk_walk_cmd(
                self.engine, self.auth, self.transport, ContextData(),
                0, self.max_repetitions,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            )
            async with contextlib.aclosing(gen):
                async for err_ind, err_stat, _idx, var_binds in gen:
                    if err_ind:
                        self.last_error = str(err_ind)
                        break
                    if err_stat:
                        self.last_error = err_stat.prettyPrint()
                        break
                    for var_bind in var_binds:
                        value = var_bind[1]
                        if not is_missing(value):
                            rows.append((str(var_bind[0].get_oid()), value))
                    if len(rows) >= limit:
                        break
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
        return rows[:limit]


async def open_session(engine: Any, auth: Any, cfg: Config, target: str) -> Session:
    host, port = split_target(target)
    try:
        is_v6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        is_v6 = False
    transport_cls = Udp6TransportTarget if is_v6 else UdpTransportTarget
    transport = await transport_cls.create(
        (host, port), timeout=cfg.timeout, retries=cfg.retries
    )
    return Session(engine, auth, transport)


###############################################################################
# Value processing
###############################################################################


def clean_value(text: str) -> str:
    return text.replace("\x00", "").replace("\r", "").replace("\n", " ").strip()


def to_text(value: Any | None) -> str:
    if value is None:
        return ""
    try:
        raw = bytes(value).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        raw = value.prettyPrint()
    return clean_value(raw)


def to_int(value: Any | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ints(rows: list[tuple[str, Any]]) -> list[int]:
    return [n for _oid, v in rows if (n := to_int(v)) is not None]


def format_uptime(seconds: int) -> str:
    days, rem = divmod(max(seconds, 0), 86400)
    hours, rem = divmod(rem, 3600)
    return f"{days}d,{hours:02d}:{rem // 60:02d}"


_VERSION_RE = re.compile(r"[Vv]ersion\s+([^,\s]+)")


def normalise_software(description: str) -> str:
    match = _VERSION_RE.search(description)
    if not match:
        return "Unknown"
    version = match.group(1)

    if any(k in description for k in ("IOSXE", "IOS XE", "IOS-XE")):
        return f"IOSXE-{version}"
    if any(k in description for k in ("NX-OS", "NXOS", "Cisco Nexus")):
        return f"NXOS-{version}"
    if "Cisco IOS Software" in description:
        return f"IOS-{version}"
    return version


def summarise_states(states: list[int], healthy: int,
                     names: dict[int, str]) -> str | None:
    """'OK (n/n)' or 'FAIL a,b'; None when there is nothing to summarise."""
    if not states:
        return None
    problems = [names.get(s, f"unknown({s})") for s in states if s != healthy]
    if problems:
        return "FAIL " + ",".join(problems)
    return f"OK ({len(states)}/{len(states)})"


###############################################################################
# Per-metric polling
###############################################################################


async def get_uptime(session: Session, sysuptime_only: bool) -> str:
    if not sysuptime_only:
        seconds = to_int(await session.get(OID_SNMP_ENGINE_TIME))
        if seconds is not None:
            return format_uptime(seconds)

    ticks = to_int(await session.get(OID_SYS_UPTIME))
    if ticks is None:
        return "Unknown"
    return format_uptime(ticks // 100)  # TimeTicks are 1/100 s


async def get_psu_status(session: Session) -> str:
    states = ints(await session.walk(OID_CEFC_PSU_STATUS))
    summary = summarise_states(states, PSU_HEALTHY, PSU_STATES)
    if summary:
        return summary

    states = ints(await session.walk(OID_ENVMON_PSU_STATUS))
    summary = summarise_states(states, ENVMON_PSU_HEALTHY, ENVMON_PSU_STATES)
    return summary or "Unsupported"


async def get_fan_status(session: Session) -> str:
    states = ints(await session.walk(OID_CEFC_FAN_STATUS))
    return summarise_states(states, FAN_HEALTHY, FAN_STATES) or "Unsupported"


async def get_stack_status(session: Session) -> str:
    states = ints(await session.walk(OID_STACK_MEMBER_STATE))
    if not states:
        return "[-]"
    ready = sum(1 for s in states if s == STACK_STATE_READY)
    return f"[{ready}/{len(states)}]"


async def get_serial(session: Session) -> str:
    # Fast path: find the first chassis in a bounded walk of entPhysicalClass,
    # then GET that entity's serial number directly.
    for oid, value in await session.walk(OID_ENT_PHYSICAL_CLASS, limit=50):
        if to_int(value) == ENT_CLASS_CHASSIS:
            index = oid.rsplit(".", 1)[-1]
            serial = to_text(
                await session.get(f"{OID_ENT_PHYSICAL_SERIAL}.{index}")
            )
            if serial:
                return serial
            break

    # Compatibility fallback: first non-empty entPhysicalSerialNum.
    for _oid, value in await session.walk(OID_ENT_PHYSICAL_SERIAL, limit=500):
        serial = to_text(value)
        if serial:
            return serial
    return "Unknown"


###############################################################################
# Target polling
###############################################################################


@dataclass
class Result:
    target: str
    ok: bool = True
    sysname: str = ""
    serial: str = "Unknown"
    uptime: str = "Unknown"
    psu: str = "Unsupported"
    fan: str = "Unsupported"
    stack: str = "N/A"
    software: str = "Unknown"
    error: str = ""


def failed_result(target: str, error: str) -> Result:
    return Result(
        target=target, ok=False, sysname="SNMP FAILED", serial="-",
        uptime="-", psu="-", fan="-", stack="-", software="-", error=error,
    )


async def poll_target(session: Session, target: str, cfg: Config) -> Result:
    # Gatekeeper poll: do not attempt other OIDs if sysName fails.
    sysname = to_text(await session.get(OID_SYS_NAME))
    if not sysname:
        return failed_result(target, session.last_error or "no sysName returned")

    res = Result(target=target, sysname=sysname)
    res.serial = await get_serial(session)
    res.uptime = await get_uptime(session, cfg.sysuptime_only)
    res.psu = await get_psu_status(session)
    res.fan = await get_fan_status(session)
    if cfg.check_stack:
        res.stack = await get_stack_status(session)
    res.software = normalise_software(to_text(await session.get(OID_SYS_DESCR)))
    return res


async def poll_one(engine: Any, auth: Any, cfg: Config, target: str) -> Result:
    try:
        session = await open_session(engine, auth, cfg, target)
        return await poll_target(session, target, cfg)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        return failed_result(target, str(exc))


###############################################################################
# Presentation: shared colour semantics
###############################################################################
# Tones: green / red / yellow / cyan / None (uncoloured)

_UPTIME_RE = re.compile(r"^(\d+)d,(\d{2}):(\d{2})$")
_STACK_RE = re.compile(r"^\[(\d+)/(\d+)\]$")


def status_tone(value: str) -> str:
    if value.startswith("OK"):
        return "green"
    if value.startswith(("FAIL", "CRITICAL")):
        return "red"
    return "yellow"


def uptime_tone(value: str) -> str:
    m = _UPTIME_RE.match(value)
    if not m:
        return "yellow"
    days, hours = int(m.group(1)), int(m.group(2))
    if days >= 7:
        return "green"
    if days >= 1:
        return "cyan"
    if hours >= 1:
        return "yellow"
    return "red"


def stack_tone(value: str) -> str | None:
    m = _STACK_RE.match(value)
    if not m:
        return None
    active, total = int(m.group(1)), int(m.group(2))
    return "green" if total > 0 and active == total else "yellow"


@dataclass
class Cell:
    text: str
    tone: str | None = None


def row_cells(res: Result, cfg: Config) -> list[Cell]:
    if res.ok:
        psu_tone, fan_tone = status_tone(res.psu), status_tone(res.fan)
        up_tone, stack_t = uptime_tone(res.uptime), stack_tone(res.stack)
    else:
        psu_tone = fan_tone = "red"
        up_tone = stack_t = None

    cells = [
        Cell(res.target),
        Cell(res.sysname),
        Cell(res.serial),
        Cell(res.uptime, up_tone),
        Cell(res.psu, psu_tone),
        Cell(res.fan, fan_tone),
    ]
    if cfg.check_stack:
        cells.append(Cell(res.stack, stack_t))
    cells.append(Cell(res.software))
    return cells


def column_titles(cfg: Config) -> list[str]:
    titles = ["TARGET", "SYSNAME", "SERIAL", "UPTIME", "PSU STATUS", "FAN STATUS"]
    if cfg.check_stack:
        titles.append("STACK")
    titles.append("SOFTWARE")
    return titles


def uptime_source_text(cfg: Config) -> str:
    if cfg.sysuptime_only:
        return "sysUpTime (forced)"
    return "snmpEngineTime (sysUpTime fallback)"


###############################################################################
# Presentation: terminal table
###############################################################################

_WIDTHS = {
    "TARGET": 28, "SYSNAME": 28, "SERIAL": 16, "UPTIME": 16,
    "PSU STATUS": 22, "FAN STATUS": 22, "STACK": 9, "SOFTWARE": 18,
}
_ANSI = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "cyan": "\033[36m",
}
_ANSI_RESET = "\033[0m"


def use_colour(mode: str) -> bool:
    if mode == "auto" and os.environ.get("NO_COLOR"):
        return False
    if mode == "auto":
        return sys.stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"
    return mode == "yes"


def clip(value: str, width: int) -> str:
    return value if len(value) <= width else value[: width - 1] + "~"


def term_header(cfg: Config) -> str:
    titles = column_titles(cfg)
    names = " ".join(t.ljust(_WIDTHS[t]) for t in titles)
    rules = " ".join("-" * _WIDTHS[t] for t in titles)
    return f"{names.rstrip()}\n{rules}"


def term_row(res: Result, cfg: Config, colour: bool) -> str:
    parts = []
    for title, cell in zip(column_titles(cfg), row_cells(res, cfg)):
        width = _WIDTHS[title]
        # Padding goes inside the colour sequence so escape codes never
        # affect the visual width of the table.
        padded = clip(cell.text, width).ljust(width)
        if colour and cell.tone:
            padded = f"{_ANSI[cell.tone]}{padded}{_ANSI_RESET}"
        parts.append(padded)
    return " ".join(parts).rstrip()


###############################################################################
# Presentation: HTML report
###############################################################################

_HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hardware audit - $generated</title>
<style>
:root {
  --bg:#1e1e1e; --panel:#252526; --head:#2d2d30; --line:#3c3c3c;
  --fg:#d4d4d4; --muted:#8a8a8a;
  --green:#23d18b; --red:#f14c4c; --yellow:#e5e510; --cyan:#29b8db;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg:#f6f6f4; --panel:#ffffff; --head:#eeeeea; --line:#d8d8d4;
    --fg:#1f2328; --muted:#6b7280;
    --green:#0f7b3f; --red:#c62828; --yellow:#8a6d00; --cyan:#00718f;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px; background: var(--bg); color: var(--fg);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
h1 { font-size: 18px; margin: 0 0 4px; }
.meta, footer { color: var(--muted); font-size: 12.5px; }
.meta { margin-bottom: 16px; }
.banner {
  margin: 0 0 16px; padding: 10px 14px; border-radius: 6px;
  border: 1px solid var(--red); color: var(--red);
}
.summary { display: flex; flex-wrap: wrap; gap: 10px; margin: 0 0 16px;
  padding: 0; list-style: none; }
.summary li { background: var(--panel); border: 1px solid var(--line);
  border-radius: 6px; padding: 8px 16px; min-width: 110px; }
.summary b { display: block; font-size: 22px; font-weight: 600; }
.summary span { color: var(--muted); font-size: 11.5px;
  text-transform: uppercase; letter-spacing: .05em; }
.wrap { overflow-x: auto; border: 1px solid var(--line);
  border-radius: 6px; background: var(--panel); }
table { border-collapse: collapse; width: 100%;
  font: 13px ui-monospace, SFMono-Regular, Menlo, Consolas,
    "Liberation Mono", monospace; }
th, td { padding: 7px 12px; text-align: left; white-space: nowrap;
  border-bottom: 1px solid var(--line); }
thead th { background: var(--head); color: var(--muted); font-size: 11.5px;
  letter-spacing: .06em; font-weight: 600; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: rgba(127,127,127,.09); }
tr.failed td:first-child { box-shadow: inset 3px 0 0 var(--red); }
.green { color: var(--green); } .red { color: var(--red); }
.yellow { color: var(--yellow); } .cyan { color: var(--cyan); }
footer { margin-top: 14px; }
footer p { margin: 2px 0; }
</style>
</head>
<body>
<h1>Hardware audit</h1>
<div class="meta">Generated $generated &middot; SNMP $snmp_version</div>
$banner
<ul class="summary">
$summary
</ul>
<div class="wrap">
<table>
<thead><tr>$head</tr></thead>
<tbody>
$body
</tbody>
</table>
</div>
<footer>
<p>Uptime source: $uptime_source</p>
<p>Uptime colours:
<span class="green">7 days or more</span> &middot;
<span class="cyan">1 day or more</span> &middot;
<span class="yellow">1 hour or more</span> &middot;
<span class="red">under 1 hour</span></p>
</footer>
</body>
</html>
""")


def _html_cell(cell: Cell) -> str:
    text = html.escape(cell.text)
    if cell.tone:
        return f'<td class="{cell.tone}">{text}</td>'
    return f"<td>{text}</td>"


def render_html(results: list[Result], cfg: Config, *,
                not_polled: int = 0, generated: str | None = None) -> str:
    generated = generated or dt.datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )
    failed = sum(1 for r in results if not r.ok)
    faults = sum(
        1 for r in results
        if r.ok and (r.psu.startswith("FAIL") or r.fan.startswith("FAIL"))
    )

    summary = [
        ("Targets polled", len(results), ""),
        ("Responding", len(results) - failed, ""),
        ("Failed", failed, "red" if failed else ""),
        ("PSU/fan faults", faults, "red" if faults else ""),
    ]
    if not_polled:
        summary.append(("Not polled", not_polled, "yellow"))
    summary_html = "\n".join(
        f'<li><b class="{tone}">{value}</b><span>{html.escape(label)}</span></li>'
        if tone else
        f"<li><b>{value}</b><span>{html.escape(label)}</span></li>"
        for label, value, tone in summary
    )

    banner = ""
    if not_polled:
        banner = (
            '<div class="banner">Run aborted after a failed sysName poll '
            f"({not_polled} target(s) not polled; use --continue-on-error "
            "to poll the rest).</div>"
        )

    head = "".join(f"<th>{html.escape(t)}</th>" for t in column_titles(cfg))

    rows = []
    for res in results:
        cells = "".join(_html_cell(c) for c in row_cells(res, cfg))
        if res.ok:
            rows.append(f"<tr>{cells}</tr>")
        else:
            title = html.escape(res.error, quote=True)
            rows.append(f'<tr class="failed" title="{title}">{cells}</tr>')

    return _HTML_TEMPLATE.substitute(
        generated=html.escape(generated),
        snmp_version=html.escape(cfg.snmp_version),
        banner=banner,
        summary=summary_html,
        head=head,
        body="\n".join(rows),
        uptime_source=html.escape(uptime_source_text(cfg)),
    )


def write_html(content: str, path: str) -> None:
    if path == "-":
        sys.stdout.write(content)
        return
    try:
        Path(path).expanduser().write_text(content, encoding="utf-8")
    except OSError as exc:
        die(f"Cannot write HTML report to {path}: {exc.strerror}")


###############################################################################
# Main
###############################################################################


async def run(cfg: Config) -> int:
    colour = use_colour(cfg.color)
    show_table = not cfg.quiet and cfg.html_path != "-"

    engine = SnmpEngine()
    auth = build_auth(cfg)
    semaphore = asyncio.Semaphore(cfg.jobs)

    async def worker(target: str) -> Result:
        async with semaphore:
            return await poll_one(engine, auth, cfg, target)

    if show_table:
        print(f"Uptime source: {uptime_source_text(cfg)}")
        print(term_header(cfg), flush=True)

    tasks = [asyncio.create_task(worker(t)) for t in cfg.hosts]
    results: list[Result] = []
    aborted = False

    try:
        # Await in input order so output order is stable even though the
        # polling itself runs concurrently.
        for target, task in zip(cfg.hosts, tasks):
            res = await task
            results.append(res)

            if not res.ok:
                warn(f"{target}: sysName poll failed ({res.error})")
                if not cfg.continue_on_error:
                    print(
                        f"\nAborting: the initial sysName poll failed for "
                        f"{target}.",
                        file=sys.stderr,
                    )
                    aborted = True

            if show_table:
                print(term_row(res, cfg, colour), flush=True)

            if aborted:
                break
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        with contextlib.suppress(Exception):
            engine.close_dispatcher()

    if cfg.html_path:
        write_html(
            render_html(results, cfg, not_polled=len(cfg.hosts) - len(results)),
            cfg.html_path,
        )

    return 1 if aborted or any(not r.ok for r in results) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = build_config(args)

    if PYSNMP_IMPORT_ERROR is not None:
        die(
            f"pysnmp 7.x is required ({PYSNMP_IMPORT_ERROR}). "
            "Install it with: pip install pysnmp"
        )

    try:
        return asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())