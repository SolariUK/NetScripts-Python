#!/usr/bin/env python3
"""
sweepup - sweep devices for uptime (and optionally Cisco StackWise member state).

Python port of the original bash sweepup.

  sweepup.py -l myfw01 myfw02 myfw03 -v3
  sweepup.py lonplcasw                      # match against /etc/hosts
  sweepup.py -f mylistofdevices.txt -s      # include stack status
  sweepup.py -f devices.txt --html sweep.html

SNMP backends (--backend auto|pysnmp|netsnmp):
  pysnmp   - pysnmp 6.2+/7.x (asyncio API, snake_case get_cmd/walk_cmd)
  netsnmp  - shells out to snmpget/snmpwalk; no Python dependencies, so it
             still works on boxes where pysnmp isn't installable
  auto     - pysnmp if importable, otherwise netsnmp

SNMPv3 credentials are read from the environment (or edit the defaults below):
  SWEEPUP_V3_USER, SWEEPUP_V3_AUTH_PROTO, SWEEPUP_V3_AUTH_KEY,
  SWEEPUP_V3_PRIV_PROTO, SWEEPUP_V3_PRIV_KEY
"""
import argparse
import asyncio
import datetime
import html
import os
import re
import shutil
import socket
import sys
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# Defaults (same as the bash version)
# --------------------------------------------------------------------------
TIMEOUT = 4                 # seconds
RETRIES = 0                 # no retries
COMMUNITY = "public"        # v2c community
HOSTS_FILE = "/etc/hosts"   # searched when a bare pattern is given
V3_USER = os.environ.get("SWEEPUP_V3_USER", "v3user")
V3_AUTH_PROTO = os.environ.get("SWEEPUP_V3_AUTH_PROTO", "SHA")
V3_AUTH_KEY = os.environ.get("SWEEPUP_V3_AUTH_KEY", "SNMPAUTHPWD")
V3_PRIV_PROTO = os.environ.get("SWEEPUP_V3_PRIV_PROTO", "AES")
V3_PRIV_KEY = os.environ.get("SWEEPUP_V3_PRIV_KEY", "SNMPPRIVPWD")

OID_ENGINE_TIME = "1.3.6.1.6.3.10.2.1.3.0"        # snmpEngineTime, seconds (wraps ~68y)
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"              # sysUpTime, centiseconds (wraps ~497 days)
OID_STACK_STATE = "1.3.6.1.4.1.9.9.500.1.2.1.1.6"  # CISCO-STACKWISE-MIB cswSwitchState
STACK_STATE_READY = 4

# --------------------------------------------------------------------------
# Colour scheme: one semantic name -> ANSI code + HTML class
# --------------------------------------------------------------------------
ANSI = {
    "white":   "37",
    "red":     "31;1",
    "green":   "32;1",
    "cyan":    "36;1",
    "magenta": "35;1",
    "blue":    "34;1",
}
Segment = tuple  # (text, colour-name or None)


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------
@dataclass
class Result:
    host: str
    ping: str = "uh"                    # "ok" | "nr" | "uh" (unresolvable)
    stack: Optional[tuple] = None       # (members_ok, members_total) once checked
    stack_checked: bool = False
    raw: Optional[int] = None           # raw SNMP value (seconds or centiseconds)
    secs: Optional[float] = None
    error: Optional[str] = None


# --------------------------------------------------------------------------
# SNMP backends. Both expose:  get(host, oid) -> (int|None, err|None)
#                              walk(host, oid) -> (list[int], err|None)
# --------------------------------------------------------------------------
def _norm(name: str) -> str:
    return name.upper().replace("-", "").replace("_", "")


def tidy_error(msg: str) -> str:
    """Map assorted backend wording onto a few consistent messages."""
    m = re.search(r"\w+\('([^']*)'\)", msg)      # unwrap "{'errorIndication': XError('text')}"
    if msg.lstrip().startswith("{") and m:
        msg = m.group(1)
    low = msg.lower()
    if "ciphering services not available" in low:
        return "SNMPv3 privacy unavailable - upgrade the 'cryptography' package"
    if "timeout" in low or "no snmp response" in low or "no response" in low:
        return "Timeout: No Response"
    if "unknown user" in low or "unknown usm" in low:
        return "Unknown user name"
    if "authentication" in low or "wrong digest" in low:
        return "Authentication failure"
    return msg.strip() or "Unknown SNMP error"


class PySnmpBackend:
    name = "pysnmp"

    def __init__(self, cfg):
        from pysnmp.hlapi.v3arch.asyncio import (  # raises ImportError on old pysnmp
            SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, get_cmd, walk_cmd,
            usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
            usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
            usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
            usmDESPrivProtocol, usmAesCfb128Protocol,
            usmAesCfb192Protocol, usmAesCfb256Protocol,
        )
        self.s = dict(UdpTransportTarget=UdpTransportTarget, ContextData=ContextData,
                      ObjectType=ObjectType, ObjectIdentity=ObjectIdentity,
                      get_cmd=get_cmd, walk_cmd=walk_cmd)
        self.cfg = cfg
        self.engine = SnmpEngine()
        if cfg.v3:
            auth = {"MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol,
                    "SHA1": usmHMACSHAAuthProtocol, "SHA224": usmHMAC128SHA224AuthProtocol,
                    "SHA256": usmHMAC192SHA256AuthProtocol, "SHA384": usmHMAC256SHA384AuthProtocol,
                    "SHA512": usmHMAC384SHA512AuthProtocol}
            priv = {"DES": usmDESPrivProtocol, "AES": usmAesCfb128Protocol,
                    "AES128": usmAesCfb128Protocol, "AES192": usmAesCfb192Protocol,
                    "AES256": usmAesCfb256Protocol}
            try:
                ap, pp = auth[_norm(cfg.v3_auth_proto)], priv[_norm(cfg.v3_priv_proto)]
            except KeyError as e:
                raise SystemExit(f"Unsupported SNMPv3 protocol: {e}")
            self.auth = UsmUserData(cfg.v3_user, cfg.v3_auth_key, cfg.v3_priv_key,
                                    authProtocol=ap, privProtocol=pp)
        else:
            self.auth = CommunityData(cfg.community, mpModel=1)  # v2c

    async def _target(self, host):
        return await self.s["UdpTransportTarget"].create(
            (host, 161), timeout=self.cfg.timeout, retries=self.cfg.retries)

    async def get(self, host, oid):
        s = self.s
        try:
            target = await self._target(host)
            err_ind, err_stat, _, binds = await s["get_cmd"](
                self.engine, self.auth, target, s["ContextData"](),
                s["ObjectType"](s["ObjectIdentity"](oid)))
        except Exception as e:  # resolution/transport problems
            return None, tidy_error(str(e))
        if err_ind:
            return None, tidy_error(str(err_ind))
        if err_stat:
            return None, tidy_error(err_stat.prettyPrint())
        try:
            return int(binds[0][1]), None
        except (ValueError, TypeError):
            return None, binds[0][1].prettyPrint()

    async def walk(self, host, oid):
        s = self.s
        values = []
        try:
            target = await self._target(host)
            async for err_ind, err_stat, _, binds in s["walk_cmd"](
                    self.engine, self.auth, target, s["ContextData"](),
                    s["ObjectType"](s["ObjectIdentity"](oid)),
                    lexicographicMode=False):
                if err_ind:
                    return values, tidy_error(str(err_ind))
                if err_stat:
                    return values, tidy_error(err_stat.prettyPrint())
                for _, val in binds:
                    try:
                        values.append(int(val))
                    except (ValueError, TypeError):
                        pass
        except Exception as e:
            return values, tidy_error(str(e))
        return values, None

    def close(self):
        try:
            self.engine.close_dispatcher()
        except Exception:
            pass


class NetSnmpBackend:
    name = "netsnmp"
    _line = re.compile(r"=\s*(?:[\w\- ]+:\s*)?(.*)$")  # type label is absent for -Ot TimeTicks

    def __init__(self, cfg):
        if not (shutil.which("snmpget") and shutil.which("snmpwalk")):
            raise SystemExit("net-snmp tools (snmpget/snmpwalk) not found in PATH")
        # -On numeric OIDs, -Ot raw TimeTicks, -Oe numeric enums: output shape is
        # then identical across net-snmp versions.
        base = ["-On", "-Ot", "-Oe", "-t", str(cfg.timeout), "-r", str(cfg.retries)]
        if cfg.v3:
            base += ["-v3", "-u", cfg.v3_user, "-l", "authPriv",
                     "-a", cfg.v3_auth_proto, "-A", cfg.v3_auth_key,
                     "-x", cfg.v3_priv_proto, "-X", cfg.v3_priv_key]
        else:
            base += ["-v2c", "-c", cfg.community]
        self.base = base

    async def _run(self, tool, host, oid):
        proc = await asyncio.create_subprocess_exec(
            tool, *self.base, host, oid,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        return out.decode(errors="replace").splitlines()

    def _parse(self, lines):
        values, err = [], None
        for ln in lines:
            m = self._line.search(ln)
            if m:
                tok = m.group(1).split()
                try:
                    values.append(int(tok[0].strip("()")))
                    continue
                except (ValueError, IndexError):
                    err = err or tidy_error(m.group(1))
                    continue
            if ln.strip():
                err = err or tidy_error(re.sub(r"^snmp\w+:\s*", "", ln))
        return values, err

    async def get(self, host, oid):
        values, err = self._parse(await self._run("snmpget", host, oid))
        return (values[0], None) if values else (None, err or "No value returned")

    async def walk(self, host, oid):
        values, err = self._parse(await self._run("snmpwalk", host, oid))
        return values, (None if values else err)

    def close(self):
        pass


def make_backend(cfg):
    if cfg.backend in ("auto", "pysnmp"):
        try:
            return PySnmpBackend(cfg)
        except ImportError:
            if cfg.backend == "pysnmp":
                raise SystemExit("pysnmp 6.2+/7.x with the v3arch asyncio API is required "
                                 "(pip install -U pysnmp cryptography)")
    return NetSnmpBackend(cfg)


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------
async def ping(host):
    """Return 'ok', 'nr' (no reply) or 'uh' (unresolvable)."""
    try:
        await asyncio.get_running_loop().getaddrinfo(host, None)
    except socket.gaierror:
        return "uh"
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-qc1", "-W1", host,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        return "ok" if await proc.wait() == 0 else "nr"
    except FileNotFoundError:
        return "nr"


async def probe(host, cfg, backend, sem):
    async with sem:
        r = Result(host=host)
        r.ping = await ping(host)
        if r.ping == "uh":
            return r

        if cfg.stacks:
            r.stack_checked = True
            states, _ = await backend.walk(host, OID_STACK_STATE)
            if states:
                r.stack = (sum(1 for s in states if s == STACK_STATE_READY), len(states))

        oid, scale = (OID_SYS_UPTIME, 100) if cfg.use_sysuptime else (OID_ENGINE_TIME, 1)
        raw, err = await backend.get(host, oid)
        if raw is None:
            r.error = err
        else:
            r.raw, r.secs = raw, raw / scale
        return r


# --------------------------------------------------------------------------
# Presentation: results -> coloured segments (shared by terminal and HTML)
# --------------------------------------------------------------------------
def ping_segments(r):
    return {"ok": [(" OK ", "green")], "nr": [(" NR ", "red")],
            "uh": [(" UH  Unresolvable Host", "red")]}[r.ping]


def stack_segments(r):
    if r.stack and r.stack[1] > 0:
        ok, total = r.stack
        return [(f"{ok}/{total}", "green" if ok == total else "red")]
    return [("N/A", "white")]


def uptime_segments(r):
    if r.error:
        return [(f" {r.error}", "red")]
    if r.secs is None:
        return []
    s = int(r.secs)
    days, hh, mm, ss = s // 86400, s // 3600 % 24, s // 60 % 60, s % 60
    text = f" ({r.raw}) {days} days, {hh:02d}:{mm:02d}:{ss:02d}"
    if days == 0:
        return [(text, "red")]
    if days == 1:
        return [(text, "magenta")]
    if days <= 7:
        return [(text, "cyan")]
    if days < 1000:
        return [(text, "green")]
    return [(text, "green"), (" [WOW!]", "cyan")]


def paint(segments, colour_on):
    out = []
    for text, colour in segments:
        out.append(f"\033[{ANSI[colour]}m{text}\033[0m" if colour_on and colour else text)
    return "".join(out)


def terminal_row(r, cfg, colour_on):
    line = [(" Req from ", "white"), (f"{r.host:<30.30}", "cyan"), (" :", "white")]
    line += ping_segments(r)
    if r.ping == "uh":
        return paint(line, colour_on)
    if cfg.stacks:
        line += [(" [", None)] + stack_segments(r) + [("] ", None)]
    line += uptime_segments(r)
    return paint(line, colour_on)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Uptime sweep - {when}</title>
<style>
  :root {{
    --bg:#1b1d21; --panel:#23262c; --line:#343841; --text:#c9ced6; --muted:#8a919c;
    --white:#e6e8eb; --red:#ff5f5f; --green:#4ee07a; --cyan:#4fd8e8;
    --magenta:#e56bf0; --blue:#6f9bff;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg:#f4f5f7; --panel:#ffffff; --line:#d8dbe0; --text:#2b2f36; --muted:#6a707a;
      --white:#3b4048; --red:#c62828; --green:#1b8a3a; --cyan:#00838f;
      --magenta:#9c27b0; --blue:#1c4fd8;
    }}
  }}
  body {{ margin:0; padding:1.5rem; background:var(--bg); color:var(--text);
         font:14px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  h1 {{ font-size:1.1rem; margin:0 0 .25rem; color:var(--white); }}
  .meta {{ color:var(--muted); margin-bottom:1rem; }}
  .wrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:6px; background:var(--panel); }}
  table {{ border-collapse:collapse; width:100%; }}
  th, td {{ padding:.45rem .8rem; text-align:left; white-space:nowrap; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-weight:600; background:var(--bg); position:sticky; top:0; }}
  tr:last-child td {{ border-bottom:none; }}
  tbody tr:hover {{ background:rgba(127,127,127,.08); }}
  .white {{ color:var(--white); }} .red {{ color:var(--red); font-weight:700; }}
  .green {{ color:var(--green); font-weight:700; }} .cyan {{ color:var(--cyan); font-weight:700; }}
  .magenta {{ color:var(--magenta); font-weight:700; }} .blue {{ color:var(--blue); font-weight:700; }}
  .legend span {{ margin-right:1rem; }}
</style>
</head>
<body>
<h1>Uptime sweep</h1>
<div class="meta">{when} &middot; {mode} &middot; {summary}</div>
<div class="wrap">
<table>
<thead><tr><th>Device</th><th>Ping</th>{stack_head}<th>Uptime</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
<p class="meta legend">Uptime:
  <span class="red">&lt; 1 day</span><span class="magenta">1 day</span><span class="cyan">2-7 days</span><span class="green">8+ days</span>
</p>
</body>
</html>
"""


def html_cell(segments):
    return "".join(f'<span class="{c}">{html.escape(t)}</span>' if c else html.escape(t)
                   for t, c in segments)


def render_html(results, cfg, backend):
    rows = []
    for r in results:
        ping_text, ping_col = ping_segments(r)[0]
        cells = [f'<td class="cyan">{html.escape(r.host)}</td>',
                 f'<td class="{ping_col}">{html.escape(ping_text.strip())}</td>']
        reachable = r.ping != "uh"
        if cfg.stacks:
            cells.append(f"<td>{html_cell(stack_segments(r)) if reachable else ''}</td>")
        up = [(t.strip(), c) for t, c in uptime_segments(r)]
        cells.append(f"<td>{html_cell(up) if reachable else ''}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")

    n_ok = sum(r.ping == "ok" for r in results)
    n_nr = sum(r.ping == "nr" for r in results)
    n_uh = sum(r.ping == "uh" for r in results)
    n_err = sum(bool(r.error) for r in results)
    summary = (f"{len(results)} devices: {n_ok} pingable, {n_nr} no reply, "
               f"{n_uh} unresolvable, {n_err} SNMP errors")
    if cfg.v3:
        ver = "SNMPv3"
    else:
        ver = "SNMPv2c"
    mode = f"{ver} / {'sysUpTime' if cfg.use_sysuptime else 'snmpEngineTime'} ({backend.name})"
    return HTML_TEMPLATE.format(
        when=datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        mode=html.escape(mode), summary=html.escape(summary),
        stack_head="<th>Stack</th>" if cfg.stacks else "", rows="\n".join(rows))


# --------------------------------------------------------------------------
# Host list handling and CLI
# --------------------------------------------------------------------------
def read_host_file(path):
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def search_hosts_file(pattern, path):
    rx = re.compile(pattern, re.I)
    found = set()
    with open(path) as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln or ln.startswith("#") or not rx.search(ln):
                continue
            fields = ln.split()
            if len(fields) > 1:
                found.add(fields[1])
    return sorted(found)


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="sweepup", description="Sweep devices for uptime (and Cisco StackWise state).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Give a single bare pattern to search /etc/hosts (or --hosts-file) for matching devices.

examples:
  sweepup.py -v3 -l myfw01 myfw02 myfw03     SNMPv3 sweep of three devices
  sweepup.py lonplcasw                       every /etc/hosts entry matching 'lonplcasw'
  sweepup.py -f mylistofdevices.txt -s       devices from a file, with stack member state
  sweepup.py -f devices.txt -e --html out.html   sysUpTime, plus an HTML table
  sweepup.py -l sw1 sw2 --html - > sweep.html    HTML only, to stdout

SNMPv3 credentials: SWEEPUP_V3_USER, _AUTH_PROTO, _AUTH_KEY, _PRIV_PROTO, _PRIV_KEY""")
    p.add_argument("pattern", nargs="?", help="regex to match against /etc/hosts entries")
    p.add_argument("-l", dest="hosts", nargs="+", metavar="HOST", default=[],
                   help="hostnames/IPs to poll")
    p.add_argument("-f", dest="file", metavar="FILE",
                   help="file of hostnames/IPs, one per line (# comments allowed)")
    p.add_argument("-v3", "--v3", dest="v3", action="store_true",
                   help="use SNMPv3 (credentials from SWEEPUP_V3_* env vars / script defaults)")
    p.add_argument("-c", dest="community", default=COMMUNITY, metavar="COMMUNITY",
                   help=f"SNMPv2c community (default: {COMMUNITY})")
    p.add_argument("-s", dest="stacks", action="store_true", help="check StackWise member state")
    p.add_argument("-e", dest="use_sysuptime", action="store_true",
                   help="use sysUpTime instead of snmpEngineTime")
    p.add_argument("--html", metavar="FILE",
                   help="also write an HTML table to FILE ('-' = HTML on stdout only)")
    p.add_argument("--hosts-file", default=HOSTS_FILE, metavar="FILE",
                   help=f"file searched for a bare pattern (default: {HOSTS_FILE})")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("-j", "--jobs", type=int, default=16, help="concurrent devices (default 16)")
    p.add_argument("--backend", choices=["auto", "pysnmp", "netsnmp"], default="auto")
    p.add_argument("-t", "--timeout", type=int, default=TIMEOUT)
    p.add_argument("-r", "--retries", type=int, default=RETRIES)
    cfg = p.parse_args(argv)
    cfg.v3_user, cfg.v3_auth_proto, cfg.v3_auth_key = V3_USER, V3_AUTH_PROTO, V3_AUTH_KEY
    cfg.v3_priv_proto, cfg.v3_priv_key = V3_PRIV_PROTO, V3_PRIV_KEY
    if not (cfg.pattern or cfg.hosts or cfg.file):
        p.error("give a pattern, -l hosts..., or -f file")
    if cfg.pattern and (cfg.hosts or cfg.file):
        p.error("use either a pattern or -l/-f, not both")
    return cfg


async def run(cfg):
    html_to_stdout = cfg.html == "-"
    info_out = sys.stderr if html_to_stdout else sys.stdout
    colour_on = (not cfg.no_color and "NO_COLOR" not in os.environ
                 and info_out.isatty())

    def info(segments):
        print(paint(segments, colour_on), file=info_out)

    if cfg.v3:
        info([("Override: Using ", None), ("SNMPv3", "red"), (" with credentials in script/env", None)])
    elif cfg.community != COMMUNITY:
        info([("Override: Using ", None), ("SNMPv2", "red"), (" with Community ", None), (cfg.community, "white")])
    if cfg.use_sysuptime:
        info([("Override: Using ", None), ("sysUpTime", "red"), (" instead of snmpEngineTime", None)])

    hosts = []
    if cfg.file:
        try:
            hosts += read_host_file(cfg.file)
        except OSError:
            raise SystemExit(f"File {cfg.file} not readable or doesn't exist")
        info([("Using file ", None), (cfg.file, "white"), (" for list of hosts to sweep", None)])
    if cfg.hosts:
        hosts += cfg.hosts
        info([("Using list provided from command line...", None)])
    if cfg.pattern:
        info([("Searching for ", None), (cfg.pattern, "white"), (f" in {cfg.hosts_file}", None)])
        try:
            hosts = search_hosts_file(cfg.pattern, cfg.hosts_file)
        except (OSError, re.error) as e:
            raise SystemExit(f"Cannot search {cfg.hosts_file}: {e}")
    if not hosts:
        raise SystemExit("No devices to sweep")

    backend = make_backend(cfg)
    sem = asyncio.Semaphore(max(1, cfg.jobs))
    tasks = [asyncio.create_task(probe(h, cfg, backend, sem)) for h in hosts]

    if not html_to_stdout:
        print(f"{' Device':<41} {'Ping Stack   Uptime' if cfg.stacks else 'Ping Uptime'}")

    results = []
    for t in tasks:                       # emit in input order as each completes
        r = await t
        results.append(r)
        if not html_to_stdout:
            print(terminal_row(r, cfg, colour_on), flush=True)
    backend.close()

    if cfg.html:
        page = render_html(results, cfg, backend)
        if html_to_stdout:
            sys.stdout.write(page)
        else:
            with open(cfg.html, "w", encoding="utf-8") as fh:
                fh.write(page)
            print(f"HTML table written to {cfg.html}")


def main(argv=None):
    cfg = parse_args(argv)
    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
    