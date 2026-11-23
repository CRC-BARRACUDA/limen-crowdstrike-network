"""crowdstrike-network — every network interface on every fleet host, over RTR.

Addresses, MACs, gateways, DNS and link state, per host — the answer to "who has
that IP", "where is that MAC", and "what else is this machine attached to".

It owns no credentials. Auth and the host list come from the ``crowdstrike``
capability; this module only knows how to ask a host what it is connected by.

How it gets there
-----------------
Falcon's inventory carries a host's primary address and MAC, which is one
interface out of however many it has — and the interesting one is rarely the
primary. So the question is asked on the host itself: an RTR session **per host**
and one ``runscript`` for its platform, printing one interface per line. One
session per host rather than one batch across many is the point of the screen: a
batch returns when its slowest member does, while here each host lands on its own
and can be opened while the rest are still going.

The fleet scan is read-only: the interface, route and resolver tables are read
and nothing is changed. Interfaces are changed only when the host panel asks —
`check` and `change`, below — after the user has accepted every change.

What it reads
-------------
* **Windows** — ``Get-NetAdapter`` with the addresses, default routes and DNS
  servers joined on by interface index. Hosts older than Server 2012 fall back to
  ``Win32_NetworkAdapterConfiguration``, which is thinner but is the difference
  between a partial answer and none.
* **Linux** — ``/sys/class/net`` for the list, the MAC and the link state; ``ip``
  for addresses and routes; ``/etc/resolv.conf`` for the resolvers.
* **macOS** — ``ifconfig``, with ``networksetup`` supplying the names people
  recognise, ``route`` the gateway and ``scutil`` the resolvers.

Everything is reported, including interfaces that are down and virtual ones. A
bridge or a tunnel that should not be there is exactly the thing worth seeing, so
they are labelled rather than filtered and the screen groups by state instead.

Methods
-------
  ui              -> the screen: fetch hosts, tick them, scan
  fetch           -> load the reachable inventory from ``crowdstrike``
  scan_selected   -> enumerate the ticked hosts
  scan_all        -> enumerate every listed host
  progress        -> one tick of the progress loop
  stop            -> call off what has not started
  open_host       -> one host's interfaces, in a tab (the double-click target)
  about           -> one interface, in a tab
  network         -> the same data as JSON, for other modules
  read_host       -> read one host on request, for the host panel
  check           -> check drafted interface changes, sending nothing
  change          -> make drafted interface changes on one host, then read it
"""

import ipaddress
import json
import os
import re
import queue
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from limen_sdk import (
    Button,
    Catalog,
    Checkbox,
    Label,
    MenuItem,
    Module,
    Row,
    Separator,
    Table,
    Text,
    Window,
)

# The module's own strings. `host.locale()` is asked per render rather than
# once at start: the language is the application's setting and can change
# while the module is running.
CAT = Catalog.from_dir(os.path.dirname(os.path.abspath(__file__)), ("en", "uk"))
_lang = {"code": "en"}


def t(key, **args):
    """Translate for the language the host last reported."""
    return CAT.tr(_lang["code"], key, **args)


def _sync_locale():
    """Re-read the host's language before drawing.

    Asked each time rather than once at start, because it is the
    application's setting and the user can change it while the module is
    open. One round-trip per render, which is what the Rust modules do too.
    """
    try:
        _lang["code"] = m.host.locale()
    except Exception:  # noqa: BLE001
        pass  # keep the last language rather than failing to draw


CAP = "crowdstrike.network"
m = Module("crowdstrike-network", [CAP])

# The fetched inventory. Held so reopening the tab restores the list rather than
# re-querying the fleet.
_hosts = {"rows": None}
_status = {"msg": ""}

# Per-host scan state, the only thing shared between the worker threads and the
# dispatch thread — so every read and write of it takes `_lock`.
#
#   _jobs[host_id] = {hostname, platform, state, ifaces, error, notes}
#   state: "queued" | "scanning" | "done" | "failed" | "stopped"
_jobs = {}
_lock = threading.Lock()

# One-host reads asked for by another module — the host panel — by device id.
# Kept apart from `_jobs`: asking about one machine must neither wipe what the
# fleet screen is showing nor wait for a fleet scan to finish. Same lock.
_reads = {}

# Workers must not log through `host`: the SDK's host bridge writes a frame to
# stdout and then reads stdin, and that is the JSON-RPC pipe. A second thread
# using it interleaves a write into the protocol and steals a line of the
# response. So workers put their lines here and the dispatch thread drains them
# on the next poll, where logging is safe.
_logq = queue.Queue()

# The running scan: the pool doing the work, and the flag that calls it off.
_run = {"pool": None, "stop": None, "started": 0.0}

# One host at a time per thread, and few enough threads not to be rate-limited
# off the Falcon API — the aim is that a small fleet finishes quickly, not that a
# large one arrives all at once.
MAX_WORKERS = 8

# A scan of a large fleet returns a lot of rows, and every one of them crosses
# the RTR response, this process, and the UI — so there is a cap per host.
#
# Set far higher than the device list's, because the shape of the data is
# different: a host has a handful of physical interfaces and can have hundreds of
# virtual ones — container veths, tunnels, VPN adapters — and on a container host
# that is the whole list. Generous enough that the cap is a guard rather than a
# limit, and when it does bite the host says so on its own row.
MAX_ROWS_PER_HOST = 5000

# How long the script itself may run on the endpoint. Falcon caps this at 600.
RTR_TIMEOUT = 600

# The most one `runscript -Raw` may carry. The command travels as a single string
# in a REST body, and the figures quoted for RTR sit around 4 KB — so this is set
# below that and enforced when the script is built, where it is a loud failure in
# a test, rather than discovered on a host as empty output.
MAX_SCRIPT_BYTES = 4000

# How long a poll waits before answering. The host re-invokes an `auto` action as
# soon as the view renders, so without this the progress loop would spin as fast
# as the two processes can exchange frames, for as long as the scan lasts.
POLL_SECONDS = 0.6


class _Stopped(Exception):
    """Raised inside a worker when Stop was pressed — a cancellation, not a
    failure, and shown as one."""


class _UnknownOS(Exception):
    """The host's OS is not one this module can read, so nothing is run on it."""

    def __init__(self, platform):
        super().__init__(f"unsupported OS: {platform}")
        self.platform = platform


# --------------------------------------------------------------------------- #
# Falcon RTR (auth and the inventory come from the crowdstrike capability).
# --------------------------------------------------------------------------- #
def _http(method, url, token, body=None):
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    # Walking three registry views (or four package databases) takes longer
    # than a notification does, so the read timeout is generous.
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, (json.loads(raw) if raw else {})


def _auth(host):
    """Bearer token + API base from the crowdstrike capability."""
    token = (host.call("crowdstrike", "token", {}) or {}).get("token")
    base = (
        (host.call("crowdstrike", "api", {}) or {})
        .get("base_url", "https://api.crowdstrike.com")
        .rstrip("/")
    )
    if not token:
        raise RuntimeError(
            "no CrowdStrike token — configure the crowdstrike module first"
        )
    return token, base


def _rtr_one(hid, platform, token, base, stop, before=()):
    """Enumerate ONE host and return its stdout.

    One RTR session per host rather than one batch across many: a batch returns
    when its slowest member does, and this module's whole point is that a finished
    host is usable while the others are still going. The cost is an init call per
    host, which is what the thread pool is for.

    Raises on failure — the caller turns that into the host's error state. Never
    touches `host`: this runs on a worker thread, and the SDK's host bridge is the
    JSON-RPC pipe on stdio, which only the dispatch thread may write to.
    """
    if stop.is_set():
        raise _Stopped()
    # Chosen first, so a host whose OS we cannot read costs no RTR session and
    # nothing is run on it.
    # Changes, when there are any, go first: the read after them is then of the
    # host as the changes left it.
    passes = list(before) + _script_for(platform)
    st, init = _http(
        "POST",
        f"{base}/real-time-response/combined/batch-init-session/v1",
        token,
        {"host_ids": [hid], "timeout": 120},
    )
    batch_id = init.get("batch_id")
    if not batch_id:
        raise RuntimeError(f"no RTR session (RTR enabled for this host?) HTTP {st}")
    resources = init.get("resources") or {}
    if isinstance(resources, dict):
        for r in resources.values():
            for e in r.get("errors") or []:
                raise RuntimeError(str(e.get("message", e)))

    # One session, then each pass over it. Their outputs are concatenated: the
    # parser only ever sees lines, so it neither knows nor needs to know that they
    # arrived in several pieces.
    collected, troubles = [], []
    for label, script in passes:
        if stop.is_set():
            raise _Stopped()
        # `-Timeout` before `-Raw`: the raw block ends at a fence, and anything
        # after that fence is ambiguous, so no argument goes there.
        command_string = f"runscript -Timeout={RTR_TIMEOUT} -Raw=```" + script + "```"
        st, res = _http(
            "POST",
            f"{base}/real-time-response/combined/batch-admin-command/v1",
            token,
            {
                "batch_id": batch_id,
                "base_command": "runscript",
                "command_string": command_string,
            },
        )
        per_host = (res.get("combined", {}).get("resources", {}) or {}).get(hid)
        if per_host is None:
            troubles.append(f"{label}: no answer (HTTP {st})")
            continue
        stdout = per_host.get("stdout") or ""
        if "#begin" in stdout:
            collected.append(stdout)
            continue
        # The script prints `#begin` before doing anything, so its absence does
        # not mean "nothing here" — it means the pass did not run. One pass
        # failing is not the host failing, so it is recorded and the rest go on.
        stderr = (per_host.get("stderr") or "").strip()
        errs = "; ".join(str(e.get("message", e)) for e in per_host.get("errors") or [])
        troubles.append(f"{label}: {errs or stderr or 'did not run'}")

    if not collected:
        # Every pass failed, so there is nothing to show and a reason to give.
        raise RuntimeError("; ".join(troubles) or "the script did not run on this host")
    if troubles:
        # Some of the picture is missing, and the operator has to know which part
        # rather than be handed a short list that looks complete.
        collected.append("#err=" + "; ".join(troubles) + "\n")
    return "\n".join(collected)


# --------------------------------------------------------------------------- #
# The enumeration scripts.
#
# Each prints one entry per line as
#     iface|kind|mac|ipv4|ipv6|gateway|dns|state|speed
# plus `#`-prefixed metadata lines. A flat line format rather than JSON on
# purpose: RTR hands back stdout as loose text and truncates it, and a truncated
# JSON document is worth nothing while a truncated list of lines is worth all but
# the last line.
#
# **No backticks.** The script is sent inside an RTR ```...``` block, and a
# backtick is also PowerShell's escape character — one in here corrupts the
# command on the wire, so the Windows script escapes nothing and quotes with
# single quotes throughout.
# --------------------------------------------------------------------------- #

# Windows. One interface per line, with the addresses, gateway and DNS servers
# joined onto it — the tables live apart (adapters, addresses, routes, DNS) and
# are keyed by interface index, so they are gathered into maps first and the
# adapter walk reads them.
#
# `Get-NetAdapter` is Windows 8 / Server 2012 and later. Older hosts fall back to
# WMI, which is less detailed but is the difference between a thin answer and no
# answer at all.
_WIN = r"""
Write-Output '#begin'
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$n = 0
function Clean($s) {
  if ($null -eq $s) { return '' }
  return (([string]$s) -replace '[\r\n\|]', ' ').Trim()
}
function Add($map, $k, $v) {
  if (-not $v) { return }
  if ($map.ContainsKey($k)) { $map[$k] = $map[$k] + ' ' + $v } else { $map[$k] = $v }
}
function Emit($line) {
  if ($script:n -ge __LIMIT__) { Write-Output '#truncated'; exit }
  $script:n = $script:n + 1
  Write-Output $line
}
try {
$adapters = @(Get-NetAdapter -IncludeHidden)
if ($adapters.Count -eq 0) {
  Write-Output '#legacy'
  foreach ($c in @(Get-WmiObject Win32_NetworkAdapterConfiguration)) {
    if (-not $c.MACAddress) { continue }
    $v4 = ''
    $v6 = ''
    foreach ($a in @($c.IPAddress)) {
      if ($a -like '*:*') { $v6 = (Clean ($v6 + ' ' + $a)) } else { $v4 = (Clean ($v4 + ' ' + $a)) }
    }
    $state = 'down'
    if ($c.IPEnabled) { $state = 'up' }
    Emit (@((Clean $c.Description), 'net', (Clean $c.MACAddress), $v4, $v6,
            (Clean (@($c.DefaultIPGateway) -join ' ')),
            (Clean (@($c.DNSServerSearchOrder) -join ' ')), $state, '') -join '|')
  }
  exit
}
$ip4 = @{}
$ip6 = @{}
$gw = @{}
$dns = @{}
foreach ($a in @(Get-NetIPAddress)) {
  $k = [string]$a.InterfaceIndex
  $v = (Clean $a.IPAddress) + '/' + $a.PrefixLength
  if ($a.AddressFamily -eq 'IPv4') { Add $ip4 $k $v } else { Add $ip6 $k $v }
}
foreach ($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0')) {
  Add $gw ([string]$r.InterfaceIndex) (Clean $r.NextHop)
}
foreach ($r in @(Get-NetRoute -DestinationPrefix '::/0')) {
  Add $gw ([string]$r.InterfaceIndex) (Clean $r.NextHop)
}
foreach ($d in @(Get-DnsClientServerAddress)) {
  foreach ($srv in @($d.ServerAddresses)) {
    if ([string]$srv -like 'fec0:0:0:ffff::*') { continue }
    Add $dns ([string]$d.InterfaceIndex) (Clean $srv)
  }
}
# What the edit form shows as it is now: the profile (Private, Public, or set by
# the domain), the IPv4 metric and whether it is automatic, and DHCP.
$cat = @{}
foreach ($p in @(Get-NetConnectionProfile)) { $cat[[string]$p.InterfaceIndex] = Clean $p.NetworkCategory }
$met = @{}
$amet = @{}
$dh = @{}
foreach ($i in @(Get-NetIPInterface -AddressFamily IPv4)) {
  $j = [string]$i.InterfaceIndex
  $met[$j] = Clean $i.InterfaceMetric
  $amet[$j] = Clean $i.AutomaticMetric
  $dh[$j] = Clean $i.Dhcp
}
foreach ($a in $adapters) {
  $k = [string]$a.ifIndex
  # The saved settings, where Properties reads them and netsh writes them: in
  # force once the adapter is connected, which on an unplugged one they are not.
  # DNS typed in is in NameServer; with it empty, DNS comes from DHCP.
  $cf = Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $a.InterfaceGuid)
  $dsrc = ''
  if ($cf) { $dsrc = 'dhcp'; if ($cf.NameServer) { $dsrc = 'static' } }
  if ($cf.EnableDHCP -eq 1) { $ips = @($cf.DhcpIPAddress); $ms = @($cf.DhcpSubnetMask); $gs = @($cf.DhcpDefaultGateway) }
  else { $ips = @($cf.IPAddress); $ms = @($cf.SubnetMask); $gs = @($cf.DefaultGateway) }
  $cv = @()
  for ($x = 0; $x -lt $ips.Count; $x++) { if ($ips[$x] -and $ips[$x] -ne '0.0.0.0') { $cv += ($ips[$x] + '/' + $ms[$x]) } }
  $cd = $cf.NameServer
  if (-not $cd) { $cd = $cf.DhcpNameServer }
  $kind = Clean $a.PhysicalMediaType
  if (-not $kind -or $kind -eq 'Unspecified') { $kind = 'net' }
  if ($a.Virtual) { $kind = 'virtual' }
  $state = Clean $a.Status
  $speed = Clean $a.LinkSpeed
  Emit (@((Clean $a.Name), $kind, (Clean $a.MacAddress), (Clean $ip4[$k]), (Clean $ip6[$k]),
          (Clean $gw[$k]), (Clean $dns[$k]), $state, $speed,
          (Clean $cat[$k]), (Clean $met[$k]), (Clean $amet[$k]), (Clean $dh[$k]), $dsrc,
          (Clean $cf.EnableDHCP), (Clean ($cv -join ' ')), (Clean ($gs -join ' ')),
          (Clean ([string]$cd -replace ',', ' '))) -join '|')
}
} catch { Write-Output ('#err=' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""

# Linux. `/sys/class/net` is the list and the link state; `ip` carries the
# addresses and the routes. An interface with no `device` symlink is virtual —
# a bridge, a tun, a container veth — which is worth saying, because on a busy
# host those outnumber the real ones.
_LINUX = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
n=0
clean() { printf '%s' "$1" | tr -d '|' | tr '\n' ' ' | tr -d '\r'; }
emit() {
  n=$((n+1))
  if [ "$n" -gt "$LIMIT" ]; then echo '#truncated'; exit 0; fi
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
}
routes=$(ip route show default 2>/dev/null)
dns=$(awk '/^[[:space:]]*nameserver/ { printf "%s ", $2 }' /etc/resolv.conf 2>/dev/null)
for d in /sys/class/net/*/ ; do
  i=$(basename "$d")
  kind=ethernet
  [ -d "$d/wireless" ] && kind=wifi
  [ -e "$d/device" ] || kind=virtual
  [ "$i" = "lo" ] && kind=loopback
  sp=$(cat "$d/speed" 2>/dev/null)
  # -1 on a down link, 0 on some drivers: both mean "no reading", and printing
  # them as "-1Mb/s" looks like one.
  case "$sp" in ''|-*|0) sp='' ;; *) sp="${sp}Mb/s" ;; esac
  if command -v ip >/dev/null 2>&1; then
    v4=$(ip -o -4 addr show dev "$i" 2>/dev/null | awk '{ printf "%s ", $4 }')
    v6=$(ip -o -6 addr show dev "$i" 2>/dev/null | awk '{ printf "%s ", $4 }')
  else
    v4=$(ifconfig "$i" 2>/dev/null | awk '/inet /{ printf "%s ", $2 }')
    v6=$(ifconfig "$i" 2>/dev/null | awk '/inet6 /{ printf "%s ", $2 }')
  fi
  gw=$(printf '%s\n' "$routes" | awk -v i="$i" '$0 ~ ("dev " i " ") { print $3; exit }')
  emit "$(clean "$i")" "$kind" "$(clean "$(cat "$d/address" 2>/dev/null)")" \
       "$(clean "$v4")" "$(clean "$v6")" "$(clean "$gw")" "$(clean "$dns")" \
       "$(clean "$(cat "$d/operstate" 2>/dev/null)")" "$(clean "$sp")"
done
"""

# macOS. `ifconfig -a` is the whole picture bar the names people recognise, so
# `networksetup` supplies those: an operator asked about "Wi-Fi" should not have
# to know it is `en0` on this machine and `en1` on the next.
_MAC = r"""
exec 2>/dev/null
echo '#begin'
LIMIT=__LIMIT__
gw=$(route -n get default 2>/dev/null | awk '/gateway:/{ print $2 }')
dns=$(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/{ printf "%s ", $3 }' | awk '{ $1=$1; print }')
ports=$(networksetup -listallhardwareports 2>/dev/null)
ifconfig -a 2>/dev/null | awk -v lim=__LIMIT__ -v gw="$gw" -v dns="$dns" -v ports="$ports" '
  function name_of(dev,   n, line, i, arr, cnt) {
    cnt = split(ports, arr, "\n")
    for (i = 1; i <= cnt; i++) {
      if (arr[i] ~ ("Device: " dev "$")) { n = arr[i-1]; sub(/^Hardware Port: /, "", n); return n }
    }
    return dev
  }
  function flush() {
    if (dev == "") return
    if (++c > lim) { print "#truncated"; exit }
    kind = "ethernet"
    if (dev ~ /^lo/) kind = "loopback"
    else if (dev ~ /^(utun|gif|stf|bridge|awdl|llw|ap)/) kind = "virtual"
    else if (nm ~ /Wi-Fi|AirPort/) kind = "wifi"
    gsub(/\|/, " ", nm)
    print nm "|" kind "|" mac "|" v4 "|" v6 "|" gw "|" dns "|" st "|"
    dev = ""; mac = ""; v4 = ""; v6 = ""; st = ""; nm = ""
  }
  /^[a-z0-9]+:/ { flush(); dev = $1; sub(/:$/, "", dev); nm = name_of(dev); next }
  /^[[:space:]]*ether / { mac = $2 }
  /^[[:space:]]*inet / { v4 = v4 $2 " " }
  /^[[:space:]]*inet6 / { v6 = v6 $2 " " }
  /^[[:space:]]*status: / { st = $2 }
  END { flush() }
'
"""


# Falcon's `platform_name`, lowercased, to the script that can read that OS.
# Matched on a prefix because the field is not a closed set: "Windows", "Linux",
# "Mac" and "macOS" have all been seen in the wild.
_SCRIPTS = (("win", "win"), ("mac", "mac"), ("linux", "linux"), ("ubuntu", "linux"),
            ("rhel", "linux"), ("centos", "linux"), ("debian", "linux"),
            ("amazon", "linux"), ("suse", "linux"), ("oracle", "linux"))

# The scripts to run on each OS, in order, as (label, body).
#
# Windows is **three** scripts rather than one, and not for tidiness: a
# `runscript -Raw` command travels as one string in a REST body, and that string
# is not unbounded. The single script came to 4.8 KB, which is close enough to the
# limits quoted for RTR that a host would refuse it — and a refused script comes
# back as empty output, which is indistinguishable from a machine with nothing to
# report. Splitting also buys failure granularity: if reading the scheduled tasks
# trips over one bad task, the Run keys have already been returned.
_PASSES = {
    "win": (("all", "_WIN"),),
    "linux": (("all", "_LINUX"),),
    "mac": (("all", "_MAC"),),
}


def _minify(script):
    """Drop comment-only and blank lines.

    The comments in these scripts are worth a great deal in this file and nothing
    at all on the wire, where they are the difference between a command that fits
    and one that may not: the autorun script carries far more explanation than the
    others, and an RTR command string is not unbounded. Only lines whose first
    non-space character is `#` go — so `echo '#begin'`, which starts with `echo`,
    is untouched, and no string literal is ever cut into.
    """
    kept = [ln for ln in script.split("\n")
            if ln.strip() and not ln.lstrip().startswith("#")]
    return "\n".join(kept) + "\n"


def _script_for(platform, limit=MAX_ROWS_PER_HOST):
    """The enumeration scripts for a Falcon `platform_name`, as (label, script).

    Raises [`_UnknownOS`] rather than guessing. Guessing would mean falling
    through to the shell script, and on a Windows host that does not fail
    cleanly — it comes back empty, and that host then reads as a machine with
    **no software installed**. Which is the one wrong conclusion this module must
    never invite, so an OS we cannot name is a visible failure instead. Falcon
    also reports iOS, Android and Kubernetes nodes; none can be enumerated this
    way.
    """
    p = (platform or "").strip().lower()
    which = next((kind for prefix, kind in _SCRIPTS if p.startswith(prefix)), None)
    if which is None:
        raise _UnknownOS(platform or "(not reported)")
    bodies = globals()
    return [_ready(label, platform, bodies[name].replace("__LIMIT__", str(int(limit))))
            for label, name in _PASSES[which]]


def _ready(label, platform, body):
    """A script as it goes on the wire, checked."""
    # This file is checked out with CRLF, so the literals above carry \r on
    # every line. PowerShell copes; /bin/sh does not — `LIMIT=400\r` compares
    # against a value with a carriage return in it and every `done` becomes an
    # unknown command. So the script is normalised to LF whichever platform it is
    # for, rather than leaving it to how this file happens to be checked out.
    script = _minify(body).replace("\r\n", "\n")
        # The script is sent inside an RTR ```…``` block, so a backtick anywhere
        # in it — including in a comment written out of Markdown habit — closes
        # that block early and corrupts the command on the wire. It fails as a
        # script that does not run rather than as an error anybody sees, so it is
        # caught here instead.
    if "`" in script:
        bad = next(n for n, ln in enumerate(script.splitlines(), 1) if "`" in ln)
        raise AssertionError(f"backtick in {label} for {platform}, line {bad}")
    if len(script) > MAX_SCRIPT_BYTES:
        raise AssertionError(
            f"{label} for {platform} is {len(script)}B, over the "
            f"{MAX_SCRIPT_BYTES}B a single runscript may carry — split it")
    return label, script


def _with_prefix(pairs):
    """`ip/255.255.255.0` pairs, as the registry keeps them, as `ip/24`."""
    out = []
    for pair in pairs.split():
        try:
            out.append(str(ipaddress.IPv4Interface(pair)))
        except ValueError:
            continue
    return " ".join(out)


def _parse(stdout, hostname, host_id):
    """One host's stdout into interface rows, plus what the metadata lines said.

    Every interface is reported, including the ones that are down and the virtual
    ones. A bridge or a tun that should not be there is exactly the thing worth
    seeing, and on a busy host those outnumber the physical adapters — so they
    are labelled rather than filtered, and the screen groups by state instead.
    """
    rows, flags = [], {"truncated": False, "error": "", "legacy": False,
                       "changed": [], "change_failed": {}}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line == "#begin":
                pass  # only proves the script ran; `_rtr_one` already checked
            elif line == "#truncated":
                flags["truncated"] = True
            elif line == "#legacy":
                flags["legacy"] = True
            elif line.startswith("#err="):
                # The endpoint stayed silent and told us instead.
                flags["error"] = line[5:].strip()
            elif line.startswith("#changed="):
                flags["changed"].append(int(line[9:].strip() or -1))
            elif line.startswith("#change-failed="):
                at, _, err = line[15:].partition(":")
                if at.strip().isdigit():
                    flags["change_failed"][int(at)] = err.strip()
            continue
        parts = [f.strip() for f in line.split("|")]
        if len(parts) < 8:
            continue
        iface, kind, mac, v4, v6, gw, dns, state = parts[:8]
        speed = parts[8] if len(parts) > 8 else ""
        # Windows only, and not from the legacy path: the network profile, the
        # interface metric and whether it is automatic, DHCP, and where the DNS
        # servers come from.
        profile, metric, auto_metric, dhcp, dns_from = (parts[9:14] + [""] * 5)[:5]
        # And the saved settings — what the adapter will use once connected,
        # which on an unplugged one is not what is in force.
        cfg_dhcp, cfg_v4, cfg_gw, cfg_dns = (parts[14:18] + [""] * 4)[:4]
        if cfg_dhcp.strip() in ("0", "1"):
            dhcp = "enabled" if cfg_dhcp.strip() == "1" else "disabled"
        if not iface:
            continue
        rows.append({
            "host": hostname,
            "host_id": host_id,
            "iface": iface,
            "kind": kind or "net",
            "mac": mac,
            # Several addresses on one interface is ordinary, so they arrive
            # space-separated and are kept that way — splitting them into rows
            # would multiply the interface instead of describing it.
            "ipv4": " ".join(v4.split()),
            "ipv6": " ".join(v6.split()),
            "gateway": " ".join(gw.split()),
            "dns": " ".join(dns.split()),
            "state": (state or "").lower(),
            "speed": speed,
            "profile": profile,
            "metric": metric,
            "auto_metric": auto_metric.lower() == "enabled",
            "dhcp": dhcp.lower() == "enabled",
            # DNS from DHCP: nothing typed in, on an interface that has DHCP to
            # get it from. Without DHCP, an empty list is just no servers.
            "dns_auto": dns_from == "dhcp" and dhcp.lower() == "enabled",
            # Whether the saved settings were read at all. An empty saved
            # gateway is "none", not "unknown" — only without them does what
            # is in force stand in.
            "saved": cfg_dhcp.strip() in ("0", "1"),
            "cfg_ipv4": _with_prefix(cfg_v4),
            "cfg_gateway": " ".join(g for g in cfg_gw.split() if ":" not in g),
            "cfg_dns": " ".join(cfg_dns.split()),
            # What an operator actually searches for: "is this MAC on the fleet",
            # "who has 10.1.2.3". Both live behind a normalisation, so the search
            # box can match either without the user matching the host's spelling.
            "up": (state or "").lower() in ("up", "active", "connected"),
        })
    rows.sort(key=lambda r: (not r["up"], r["iface"].lower()))
    return rows, flags


# --------------------------------------------------------------------------- #
# Scanning: one worker per host, so a finished host is usable immediately.
# --------------------------------------------------------------------------- #
def _log(line):
    """Queue a line for the dispatch thread to log. Safe from any thread."""
    _logq.put(line)


def _set(hid, **fields):
    """Update one host's job state under the lock."""
    with _lock:
        job = _jobs.get(hid)
        if job is not None:
            job.update(fields)


def _read(hid, hostname, platform, token, base, stop, before=()):
    """Read one host's interfaces over RTR, and say how it ended.

    Returns the fields of a finished read: `state`, with `ifaces` and `notes`
    when it is `done`, or `error` when it is not. Shared by the fleet scan and
    the one-host read another module asks for, so both read a machine the same
    way. Runs on a worker thread; touches only `_logq` and the network.
    """
    try:
        stdout = _rtr_one(hid, platform, token, base, stop, before)
        rows, flags = _parse(stdout, hostname, hid)
        notes = []
        if flags["truncated"]:
            notes.append(t("note.truncated", n=MAX_ROWS_PER_HOST))
        if flags["error"]:
            # The script caught something on the endpoint and reported it here
            # instead of showing it there. Surfaced as a note, not a failure: the
            # rows it did manage to send are still good.
            notes.append(flags["error"])
        if not rows and not notes:
            notes.append(t("note.empty"))
        _log(f"cs-network: {hostname} — {len(rows)} interface(s)")
        return {"state": "done", "ifaces": rows, "notes": notes,
                "changed": flags["changed"], "change_failed": flags["change_failed"]}
    except _Stopped:
        return {"state": "stopped"}
    except _UnknownOS as exc:
        _log(f"cs-network: {hostname} skipped — {exc}")
        return {"state": "skipped", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        _log(f"cs-network: {hostname} failed — {exc}")
        return {"state": "failed", "error": str(exc)}


def _worker(hid, token, base, stop):
    """Enumerate one host of a fleet scan. Runs on a pool thread; touches only
    `_jobs` (locked), `_logq`, and the network."""
    with _lock:
        job = _jobs.get(hid)
        if job is None:
            return
        hostname, platform = job["hostname"], job["platform"]
    if stop.is_set():
        _set(hid, state="stopped")
        return
    _set(hid, state="scanning")
    _set(hid, **_read(hid, hostname, platform, token, base, stop))


def _start(host, targets):
    """Queue `targets` and start the pool. Returns the status line.

    The token is fetched **here**, on the dispatch thread, and handed to the
    workers: asking for it from a worker would mean using the host bridge off the
    RPC thread.
    """
    if not targets:
        return t("status.none_selected")
    if _busy():
        return t("status.already_running")
    try:
        token, base = _auth(host)
    except Exception as exc:  # noqa: BLE001
        host.log(f"cs-network: auth failed: {exc}")
        return str(exc)

    stop = threading.Event()
    with _lock:
        _jobs.clear()
        for target in targets:
            _jobs[target["id"]] = {
                "hostname": target.get("hostname") or target["id"],
                "platform": target.get("platform", ""),
                "state": "queued",
                "ifaces": [],
                "error": "",
                "notes": [],
            }
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets)))
    _run.update(pool=pool, stop=stop, started=time.time())
    for target in targets:
        pool.submit(_worker, target["id"], token, base, stop)
    # Nothing is waited on: the pool is left running and the view polls it, so
    # the dispatch thread returns to drawing immediately.
    host.log(f"cs-network: scanning {len(targets)} host(s) on "
             f"{min(MAX_WORKERS, len(targets))} thread(s)")
    return t("status.starting", n=len(targets))


def _busy():
    """Whether any host is still queued or in flight."""
    with _lock:
        return any(j["state"] in ("queued", "scanning") for j in _jobs.values())


def _drain_log(host):
    """Move whatever the workers queued into the host log. Dispatch thread only."""
    while True:
        try:
            host.log(_logq.get_nowait())
        except queue.Empty:
            return


def _tally():
    with _lock:
        states = [j["state"] for j in _jobs.values()]
        ifaces = sum(len(j["ifaces"]) for j in _jobs.values())
    return {
        "total": len(states),
        "done": states.count("done"),
        "failed": states.count("failed"),
        "stopped": states.count("stopped"),
        "skipped": states.count("skipped"),
        "running": states.count("scanning") + states.count("queued"),
        "ifaces": ifaces,
    }


def _targets_from(rows):
    return [
        {"id": h["id"], "hostname": h.get("hostname", ""),
         "platform": h.get("platform", "")}
        for h in rows
        if h.get("id")
    ]


# --------------------------------------------------------------------------- #
# Methods.
# --------------------------------------------------------------------------- #
@m.method("fetch")
def fetch(params, host):
    """Load the reachable inventory from the crowdstrike capability."""
    try:
        inv = host.call("crowdstrike", "hosts", {})
        # Only reachable hosts: RTR cannot open a session to a host that is
        # offline, so listing them as scannable would only produce failures.
        rows = inv.get("accessible", []) if isinstance(inv, dict) else []
        _hosts["rows"] = rows
        _status["msg"] = t("status.reachable", n=len(rows))
    except Exception as exc:  # noqa: BLE001
        _hosts["rows"] = None
        _status["msg"] = t("status.fetch_failed", err=exc)
        host.log(f"cs-network: fetch failed: {exc}")
    return m._view_spec()


@m.method("scan_selected")
def scan_selected(params, host):
    """Start scanning the ticked hosts."""
    rows = _hosts["rows"] or []
    selected = [h for h in rows if params.get(f"sel_{h.get('id')}")]
    _status["msg"] = _start(host, _targets_from(selected))
    return m._view_spec()


@m.method("scan_all")
def scan_all(params, host):
    """Start scanning every host in the current list."""
    _status["msg"] = _start(host, _targets_from(_hosts["rows"] or []))
    return m._view_spec()


@m.method("progress")
def progress(params, host):
    """One tick of the progress loop: drain the workers' log lines, wait a beat,
    and re-render.

    The wait is the throttle. The host re-invokes an `auto` action the moment the
    view renders, so answering immediately would spin the loop as fast as the two
    processes can pass frames.
    """
    _drain_log(host)
    if _busy():
        time.sleep(POLL_SECONDS)
    t = _tally()
    if t["running"]:
        _status["msg"] = (
            f"scanning — {t['done']} of {t['total']} done, "
            f"{t['ifaces']} interface(s) so far"
        )
    else:
        _shutdown_pool()
        parts = [f"{t['done']} host(s) scanned", f"{t['ifaces']} interface(s)"]
        if t["failed"]:
            parts.append(f"{t['failed']} failed")
        if t["stopped"]:
            parts.append(f"{t['stopped']} stopped")
        if t["skipped"]:
            parts.append(f"{t['skipped']} unsupported")
        _status["msg"] = " · ".join(parts)
    return m._view_spec()


def _shutdown_pool():
    """Let the finished pool go. Not blocking: every worker has already left."""
    pool = _run.get("pool")
    if pool is not None:
        pool.shutdown(wait=False)
        _run["pool"] = None


@m.method("stop")
def stop(params, host):
    """Call off the scan.

    A host already in flight finishes its current HTTP call — there is no way to
    un-ask a request that is out — but nothing new is started, and anything still
    queued is marked stopped rather than left looking as though it is coming.
    """
    ev = _run.get("stop")
    if ev is not None:
        ev.set()
    with _lock:
        for job in _jobs.values():
            if job["state"] == "queued":
                job["state"] = "stopped"
    host.log("cs-network: stop requested")
    _status["msg"] = t("status.stopping")
    return m._view_spec()


# --------------------------------------------------------------------------- #
# One host's interfaces, in its own tab.
# --------------------------------------------------------------------------- #
def columns():
    """Column headings, in the current language. A function rather than a
    constant, which would freeze whichever language the module was imported in."""
    return [t("col.iface"), t("col.type"), t("col.state"), t("col.mac"),
            t("col.ipv4"), t("col.ipv6"), t("col.gateway"), t("col.dns")]


def _cells(r):
    return [r.get("iface", ""), r.get("kind", ""), r.get("state", ""),
            r.get("mac", ""), r.get("ipv4", ""), r.get("ipv6", ""),
            r.get("gateway", ""), r.get("dns", "")]


# Interfaces shown in a host tab, by row id, so `about` can resolve one. Keyed
# "<host id>:<index>" rather than by index alone: several host tabs are open at
# once, and row 3 means a different interface in each.
_shown = {}

# The filter text per open host tab, so two tabs can be narrowed differently.
_query = {}


@m.method("open_host")
def open_host(params, host):
    """A finished host's interfaces, opened in a tab. The double-click target."""
    _sync_locale()
    hid = str(params.get("id", ""))
    with _lock:
        job = dict(_jobs.get(hid) or {})
    if not job:
        return Window(t("ui.col_host"), [Label(t("host.unknown"))]).to_spec()
    name = job["hostname"]
    if job["state"] != "done":
        return Window(name, [
            Label(name, style="heading"),
            Label(state_text(job["state"]), style="weak"),
            Label(job["error"], style="weak") if job["error"] else Separator(),
        ]).to_spec()

    # A filter typed in this tab arrives with the call; otherwise the one this tab
    # was last left with, so a refresh does not silently widen the list.
    if "query" in params:
        _query[hid] = params.get("query") or ""
    query = (_query.get(hid) or "").lower()

    ifaces = job["ifaces"]
    up, down, up_ids, down_ids = [], [], [], []
    for i, r in enumerate(ifaces):
        cells = _cells(r)
        if query and query not in " ".join(cells).lower():
            continue
        rid = f"{hid}:{i}"
        _shown[rid] = r
        if r["up"]:
            up_ids.append(rid)
            up.append(cells)
        else:
            down_ids.append(rid)
            down.append(cells)

    menu = [MenuItem(t("iface.about"), capability=CAP, method="about",
                     open_in_tab=True)]
    widgets = [
        Label(name, style="heading"),
        Label(t("host.summary", n=len(ifaces)), style="weak"),
    ]
    for note in job["notes"]:
        widgets.append(Label("! " + note, style="weak"))
    widgets.append(Row([
        Text("query", label=t("ui.search"), placeholder=t("ui.search_hint"),
             default=_query.get(hid, "")),
        # Re-opens this same tab with the filter applied; the host id rides along
        # so the button knows which host it is filtering.
        Button(t("ui.filter"), calls="open_host", args={"id": hid}),
    ]))
    if query:
        widgets.append(Label(t("ui.shown_of", shown=len(up) + len(down),
                                 total=len(ifaces)), style="weak"))

    # Up first: it is the shorter list and the one that is carrying traffic.
    widgets += [Separator(), Label(t("host.up", n=len(up)), style="strong")]
    widgets.append(
        Table(columns(), up, row_ids=up_ids, menu=menu, on_activate=(CAP, "about"))
        if up else Label(t("host.nothing_up") if not query else t("ui.no_match"),
                         style="weak"))
    # Down and virtual interfaces are listed rather than dropped: one that should
    # not exist is a finding, and it cannot be one if it is never shown.
    if down or not query:
        widgets += [Separator(), Label(t("host.notup", n=len(down)), style="strong")]
        widgets.append(
            Table(columns(), down, row_ids=down_ids, menu=menu,
                  on_activate=(CAP, "about"))
            if down else Label(t("host.everything_up"), style="weak"))
    return Window(name, widgets).to_spec()


# --------------------------------------------------------------------------- #
# Changing interfaces — on request, from the host panel.
# --------------------------------------------------------------------------- #
# The panel keeps the user's changes as a draft and sends them here only when
# Apply is accepted. They are checked here first — every value parsed as what it
# claims to be, never pasted into a script as typed — then each becomes a pass
# of its own over one RTR session, and the host is read again in the same
# session, so the screen shows what the changes did.

# What a change may touch, per platform. macOS is read but not changed.
_EDIT_FIELDS = {
    "win": ("ipv4", "dhcp", "gateway", "dns", "dns_auto", "metric", "profile"),
    "linux": ("ipv4", "gateway", "dns", "metric"),
}
# What can be created. Windows has one built-in way to make an interface, a
# Hyper-V internal switch (its vEthernet adapter); no supported way to make a
# bridge. Linux makes both a bridge and a plain virtual (dummy) interface.
_ADD_KINDS = {"win": ("switch",), "linux": ("bridge", "dummy")}
_PROFILES = ("Private", "Public")


class _Bad(ValueError):
    """A change that cannot be sent: the message says why, in the user's words."""


def _family(platform):
    p = (platform or "").strip().lower()
    return next((kind for prefix, kind in _SCRIPTS if p.startswith(prefix)), None)


def actions_for(platform):
    """What can be changed on a host of this platform. Empty on macOS."""
    fam = _family(platform)
    if fam not in _EDIT_FIELDS:
        return {}
    return {"edit": list(_EDIT_FIELDS[fam]), "toggle": True, "delete": True,
            "add": list(_ADD_KINDS[fam])}


def _iface(s):
    s = str(s or "").strip()
    if not s or len(s) > 256 or any(c in s for c in "`|\r\n\0"):
        raise _Bad(t("change.bad_iface"))
    return s


def _new_name(s, fam):
    s = str(s or "").strip()
    pattern = r"[A-Za-z0-9_.-]{1,15}" if fam == "linux" else r"[A-Za-z0-9 _.()-]{1,64}"
    if not re.fullmatch(pattern, s):
        raise _Bad(t("change.bad_name_" + fam))
    return s


def _v4_cidr(s):
    s = str(s or "").strip()
    try:
        net = ipaddress.IPv4Interface(s)
    except ValueError:
        raise _Bad(t("change.bad_ipv4", v=s)) from None
    if "/" not in s or not 1 <= net.network.prefixlen <= 32:
        raise _Bad(t("change.bad_ipv4", v=s))
    return str(net)


def _v4(s):
    s = str(s or "").strip()
    try:
        return str(ipaddress.IPv4Address(s))
    except ValueError:
        raise _Bad(t("change.bad_gateway", v=s)) from None


def _dns(s):
    parts = [p for p in re.split(r"[,\s]+", str(s or "").strip()) if p]
    if not 1 <= len(parts) <= 8:
        raise _Bad(t("change.bad_dns", v=s))
    try:
        return [str(ipaddress.ip_address(p)) for p in parts]
    except ValueError:
        raise _Bad(t("change.bad_dns", v=s)) from None


def _metric(s):
    s = str(s if s is not None else "").strip()
    if not s:
        return None  # automatic
    if not s.isdigit() or not 1 <= int(s) <= 9999:
        raise _Bad(t("change.bad_metric", v=s))
    return int(s)


def _truth(v):
    return v is True or str(v).strip().lower() in ("1", "true", "yes", "on")


def _normalize(change, platform):
    """One drafted change, checked and made exact — and what it says, in words.

    Raises `_Bad` with the reason when it cannot be sent as it is.
    """
    fam = _family(platform)
    acts = actions_for(platform)
    if not acts:
        raise _Bad(t("change.unsupported", platform=platform or "?"))
    op = change.get("op")
    if op == "add":
        kind = change.get("kind")
        if kind not in acts["add"]:
            raise _Bad(t("change.bad_kind"))
        name = _new_name(change.get("name"), fam)
        return {"op": "add", "kind": kind, "name": name}, t("change.add_" + kind, name=name)
    iface = _iface(change.get("iface"))
    if op in ("disable", "enable", "delete"):
        return {"op": op, "iface": iface}, t("change." + op, iface=iface)
    if op != "edit":
        raise _Bad(t("change.bad_op"))
    given = change.get("values") or {}
    vals, said = {}, []
    for key in acts["edit"]:
        if key not in given:
            continue
        raw = given[key]
        if key == "ipv4":
            vals[key] = _v4_cidr(raw)
            said.append(t("change.f_ipv4", v=vals[key]))
        elif key == "gateway":
            vals[key] = _v4(raw) if str(raw or "").strip() else ""
            said.append(t("change.f_gateway", v=vals[key]) if vals[key] else t("change.f_no_gateway"))
        elif key == "dns":
            vals[key] = _dns(raw)
            said.append(t("change.f_dns", v=", ".join(vals[key])))
        elif key == "metric":
            vals[key] = _metric(raw)
            said.append(t("change.f_metric", v=vals[key]) if vals[key] else t("change.f_metric_auto"))
        elif key == "profile":
            if raw not in _PROFILES:
                raise _Bad(t("change.bad_profile"))
            vals[key] = raw
            said.append(t("change.f_profile_" + raw.lower()))
        elif key in ("dhcp", "dns_auto"):
            if _truth(raw):
                vals[key] = True
                said.append(t("change.f_" + key))
    if vals.get("dhcp") and "ipv4" in vals:
        raise _Bad(t("change.dhcp_and_static"))
    if vals.get("dns_auto") and "dns" in vals:
        raise _Bad(t("change.dns_auto_and_list"))
    if not vals:
        raise _Bad(t("change.nothing"))
    return ({"op": "edit", "iface": iface, "values": vals},
            t("change.edit", iface=iface, what="; ".join(said)))


def _ps(s):
    """A PowerShell string literal. Single-quoted strings expand nothing; the only
    character to escape is the quote itself."""
    return "'" + str(s).replace("'", "''") + "'"


def _sh(s):
    """A POSIX shell string literal, for the same reason."""
    return "'" + str(s).replace("'", "'\\''") + "'"


_WIN_CHANGE = r"""
Write-Output '#begin'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
try {
__BODY__
Write-Output '#changed=__I__'
} catch { Write-Output ('#change-failed=__I__:' + ($_.Exception.Message -replace '[\r\n\|]', ' ')) }
"""

_SH_CHANGE = r"""
echo '#begin'
fail() { printf '#change-failed=__I__:%s\n' "$(printf '%s' "$1" | tr '\n|' '  ')"; exit 0; }
run() { out=$("$@" 2>&1) || fail "$out"; }
__BODY__
echo '#changed=__I__'
"""


def _win_body(c):
    op = c["op"]
    if op == "add":
        return "\n".join([
            "if (-not (Get-Command New-VMSwitch -ErrorAction SilentlyContinue)) "
            "{ throw 'Hyper-V is not installed on this host, and Windows has no other "
            "built-in way to create an interface' }",
            f"New-VMSwitch -Name {_ps(c['name'])} -SwitchType Internal | Out-Null",
        ])
    out = [f"$n = {_ps(c['iface'])}", "$a = Get-NetAdapter -Name $n -IncludeHidden"]
    if op == "disable":
        out.append("Disable-NetAdapter -Name $n -Confirm:$false")
    elif op == "enable":
        out.append("Enable-NetAdapter -Name $n -Confirm:$false")
    elif op == "delete":
        out += [
            "if (-not $a.Virtual) { throw 'only a virtual interface can be deleted' }",
            "$sw = $null",
            "if ($n -match '^vEthernet \\((.+)\\)$' -and (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue)) "
            "{ $sw = Get-VMSwitch -Name $Matches[1] -ErrorAction SilentlyContinue }",
            "if ($sw) { Remove-VMSwitch -Name $sw.Name -Force } else {",
            "  $o = (pnputil /remove-device $a.PnPDeviceID) -join ' '",
            "  if ($LASTEXITCODE -ne 0) { throw ('pnputil: ' + $o) }",
            "}",
        ]
    elif op == "edit":
        v = c["values"]
        # Address, mask, gateway and DHCP through netsh, in one call. Windows
        # keeps an interface's settings twice — what is in force, and what is
        # saved for the next start — and the NetTCPIP cmdlets change them
        # separately: on an adapter that is not connected, turning DHCP off
        # reaches only the first, and New-NetIPAddress then refuses with
        # "Inconsistent parameters PolicyStore PersistentStore and Dhcp
        # Enabled". netsh writes the saved settings, connected or not, and
        # turns DHCP off as part of setting an address. The interface goes by
        # its index, so a name with spaces needs no quoting.
        out.append("$i = $a.ifIndex")
        if v.get("dhcp"):
            out.append(_netsh("set address name=$i source=dhcp"))
        elif "ipv4" in v:
            net = ipaddress.IPv4Interface(v["ipv4"])
            gateway = f"gateway={v['gateway']}" if v.get("gateway") else "gateway=none"
            out.append(_netsh(f"set address name=$i source=static address={net.ip} "
                              f"mask={net.netmask} {gateway}"))
        if v.get("dns_auto"):
            out.append("Set-DnsClientServerAddress -InterfaceAlias $n -ResetServerAddresses")
        elif "dns" in v:
            out.append("Set-DnsClientServerAddress -InterfaceAlias $n -ServerAddresses @("
                       + ",".join(_ps(d) for d in v["dns"]) + ")")
        if "metric" in v:
            out.append("Set-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -AutomaticMetric Enabled"
                       if v["metric"] is None else
                       f"Set-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -InterfaceMetric {int(v['metric'])}")
        if "profile" in v:
            out.append(f"Set-NetConnectionProfile -InterfaceAlias $n -NetworkCategory {v['profile']}")
    return "\n".join(out)


def _netsh(args):
    """A netsh interface ipv4 call, and a failure of it as an exception: netsh
    reports by exit code and prints its reason, so both are caught here."""
    return (f"$o = (netsh interface ipv4 {args} 2>&1) -join ' '\n"
            "if ($LASTEXITCODE -ne 0) { throw ('netsh: ' + $o) }")


def _complete(c, hid):
    """An edit made whole for the script.

    netsh sets an address and its gateway together, so a change to only one of
    them is sent with the other as the host last had it — read, not guessed.
    An address cannot be kept that the host was never seen to have.
    """
    v = c.get("values") or {}
    if c.get("op") != "edit" or v.get("dhcp") or ("ipv4" not in v and "gateway" not in v):
        return c
    with _lock:
        known = (_reads.get(hid) or {}).get("ifaces") or []
    r = next((x for x in known if x.get("iface") == c["iface"]), {})
    # The saved settings first: that is what netsh changes, and on an adapter
    # that is not connected, what is in force is only DHCP's stand-in.
    if r.get("saved"):
        have4 = (r.get("cfg_ipv4") or "").split()
        have_gw = (r.get("cfg_gateway") or "").split()
    else:
        have4 = [a for a in (r.get("ipv4") or "").split() if ":" not in a and "/" in a]
        have_gw = [g for g in (r.get("gateway") or "").split() if ":" not in g]
    v = dict(v)
    if "ipv4" not in v:
        if not have4:
            raise _Bad(t("change.need_address", iface=c["iface"]))
        v["ipv4"] = have4[0]
    if "gateway" not in v:
        v["gateway"] = have_gw[0] if have_gw else ""
    return {**c, "values": v}


def _sh_body(c):
    op = c["op"]
    if op == "add":
        return "\n".join([
            f"run ip link add name {_sh(c['name'])} type {'bridge' if c['kind'] == 'bridge' else 'dummy'}",
            f"run ip link set dev {_sh(c['name'])} up",
        ])
    out = [f"n={_sh(c['iface'])}",
           '[ -e "/sys/class/net/$n" ] || fail "there is no interface $n"']
    if op == "disable":
        out.append('run ip link set dev "$n" down')
    elif op == "enable":
        out.append('run ip link set dev "$n" up')
    elif op == "delete":
        out += ['[ -e "/sys/class/net/$n/device" ] && fail "only a virtual interface can be deleted"',
                'run ip link delete dev "$n"']
    elif op == "edit":
        v = c["values"]
        if "ipv4" in v:
            out += ['run ip addr flush dev "$n" scope global',
                    f'run ip addr add {_sh(v["ipv4"])} dev "$n"']
        if "gateway" in v or "metric" in v:
            out.append('old=$(ip route show default dev "$n" 2>/dev/null | head -n 1)')
            if "gateway" in v and not v["gateway"]:
                out.append('[ -n "$old" ] && run ip route del default dev "$n"')
            else:
                gw = _sh(v["gateway"]) if v.get("gateway") else \
                    '"$(printf \'%s\' "$old" | awk \'{ print $3 }\')"'
                metric = f" metric {int(v['metric'])}" if v.get("metric") else ""
                out += [f"gw={gw}",
                        '[ -n "$gw" ] || fail "a metric on Linux belongs to a route, and this interface has no default route"',
                        'ip route del default dev "$n" 2>/dev/null',
                        f'ip route add default via "$gw" dev "$n"{metric} 2>/dev/null || '
                        '{ [ -n "$old" ] && ip route add $old; fail "the default route could not be set"; }']
        if "dns" in v:
            out += ['command -v resolvectl >/dev/null 2>&1 || '
                    'fail "DNS can only be set here through systemd-resolved, which this host does not run"',
                    'run resolvectl dns "$n" ' + " ".join(_sh(d) for d in v["dns"])]
    return "\n".join(out)


def _change_passes(changes, platform):
    """The passes that make `changes`, in order, ready to send."""
    fam = _family(platform)
    passes = []
    for i, c in enumerate(changes):
        if fam == "win":
            body = _WIN_CHANGE.replace("__BODY__", _win_body(c))
        else:
            body = _SH_CHANGE.replace("__BODY__", _sh_body(c))
        passes.append(_ready(f"change {i + 1}", platform, body.replace("__I__", str(i))))
    return passes


def _uplink(hid):
    """The interface this host was last seen reaching the network through."""
    with _lock:
        read = dict(_reads.get(hid) or {})
    for r in read.get("ifaces") or []:
        if r.get("up") and r.get("gateway"):
            return r["iface"]
    return None


@m.method("check")
def check(params, host):
    """Check drafted changes without sending anything: the host panel asks this
    as each change is drafted, so a mistyped address is caught then, not at Apply.

    ``{"platform", "changes": [...]}`` -> ``{"ok", "changes", "said", "error"}``,
    where ``changes`` are the same changes made exact and ``said`` is what each
    does, in words.
    """
    _sync_locale()
    try:
        done = [_normalize(c, params.get("platform")) for c in params.get("changes") or []]
    except _Bad as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "changes": [c for c, _ in done], "said": [s for _, s in done]}


@m.method("change")
def change(params, host):
    """Make drafted changes on one host, then read it again.

    ``{"id", "hostname", "platform", "changes": [...]}``. Every change is
    checked before anything is sent; one that fails stops the lot, and the
    host is not touched. Changes to the interface the host reaches the network
    through go last: if one of them cuts it off, everything else has been done.

    Returns at once, as `read_host` does — ``{"state": "scanning"}`` — and the
    caller polls `read_host`. Its answer, when done, carries ``outcome``: what
    was applied and what was not, once.
    """
    _sync_locale()
    hid = str(params.get("id") or "")
    platform = params.get("platform") or ""
    try:
        done = [_normalize(c, platform) for c in params.get("changes") or []]
        if not hid or not done:
            raise _Bad(t("change.nothing"))
        way_out = _uplink(hid)
        done.sort(key=lambda cs: cs[0].get("iface") == way_out and way_out is not None)
        passes = _change_passes([_complete(c, hid) if _family(platform) == "win" else c
                                 for c, _ in done], platform)
    except _Bad as exc:
        return {"state": "invalid", "error": str(exc)}
    with _lock:
        if (_reads.get(hid) or {}).get("state") == "scanning":
            return {"state": "invalid", "error": t("change.busy")}
    try:
        token, base = _auth(host)
    except Exception as exc:  # noqa: BLE001
        host.log(f"cs-network: auth failed: {exc}")
        return {"state": "failed", "error": str(exc)}
    plan = [s for _, s in done]
    hostname = params.get("hostname") or hid
    with _lock:
        _reads[hid] = {"state": "scanning", "at": 0.0, "started": time.time(),
                       "doing": "change", "platform": platform}

    def run():
        result = _read(hid, hostname, platform, token, base, threading.Event(),
                       before=passes)
        result["at"] = time.time()
        result["platform"] = platform
        result["outcome"] = _outcome(plan, result.pop("changed", []),
                                     result.pop("change_failed", {}))
        for i, err in sorted(result["outcome"]["failed"].items()):
            result.setdefault("notes", []).append(
                t("change.failed_one", what=plan[i], err=err))
        with _lock:
            _reads[hid] = result

    threading.Thread(target=run, name=f"cs-network-change-{hid}", daemon=True).start()
    host.log(f"cs-network: changing {hostname}: " + "; ".join(plan))
    return {"state": "scanning", "elapsed": 0, "doing": "change"}


def _outcome(plan, changed, failed):
    """How a set of changes went: what was applied, and why the rest was not.

    A change that reported neither is a failure too — the session ended before
    it answered, which is what cutting a host off looks like from here.
    """
    failed = {int(i): err for i, err in failed.items()}
    for i in range(len(plan)):
        if i not in changed and i not in failed:
            failed[i] = t("change.no_answer")
    ok = len(plan) - len(failed)
    if not failed:
        level, text = "ok", t("change.all_applied", n=ok)
    elif ok:
        level, text = "warning", t("change.some_applied", ok=ok, n=len(plan))
    else:
        level, text = "error", t("change.none_applied")
    return {"level": level, "text": text, "failed": failed}


@m.method("read_host")
def read_host(params, host):
    """One host's interfaces, read on request — for the host panel.

    ``{"id", "hostname", "platform"}``, as the ``crowdstrike`` inventory gives
    them. ``"refresh": true`` reads the host again; ``"start": false`` only says
    what is already known, for a host that is offline and cannot be asked.

    Returns at once. A read takes seconds, so this starts it and answers
    ``{"state": "scanning", "elapsed": seconds}``; the caller asks again until it
    is ``done``, ``failed`` or ``skipped``. A finished read is kept, and answered
    from until a refresh — a failure too, so that a caller that polls does not
    start a new read on every frame of a screen that shows the error.

    A ``done`` answer is ready to show, in the language Limen is in: a
    ``headline``, and ``groups`` — the interfaces that are up, then the ones that
    are not — each with a ``title``, its ``columns`` and ``rows``, and the line to
    show instead when it has none (``empty``). ``at`` is when it was read, and
    ``ifaces`` holds every interface as data.
    """
    _sync_locale()
    hid = str(params.get("id") or "")
    if not hid:
        return {"state": "failed", "error": "no host id"}
    with _lock:
        known = dict(_reads.get(hid) or {})
        # What a set of changes did is said once: the first answer after it
        # carries it, and the screens after that do not say it again.
        if known.get("outcome") and not known.get("reported") and known["state"] != "scanning":
            _reads[hid]["reported"] = True
        else:
            known.pop("outcome", None)
    if known and (known["state"] == "scanning" or not params.get("refresh")):
        return _read_answer(known)
    if not params.get("start", True):
        return _read_answer(known) if known else {"state": "none"}

    # The token is fetched here, on the dispatch thread, as for a fleet scan.
    try:
        token, base = _auth(host)
    except Exception as exc:  # noqa: BLE001
        host.log(f"cs-network: auth failed: {exc}")
        return {"state": "failed", "error": str(exc)}
    hostname = params.get("hostname") or hid
    platform = params.get("platform") or ""
    with _lock:
        _reads[hid] = {"state": "scanning", "at": 0.0, "started": time.time(),
                       "platform": platform}

    def run():
        done = _read(hid, hostname, platform, token, base, threading.Event())
        done["at"] = time.time()
        done["platform"] = platform
        done.pop("changed", None)
        done.pop("change_failed", None)
        with _lock:
            _reads[hid] = done

    threading.Thread(target=run, name=f"cs-network-read-{hid}", daemon=True).start()
    host.log(f"cs-network: reading {hostname} for another module")
    return {"state": "scanning", "elapsed": 0}


def _read_answer(read):
    """What `read_host` says about a read, ready to show."""
    out = {
        "state": read["state"],
        "at": read.get("at", 0.0),
        "error": read.get("error", ""),
        "notes": list(read.get("notes", [])),
    }
    if read["state"] == "scanning":
        # How long it has been going, so a screen waiting on it can say so —
        # an RTR read takes tens of seconds, and a still screen reads as stuck.
        out["elapsed"] = int(time.time() - read.get("started", time.time()))
        if read.get("doing"):
            out["doing"] = read["doing"]
    if read.get("outcome"):
        out["outcome"] = {"level": read["outcome"]["level"], "text": read["outcome"]["text"]}
    if read["state"] == "done":
        ifaces = read["ifaces"]
        up = [_cells(r) for r in ifaces if r["up"]]
        down = [_cells(r) for r in ifaces if not r["up"]]
        # What can be changed on this host, so a caller offers only that.
        out["actions"] = actions_for(read.get("platform"))
        out["headline"] = t("host.summary", n=len(ifaces))
        # Up first: the shorter list, and the one carrying traffic. Down and
        # virtual interfaces are listed rather than dropped — one that should
        # not exist is a finding, and it cannot be one if it is never shown.
        out["groups"] = [
            {"title": t("host.up", n=len(up)), "columns": columns(), "rows": up,
             "empty": t("host.nothing_up"),
             "keys": [r["iface"] for r in ifaces if r["up"]]},
            {"title": t("host.notup", n=len(down)), "columns": columns(), "rows": down,
             "empty": t("host.everything_up"),
             "keys": [r["iface"] for r in ifaces if not r["up"]]},
        ]
        out["ifaces"] = [{k: r.get(k) for k in (
            "iface", "kind", "mac", "ipv4", "ipv6", "gateway", "dns", "state", "speed",
            "up", "profile", "metric", "auto_metric", "dhcp", "dns_auto",
            "saved", "cfg_ipv4", "cfg_gateway", "cfg_dns")} for r in ifaces]
    return out


@m.method("about")
def about(params, host):
    """One interface, opened in a tab."""
    _sync_locale()
    r = _shown.get(str(params.get("id", "")))
    if not r:
        return Window(t("iface.window"), [Label(t("iface.gone"))]).to_spec()

    def field(label, value):
        return Label(f"{label}: {value}" if value else f"{label}: —")

    return Window(r.get("iface") or t("iface.window"), [
        Label(r.get("iface") or t("iface.unnamed"), style="heading"),
        Label(t("iface.is_up") if r.get("up")
              else t("iface.is_down", state=r.get("state") or "?"), style="weak"),
        Separator(),
        field(t("iface.host"), r.get("host")),
        field(t("iface.type"), r.get("kind")),
        field(t("iface.mac"), r.get("mac")),
        field(t("iface.ipv4"), r.get("ipv4")),
        field(t("iface.ipv6"), r.get("ipv6")),
        field(t("iface.gateway"), r.get("gateway")),
        field(t("iface.dns"), r.get("dns")),
        field(t("iface.speed"), r.get("speed")),
        Separator(),
        field(t("iface.falcon_id"), r.get("host_id")),
    ]).to_spec()


@m.method("network")
def network(params, host):
    """The capability method: every scanned interface as data, for other modules.

    Reports the last scan rather than starting one — a scan runs across the fleet
    and takes minutes, which is not something another module should set off by
    asking a question.

    ``{"address": "10.1.2."}`` matches any IPv4 or IPv6 address by prefix and
    ``{"mac": "00:1a"}`` any MAC, both case-insensitively — which is the shape of
    the question actually asked of this data: *which host is this?*
    """
    with _lock:
        if not _jobs:
            return {"error": "nothing scanned yet", "total": 0, "interfaces": []}
        rows = [r for j in _jobs.values() for r in j["ifaces"]]
        failed = {j["hostname"]: j["error"] for j in _jobs.values()
                  if j["state"] in ("failed", "skipped")}
        # Computed here rather than by calling `_busy()`: that takes `_lock` too,
        # and `_lock` is a plain Lock, not an RLock.
        pending = any(j["state"] in ("queued", "scanning") for j in _jobs.values())
    addr = (params.get("address") or "").strip().lower()
    if addr:
        rows = [r for r in rows
                if any(a.lower().startswith(addr)
                       for a in (r["ipv4"] + " " + r["ipv6"]).split())]
    mac = (params.get("mac") or "").strip().lower()
    if mac:
        # Matched with the separators taken out, so a search does not have to
        # guess whether this host writes a MAC with colons or dashes.
        flat = mac.replace(":", "").replace("-", "")
        rows = [r for r in rows
                if r["mac"].lower().replace(":", "").replace("-", "").startswith(flat)]
    want = params.get("up")
    if want is not None:
        rows = [r for r in rows if r["up"] == bool(want)]
    up = sum(1 for r in rows if r["up"])
    return {
        "note": "Network interfaces across CrowdStrike fleet hosts, read over RTR. "
                "Every interface is reported, including ones that are down and "
                "virtual ones — a bridge or tunnel that should not be there is "
                "the thing worth seeing. Several addresses on one interface "
                "arrive space-separated in `ipv4`/`ipv6`.",
        "scanning": pending,
        "total": len(rows),
        "up": up,
        "down": len(rows) - up,
        "hosts": len({r["host_id"] for r in rows}),
        "failed_hosts": failed,
        "interfaces": rows,
    }

# --------------------------------------------------------------------------- #
# The screen.
# --------------------------------------------------------------------------- #
# What each job state says, and which `Step` icon it gets. "pending" is the idle
# dot, "loading" the spinner, "done" the check — so a failed or stopped host
# reads as finished-and-not-ok rather than as still going, which is the one thing
# it must never look like.
def state_text(state):
    """What a host's row says it is doing, in the current language."""
    return t("state." + state) if state in (
        "queued", "scanning", "done", "failed", "stopped", "skipped") else state
_STATE_ICON = {
    "queued": "pending",
    "scanning": "loading",
    "done": "done",
    "failed": "pending",
    "stopped": "pending",
    "skipped": "pending",
}


class Step:
    """A progress step: an animated spinner that morphs into a check.

    Built as a raw spec rather than imported, because the Python SDK has no `Step`
    even though the host renders one. Same for the view's `auto` below.
    """

    def __init__(self, label="", state="pending"):
        self.label, self.state = label, state

    def to_spec(self):
        return {"kind": "step", "label": self.label, "state": self.state}


def _host_lines(widgets, rows):
    """One line per host: the tick box that selects it, and — once a scan has
    touched it — the live state beside it."""
    with _lock:
        jobs = {hid: dict(j) for hid, j in _jobs.items()}
    for h in rows:
        hid = h.get("id", "")
        job = jobs.get(hid)
        line = [Checkbox(f"sel_{hid}", label=h.get("hostname", "?"))]
        if job:
            text = state_text(job["state"])
            if job["state"] == "done":
                text = t("status.items", n=len(job["ifaces"]))
            elif job["state"] == "failed" and job["error"]:
                text = t("state.failed_why", why=job["error"][:60])
            line.append(Step(label=text, state=_STATE_ICON.get(job["state"], "pending")))
        widgets.append(Row(line))
        detail = "   ·   ".join(p for p in [
            h.get("os", ""),
            f"SN {h['serial']}" if h.get("serial") else "",
            h.get("tags", ""),
        ] if p)
        if detail:
            widgets.append(Label("      " + detail, style="weak"))


def _finished_table(widgets):
    """The hosts that have finished, double-click to open one.

    Separate from the lines above because a table row is what carries a
    double-click, and because it is the natural place to be told which hosts are
    ready to look at while the rest are still running.
    """
    with _lock:
        done = [(hid, dict(j)) for hid, j in _jobs.items() if j["state"] == "done"]
    if not done:
        return
    done.sort(key=lambda kv: kv[1]["hostname"].lower())
    rows, ids = [], []
    for hid, j in done:
        up = sum(1 for r in j["ifaces"] if r["up"])
        addrs = sum(len((r["ipv4"] + " " + r["ipv6"]).split()) for r in j["ifaces"])
        rows.append([j["hostname"], str(len(j["ifaces"])), str(up), str(addrs)])
        ids.append(hid)
    widgets += [
        Separator(),
        Label(t("ui.scanned", n=len(rows)), style="strong"),
        Table([t("ui.col_host"), t("ui2.col_ifaces"), t("ui2.col_up"),
               t("ui2.col_addrs")], rows,
              row_ids=ids, on_activate=(CAP, "open_host"),
              menu=[MenuItem(t("ui.open_host"), capability=CAP, method="open_host",
                             open_in_tab=True)]),
    ]


def _failed_table(widgets):
    """Hosts that were not read, listed rather than counted.

    An absent host is the one case where an empty result means nothing at all, so
    the operator has to know which machine to go and look at by hand. Hosts whose
    OS this module cannot read are in here too: they are not failures, but they
    are equally not answers, and leaving them out would quietly shrink the fleet.
    """
    with _lock:
        bad = [dict(j) for j in _jobs.values() if j["state"] in ("failed", "skipped")]
    if not bad:
        return
    widgets += [
        Separator(),
        Label(t("ui.not_scanned", n=len(bad)), style="strong"),
        Table([t("ui.col_host"), t("ui.col_why")], sorted([[j["hostname"], j["error"]] for j in bad])),
    ]


@m.ui
def ui():
    _sync_locale()
    widgets = [
        Label(t("ui.title"), style="heading"),
        Label(t("ui.subtitle"), style="weak"),
    ]

    rows = _hosts["rows"]
    running = _busy()
    toolbar = [Button(t("ui.fetch_hosts"), calls="fetch", primary=rows is None,
                      enabled=not running)]
    if rows:
        toolbar.append(Button(t("ui.scan_selected"), calls="scan_selected",
                              primary=True, enabled=not running))
        toolbar.append(Button(t("ui.scan_all"), calls="scan_all",
                              enabled=not running))
        # Only offered while there is something to stop, so it is never a button
        # that does nothing.
        if running:
            toolbar.append(Button(t("ui.stop"), calls="stop", danger=True))
    widgets.append(Row(toolbar))

    if _status["msg"]:
        widgets.append(Label(_status["msg"], style="weak"))

    if rows is not None:
        widgets.append(Separator())
        widgets.append(Label(t("ui.reachable", n=len(rows)), style="strong"))
        if not rows:
            widgets.append(Label(t("ui.no_reachable"), style="weak"))
        _host_lines(widgets, rows)

    _finished_table(widgets)
    _failed_table(widgets)

    spec = Window(t("ui.title"), widgets).to_spec()
    # While anything is still running, ask the host to call `progress` as soon as
    # this has drawn — that loop is what makes the spinners move and the finished
    # hosts appear one at a time. It stops being emitted the moment the work is
    # done, which is what ends the loop.
    if running:
        spec["auto"] = {"capability": CAP, "method": "progress", "args": {}}
    return spec


if __name__ == "__main__":
    m.run()
