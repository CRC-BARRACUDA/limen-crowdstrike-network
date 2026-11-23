"""The enumeration scripts each platform runs over RTR, and the limits they are built to."""



# A scan of a large fleet returns a lot of rows, and every one of them crosses
# the RTR response, this process, and the UI — so there is a cap per host.
#
# Set far higher than the device list's, because the shape of the data is
# different: a host has a handful of physical interfaces and can have hundreds of
# virtual ones — container veths, tunnels, VPN adapters — and on a container host
# that is the whole list. Generous enough that the cap is a guard rather than a
# limit, and when it does bite the host says so on its own row.
MAX_ROWS_PER_HOST = 5000

# The most one `runscript -Raw` may carry. The command travels as a single string
# in a REST body, and the figures quoted for RTR sit around 4 KB — so this is set
# below that and enforced when the script is built, where it is a loud failure in
# a test, rather than discovered on a host as empty output.
MAX_SCRIPT_BYTES = 4000


class _UnknownOS(Exception):
    """The host's OS is not one this module can read, so nothing is run on it."""

    def __init__(self, platform):
        super().__init__(f"unsupported OS: {platform}")
        self.platform = platform


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
