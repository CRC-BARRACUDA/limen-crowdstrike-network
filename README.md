# limen-crowdstrike-network

Every network interface on every CrowdStrike fleet host, read over Real Time
Response — addresses, MACs, gateways, DNS and link state.

The answer to *who has that IP*, *where is that MAC*, and *what else is this
machine attached to*.

## Why ask the host

Falcon's own inventory carries a host's **primary** address and MAC. That is one
interface out of however many it has, and on a triage question the interesting
one is rarely the primary — it is the VPN adapter, the bridge, the second NIC on
a management VLAN. So the question is asked on the host itself.

One RTR session **per host**, on a small thread pool. Tick the hosts, press Scan,
and the list fills in as answers arrive — a spinner beside each host while it
runs, and a double-click on any finished host opens its interfaces in a tab
**while the rest are still scanning**. Stop calls off whatever has not started.

## What it reads

| Platform | Sources |
|---|---|
| Windows | `Get-NetAdapter`, with `Get-NetIPAddress`, `Get-NetRoute` and `Get-DnsClientServerAddress` joined on by interface index |
| Linux | `/sys/class/net` for the list, MAC and link state; `ip` for addresses and routes; `/etc/resolv.conf` |
| macOS | `ifconfig`, with `networksetup` for the recognisable names, `route` for the gateway and `scutil` for resolvers |

Windows hosts older than Server 2012 have no `Get-NetAdapter`; those fall back to
`Win32_NetworkAdapterConfiguration`, which is thinner but is the difference
between a partial answer and none. The host's row says when that happened.

**Everything is reported**, including interfaces that are down and virtual ones —
a bridge or a tunnel that should not be there is exactly the thing worth seeing.
They are labelled (`virtual`, `wifi`, `loopback`) and the screen groups by state
rather than hiding them.

Several addresses on one interface is ordinary, so they are kept on the one row,
space-separated. Splitting them into rows would multiply the interface instead of
describing it.

## Nothing shows on the endpoint

Every PowerShell output stream is set to `SilentlyContinue`, the body is wrapped
so an unforeseen throw cannot surface, and on Unix `stderr` is closed for the
whole script. No files are written and no window is opened. Anything that went
wrong travels back as data — a note on that host's row — not onto somebody's
screen.

The fleet scan is read-only: the interface, route and resolver tables are read
and nothing is changed. **The host panel can change interfaces through this
module** — see *Changing interfaces* below — so the permission is the honest one,
`run_hosts`. **This executes code on your fleet, and some of it changes how a host
reaches the network.**

## Changing interfaces

Asked by the host panel, never on its own, and never one change at a time: the
user drafts changes, and Apply opens a window listing every one before anything
is sent.

* `check` validates drafted changes and sends nothing. Every value is parsed as
  what it claims to be — an IPv4 address with its prefix, a list of DNS servers,
  a metric from 1 to 9999 — and never pasted into a script as typed; interface
  names are quoted for PowerShell or the shell, and refused if they could not be.
* `change` makes them, each as a pass of its own over **one** RTR session, then
  reads the host again in the same session. Changes to the interface the host
  reaches the network through go **last**: if one of them cuts the host off,
  everything else has been done. A change that never reported back is reported
  as not applied — which is what losing the host looks like from here.

| | Windows | Linux |
|---|---|---|
| address, gateway | `netsh interface ipv4 set address` — static or DHCP, written to the saved settings, so it works on an unplugged adapter too | `ip addr`, `ip route` |
| DNS | `Set-DnsClientServerAddress`, or from DHCP | `resolvectl` (systemd-resolved only) |
| metric | `Set-NetIPInterface` | the default route's metric |
| network profile | `Set-NetConnectionProfile` — Private or Public; a domain network is the domain's | — |
| disconnect, connect | `Disable-`/`Enable-NetAdapter` | `ip link set down/up` |
| delete | virtual adapters: the Hyper-V switch, else `pnputil /remove-device` | virtual interfaces |
| create | a Hyper-V internal switch (needs Hyper-V); no supported way to make a bridge | a bridge, or a virtual (dummy) interface |

macOS hosts are read, not changed. On Linux, `ip` changes last until reboot, and
NetworkManager may put its own settings back.

## It needs no privileges on your own machine

`network` and `run_hosts`, and nothing else. No `admin`, no `elevate`, no
`may_require_admin`: Limen's own process only makes HTTPS calls. The privilege it
needs is remote and Falcon-side — the RTR admin tier for `runscript` — a scope on
your API client, granted in the Falcon console.

## Requires

* The [`crowdstrike`](https://github.com/CRC-BARRACUDA/limen-crowdstrike) module,
  configured. It owns the credentials; this module owns none.
* RTR enabled, with the admin tier on the API client.

## Capability

Provides `crowdstrike.network`.

```
network                        -> the last scan as data
network {"address": "10.1.2."} -> any interface whose IPv4/IPv6 starts with that
network {"mac": "00:1a"}       -> any interface whose MAC starts with that
network {"up": false}          -> only what is not up
read_host {"id", "hostname", "platform"}
                               -> read one host on request (the host panel's Network)
```

`read_host` reads one machine apart from the fleet scan — it neither wipes what
the fleet screen shows nor waits for it — and answers at once: `scanning` (with
`elapsed` seconds) until the read is done, then a screen-ready answer in Limen's
language: the interfaces that are up and the ones that are not, as two tables.
`refresh: true` reads again; `start: false` only reports a read taken before, for
a host that is offline. A finished read is kept, failures included, so a caller
that polls never starts a new read per poll.

The address and MAC lookups are the shape of the question actually asked of this
data — *which host is this?* — so the MAC match ignores separators: a search need
not guess whether a given host writes them with colons or dashes.

It reports the last scan rather than starting one: a scan runs across the fleet
and takes minutes, which is not something another module should set off by asking
a question.

## Licence

GPL-3.0-or-later.
