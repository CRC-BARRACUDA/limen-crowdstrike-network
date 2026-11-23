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

# Each file registers its own methods on `m` when it is imported. Nothing
# imports this one: it runs as `__main__`, and a second import of it would be
# a second module.
import api  # noqa: F401
import change  # noqa: F401
import scan  # noqa: F401
import view  # noqa: F401
from app import m


if __name__ == "__main__":
    m.run()
