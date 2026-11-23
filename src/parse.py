"""Turning a host's script output into interface rows."""

import ipaddress


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
