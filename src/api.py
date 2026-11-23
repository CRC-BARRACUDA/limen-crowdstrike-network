"""What other modules ask for: one host read on request, and the scan as data."""

import threading
import time

from app import _jobs, _lock, _reads, _sync_locale, m, t
from rtr import _auth
from scan import _read
from view import _cells, columns
from change import actions_for


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
