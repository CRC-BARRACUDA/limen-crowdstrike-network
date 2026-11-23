"""Changing interfaces for the host panel: checking drafted changes, and making them."""

import ipaddress
import re
import threading
import time

from app import _lock, _reads, _sync_locale, m, t
from scripts import _SCRIPTS, _ready
from rtr import _auth
from scan import _read


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
