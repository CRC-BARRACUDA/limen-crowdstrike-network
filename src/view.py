"""What the screens show: the fleet view, one host's tab and one interface's."""

from limen_sdk import (
    Button,
    Checkbox,
    Label,
    MenuItem,
    Row,
    Separator,
    Table,
    Text,
    Window,
)

from app import CAP, _hosts, _jobs, _lock, _status, _sync_locale, m, t
from scan import _busy


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
