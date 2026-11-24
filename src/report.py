"""The last scan as a report, when a report provider is installed.

`report.build` is optional: the button appears only while a provider is loaded,
so nothing here is reached by somebody with no way to read the result.

What the document is — a PDF — the ground it is printed on, and whether it is
signed are decided in the provider's preview, beside the thing being saved, by
the module that owns the question. This one only says what was read.
"""

from limen_sdk import Label, Window

from app import _jobs, _lock, _sync_locale, m, t
from view import _cells, _query, columns


def _matching(ifaces, query):
    """The interfaces a host tab is showing: all of them, or what its filter left."""
    if not query:
        return list(ifaces)
    return [r for r in ifaces if query in " ".join(_cells(r)).lower()]


def _up_first(ifaces):
    """Up first, as on the screen: the shorter list, and the one carrying traffic."""
    return [r for r in ifaces if r["up"]] + [r for r in ifaces if not r["up"]]


def report_spec(hid=None):
    """The last scan as a report spec, or `None` when there is nothing to report.

    With `hid`, one host: what its tab shows, filter included — a report that
    quietly widened back out to every interface would not be the thing the
    person asked for, and they would have no way to tell. Without it, the fleet:
    every host that was read, and a list of the ones that were not — an absent
    host is the one case where an empty result means nothing at all.
    """
    with _lock:
        jobs = {k: dict(j) for k, j in _jobs.items()}
    if hid is not None:
        job = jobs.get(hid)
        if not job or job["state"] != "done":
            return None
        done, bad = [(hid, job)], []
    else:
        done = sorted(((k, j) for k, j in jobs.items() if j["state"] == "done"),
                      key=lambda kv: kv[1]["hostname"].lower())
        bad = sorted([j["hostname"], j["error"]] for j in jobs.values()
                     if j["state"] in ("failed", "skipped"))
        if not done and not bad:
            return None

    sections, notes, kinds = [], [], {}
    total = up = 0
    for k, job in done:
        query = (_query.get(k) or "").lower() if hid is not None else ""
        ifaces = _matching(job["ifaces"], query)
        total += len(ifaces)
        up += sum(1 for r in ifaces if r["up"])
        for r in ifaces:
            kind = r.get("kind") or "—"
            kinds[kind] = kinds.get(kind, 0) + 1
        for note in job["notes"]:
            notes.append(f"{job['hostname']}: {note}")
        if hid is not None:
            # One host: the two tables its tab shows.
            live = [r for r in ifaces if r["up"]]
            rest = [r for r in ifaces if not r["up"]]
            for title, rows in ((t("host.up", n=len(live)), live),
                                (t("host.notup", n=len(rest)), rest)):
                if rows:
                    sections.append({"heading": title, "columns": columns(),
                                     "rows": [_cells(r) for r in rows]})
        else:
            # The fleet: a table per host, so a page says whose interfaces it lists.
            sections.append({
                "heading": t("report.host_section", host=job["hostname"], n=len(ifaces)),
                "columns": columns(),
                "rows": [_cells(r) for r in _up_first(ifaces)],
            })
    if bad:
        sections.append({"heading": t("ui.not_scanned", n=len(bad)),
                         "columns": [t("ui.col_host"), t("ui.col_why")], "rows": bad})

    chart = [{"label": k, "value": v}
             for k, v in sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))]
    summary = [t("report.line_ifaces", n=total), t("report.line_up", n=up),
               t("report.line_down", n=total - up)]
    if hid is not None:
        name = done[0][1]["hostname"]
        subtitle = t("report.subtitle_host", host=name, n=total, up=up)
        # Filed under the machine it is about. The report module adds the date; a
        # folder of files all called "network" is one nobody can find anything in.
        file_name = f"{name}_network"
    else:
        subtitle = t("report.subtitle_fleet", hosts=len(done), n=total, up=up)
        file_name = "fleet_network"
        summary.insert(0, t("report.line_hosts", n=len(done)))
        if bad:
            summary.append(t("report.line_not_read", n=len(bad)))
    return {
        "title": t("report.title"),
        "subtitle": subtitle,
        "file_name": file_name,
        # Always the provider's preview: see the top of this file.
        "format": "view",
        "summary": summary + notes,
        "charts": [{"title": t("report.by_type"), "data": chart}] if chart else [],
        "sections": sections,
    }


@m.method("make_report")
def make_report(params, host):
    """Hand the last scan — or, with ``{"id"}``, one host of it — to whatever
    report provider is installed."""
    _sync_locale()
    hid = str(params.get("id") or "") or None
    spec = report_spec(hid)
    if spec is None:
        return Window(t("report.title"), [
            Label(t("report.nothing"), style="strong"),
        ]).to_spec()
    try:
        built = host.call("report.build", "build", spec)
    except Exception as exc:  # noqa: BLE001
        return Window(t("report.title"), [
            Label(t("report.failed"), style="strong"),
            Label(str(exc), style="weak"),
        ]).to_spec()
    # The provider answers with a screen of its own — it is the report.
    if isinstance(built, dict) and built.get("widgets") is not None:
        return built
    # A provider that writes a file and acknowledges with nothing. The one
    # shipped with Limen always answers with a screen; this is for any other.
    return Window(t("report.title"), [
        Label(t("report.written"), style="strong"),
    ]).to_spec()
