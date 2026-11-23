"""The module object, its strings, and the state the fleet scan shares between threads."""

import os
import queue
import threading

from limen_sdk import Catalog, Module


# The module's own strings, in `locales/` beside `src/`. `host.locale()` is
# asked per render rather than once at start: the language is the
# application's setting and can change while the module is running.
CAT = Catalog.from_dir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ("en", "uk"))
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
