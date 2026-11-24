"""Route/neighbor/RIF VRF consistency when a port is reused right after its VRF is deleted.

``config vrf del`` returns once CONFIG_DB is updated; it does not wait for orchagent to remove
the router interface (RIF) of a port bound to the VRF. With many routes in the VRF that removal
takes seconds. A port re-addressed in the default VRF inside that window, with a neighbor on the
new subnet, must still end up with exactly one RIF, in the default virtual router: the RIF and
virtual router of the deleted VRF must go away, and ASIC_DB must never show the neighbor or a route
programmed through a RIF of another virtual router.

The neighbor is a permanent kernel entry installed right after the re-address; neighsyncd
publishes it to NEIGH_TABLE the same way as a neighbor learned by ARP.
"""

import ast
import json
import logging
import re
import shlex
import time

import pytest
from natsort import natsorted

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.plugins.test_completeness import CompletenessLevel
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
]

VRF_OLD = "Vrf_reuse_a"
OLD_ADDR = "198.51.100.1/26"
OLD_SUBNET = "198.51.100.0/26"
OLD_HOST = "198.51.100.1/32"
OLD_GW = "198.51.100.2"
OLD_GW_MAC = "00:11:22:33:55:00"
NEW_ADDR = "203.0.113.1/26"
NEW_SUBNET = "203.0.113.0/26"
NEW_HOST = "203.0.113.1/32"
NEW_PEER = "203.0.113.2"
NEW_PEER_MAC = "00:11:22:33:66:01"
AUDIT_PREFIXES = [OLD_SUBNET, OLD_HOST, NEW_SUBNET, NEW_HOST]

# Static host routes of VRF_OLD through OLD_GW. Withdrawing them after the VRF delete keeps
# the old RIF referenced for a few seconds (about 2.7 s for 20000 on a KVM t0).
DRAIN_ROUTE_COUNT = 20000
DRAIN_ADD_CONF = "/tmp/vrf_reuse_drain_add.conf"
DRAIN_DEL_CONF = "/tmp/vrf_reuse_drain_del.conf"

ITERATIONS = {"debug": 1, "basic": 2, "confident": 3, "thorough": 5}

CMD_TIMEOUT = 60
SETTLE_TIMEOUT = 60
LOAD_TIMEOUT = 300
ITERATION_BUDGET = 300
CLEANUP_BUDGET = 420

ASIC_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_"
SWSS_REC = "/var/log/swss/swss.rec"
SAIREDIS_REC = "/var/log/swss/sairedis.rec"

RACE = "VRF delete / port reuse race reproduced: "
MACHINERY = "Test machinery failure (not the race under test): "

# KEYS and HGETALL are separate reads; parse_snapshot() rejects a dump in which an object
# vanished in between. </dev/null keeps sonic-db-cli from draining the while-read loop's stdin.
SNAPSHOT_CMD = (
    "names() { sonic-db-cli ASIC_DB KEYS \"$1\"; }; "
    "dump() { keys=$(sonic-db-cli ASIC_DB KEYS \"$1\") || return 1; [ -z \"$keys\" ] && return 0; "
    "printf '%s\\n' \"$keys\" | while read -r key; do "
    "printf '%s|%s\\n' \"$key\" \"$(sonic-db-cli ASIC_DB HGETALL \"$key\" </dev/null)\"; done; }; "
    "echo @@VR && names '" + ASIC_PREFIX + "VIRTUAL_ROUTER:*' && "
    "echo @@RIF && dump '" + ASIC_PREFIX + "ROUTER_INTERFACE:*' && "
    "echo @@NEIGH && names '" + ASIC_PREFIX + "NEIGHBOR_ENTRY:*' && echo @@ROUTE && "
    + " && ".join("dump '{}ROUTE_ENTRY:*\"dest\":\"{}\"*'".format(ASIC_PREFIX, p) for p in AUDIT_PREFIXES)
    + " && echo @@END")

# Generated drain routes in ASIC_DB as "<count> <vr>" lines; the key is {"dest","switch_id","vr"}.
DRAIN_COUNT_CMD = (
    "sonic-db-cli ASIC_DB KEYS '" + ASIC_PREFIX + "ROUTE_ENTRY:{\"dest\":\"100.64.*' | awk -F'\"' "
    "'$4 ~ /^100[.]64[.][0-9]+[.][0-9]+\\/32$/ {n[$12]++} END {for (vr in n) print n[vr], vr}'")


def sections(lines):
    """Split command output into the sections that start with '@@<name>' lines."""
    found, current = {}, None
    for line in lines:
        line = line.strip()
        if line.startswith("@@"):
            current = found.setdefault(line[2:], [])
        elif line and current is not None:
            current.append(line)
    return found


def parse_snapshot(lines, port_oid):
    """Parse the output of SNAPSHOT_CMD; None if it is incomplete or incoherent."""
    found = sections(lines)
    if "END" not in found:
        return None

    def keyed(name):
        for line in found.get(name, []):
            key, _sep, attrs = line.partition("|")
            if not key.startswith(ASIC_PREFIX):
                raise ValueError(line)
            yield key.split(":", 2)[2], ast.literal_eval(attrs) if attrs else {}

    try:
        snap = {"vrs": set(ident for ident, _attrs in keyed("VR")), "rifs": {}, "routes": [],
                "neighbors": [json.loads(ident) for ident, _attrs in keyed("NEIGH")]}
        for ident, attrs in keyed("RIF"):
            snap["rifs"][ident] = {"port": attrs.get("SAI_ROUTER_INTERFACE_ATTR_PORT_ID", ""),
                                   "vr": attrs["SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID"]}
        for ident, attrs in keyed("ROUTE"):
            entry = json.loads(ident)
            snap["routes"].append({"dest": entry["dest"], "vr": entry["vr"],
                                   "nh": attrs["SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID"]})
    except (KeyError, ValueError, SyntaxError):
        return None
    snap["port_rifs"] = sorted(rif for rif, attrs in snap["rifs"].items() if attrs["port"] == port_oid)
    return snap


def find_violations(snap, expected):
    """Compare an ASIC_DB snapshot with the state the port must reach. Returns (hard, gaps):
    a route or the new neighbor bound to a RIF of another virtual router is never acceptable;
    gaps are acceptable while the port converges. A reference to a RIF that is not in the
    snapshot (read before it was created) is a gap, not a violation."""
    vr_of = {rif: attrs["vr"] for rif, attrs in snap["rifs"].items()}
    if expected.get("old_rif"):
        vr_of.setdefault(expected["old_rif"], expected["old_vr"])
    hard, gaps = [], []
    for route in snap["routes"]:
        if vr_of.get(route["nh"], route["vr"]) != route["vr"]:
            hard.append({"kind": "route_on_rif_of_other_vr", "dest": route["dest"], "route_vr": route["vr"],
                         "rif": route["nh"], "rif_vr": vr_of[route["nh"]]})
    for neigh in snap["neighbors"]:
        if neigh["ip"] == expected.get("neighbor") and vr_of.get(neigh["rif"], expected["vr"]) != expected["vr"]:
            hard.append({"kind": "neighbor_on_rif_of_other_vr", "ip": neigh["ip"], "rif": neigh["rif"],
                         "rif_vr": vr_of[neigh["rif"]]})
    rifs = snap["port_rifs"]
    port_rif = rifs[0] if len(rifs) == 1 and vr_of[rifs[0]] == expected["vr"] else None
    if port_rif is None:
        gaps.append({"kind": "port_rif_not_in_expected_vr", "rifs": {rif: vr_of[rif] for rif in rifs}})
    if expected.get("old_rif") in snap["rifs"]:
        gaps.append({"kind": "old_rif_still_present", "rif": expected["old_rif"]})
    if expected.get("old_vr") in snap["vrs"]:
        gaps.append({"kind": "old_vr_still_present", "vr": expected["old_vr"]})
    for dest in expected["routes"]:
        routes = [r for r in snap["routes"] if r["dest"] == dest and r["vr"] == expected["vr"]]
        if not routes or (dest in expected["on_rif"] and routes[0]["nh"] != port_rif):
            gaps.append({"kind": "expected_route_missing", "dest": dest})
    for dest in expected.get("absent", []):
        if any(r["dest"] == dest for r in snap["routes"]):
            gaps.append({"kind": "route_not_withdrawn", "dest": dest})
    if expected.get("neighbor") and not any(n["ip"] == expected["neighbor"] and n["rif"] == port_rif
                                            for n in snap["neighbors"]):
        gaps.append({"kind": "expected_neighbor_missing", "ip": expected["neighbor"]})
    return hard, gaps


def drain_route_lines(remove=False):
    """vtysh input that adds (or removes) the DRAIN_ROUTE_COUNT host routes of VRF_OLD."""
    routes = ["{}ip route 100.64.{}.{}/32 {}".format("no " if remove else "", i // 256, i % 256, OLD_GW)
              for i in range(1, DRAIN_ROUTE_COUNT + 1)]
    return "\n".join(["vrf " + VRF_OLD] + routes + ["exit-vrf"]) + "\n"


class Budget(object):
    """One monotonic deadline shared by every command and wait of a phase of the test."""

    def __init__(self, seconds, name):
        self.end = time.monotonic() + seconds
        self.name = name

    def left(self, step, cap):
        """Seconds that step may take: at most cap and never past the deadline."""
        remaining = int(self.end - time.monotonic())
        if remaining < 1:
            pytest.fail("The {} time budget ran out at: {}".format(self.name, step))
        return min(cap, remaining)


def _run(duthost, cmd, budget, step, cap=CMD_TIMEOUT):
    """Run cmd in bash (pipefail) on the DUT, bounded by cap and the budget. A non-zero exit
    fails, so that a failed read can never look like an empty result."""
    seconds = budget.left(step, cap)
    res = duthost.shell("timeout {} bash -c {}".format(seconds, shlex.quote("set -o pipefail; " + cmd)),
                        module_ignore_errors=True)
    if res.get("rc", 1) != 0:
        pytest.fail("{}{} failed: rc={} (limit {}s) cmd={!r} stderr={!r}".format(
            MACHINERY, step, res.get("rc"), seconds, cmd[:300], res.get("stderr", "")[-500:]))
    return res


def _read(duthost, cmd, budget, step):
    return _run(duthost, cmd, budget, step).get("stdout_lines") or []


def _snapshot(duthost, env, budget, step):
    """ASIC_DB virtual routers, RIFs, neighbors and audited routes; an incoherent dump is retaken."""
    found = {}

    def _coherent():
        found["snap"] = parse_snapshot(_read(duthost, SNAPSHOT_CMD, budget, step), env["port_oid"])
        return found["snap"] is not None

    pytest_assert(wait_until(budget.left(step, 15), 1, 0, _coherent),
                  "{}ASIC_DB could not be read coherently ({})".format(MACHINERY, step))
    return found["snap"]


def _drain_counts(duthost, budget, step):
    lines = _read(duthost, DRAIN_COUNT_CMD, budget, step)
    return dict((vr, int(count)) for count, vr in (line.split() for line in lines))


def _port_oid(duthost, port, budget):
    oid = (_read(duthost, "sonic-db-cli COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP " + port, budget, "port OID")
           or [""])[0]
    pytest_assert(oid.startswith("oid:"), "No port OID for {} in COUNTERS_PORT_NAME_MAP".format(port))
    return oid


def _oper_up(duthost, port):
    return duthost.get_interfaces_status().get(port, {}).get("oper") == "up"


def _vlan_member(duthost, vlan, port, budget):
    """'<CONFIG_DB tagging_mode>/<STATE_DB state>': 'untagged/ok' once vlanmgrd applied it, '/' when gone."""
    cmd = ("c=$(sonic-db-cli CONFIG_DB HGET 'VLAN_MEMBER|Vlan{0}|{1}' tagging_mode) && "
           "s=$(sonic-db-cli STATE_DB HGET 'VLAN_MEMBER_TABLE|Vlan{0}|{1}' state) && echo \"$c/$s\"").format(vlan, port)
    return (_read(duthost, cmd, budget, "VLAN membership of " + port) or [""])[0]


def _leftovers(duthost, env, budget, step):
    """Everything of the test still on the DUT (empty when clean). Every read is checked."""
    port, snap = env["port"], _snapshot(duthost, env, budget, step)
    cmd = ("echo @@DB && sonic-db-cli CONFIG_DB KEYS 'VRF|{vrf}' && sonic-db-cli CONFIG_DB KEYS 'INTERFACE|{port}' && "
           "sonic-db-cli CONFIG_DB KEYS 'INTERFACE|{port}|*' && sonic-db-cli STATE_DB KEYS 'VRF_OBJECT_TABLE|{vrf}' && "
           "echo @@NEIGH && sonic-db-cli APPL_DB KEYS 'NEIGH_TABLE:{port}:*' && ip neigh show dev {port} && "
           "echo @@VRF && ip -o link show type vrf && echo @@FRR && docker exec bgp vtysh -c 'show running-config' | "
           "{{ grep -F ' {gw}' || [ $? -eq 1 ]; }} && echo @@DRAIN && ").format(vrf=VRF_OLD, port=port, gw=OLD_GW) \
        + DRAIN_COUNT_CMD
    found = sections(_read(duthost, cmd, budget, step))
    mine = (NEW_PEER, OLD_GW)
    left = {
        "port RIFs": snap["port_rifs"],
        "virtual routers": sorted(snap["vrs"]) if len(snap["vrs"]) > 1 else [],
        "audited routes": [r["dest"] for r in snap["routes"]],
        "CONFIG_DB/STATE_DB keys": found.get("DB", []),
        "neighbors": [ln for ln in found.get("NEIGH", []) if ln.split()[0] in mine or ln.rsplit(":", 1)[-1] in mine],
        "kernel VRF": [ln for ln in found.get("VRF", []) if " {}:".format(VRF_OLD) in ln],
        "FRR routes": [ln for ln in found.get("FRR", []) if ln.startswith("ip route") and OLD_GW in ln.split()],
        "drain routes in ASIC_DB (count, VR)": found.get("DRAIN", []),
    }
    return dict((what, items[:3] + (["..."] if len(items) > 3 else [])) for what, items in left.items() if items)


def _wait_clean(duthost, env, budget, step):
    """Poll _leftovers() until nothing of the test is left; returns what is left at the end."""
    state = {"left": {"unreadable": "see the errors logged for " + step}}

    def _clean():
        state["left"] = _leftovers(duthost, env, budget, step)
        return not state["left"]

    wait_until(budget.left(step, 180), 3, 0, _clean)
    return state["left"]


def _select_port(duthost):
    """A front-panel port the test may take over: oper-up, routed, not a LAG member, mux port or
    L3/sub-interface port, and in no VLAN or the untagged member of one VLAN (borrowed and
    restored in teardown). Unused ports are preferred."""
    cfg = json.loads(duthost.shell("sonic-cfggen -d --print-data")["stdout"])
    taken = set(cfg.get("MUX_CABLE", {}))
    taken.update(k.split("|")[1] for k in cfg.get("PORTCHANNEL_MEMBER", {}))
    taken.update(k.split("|")[0].split(".")[0] for t in ("INTERFACE", "VLAN_SUB_INTERFACE") for k in cfg.get(t, {}))
    vlans = {}
    for key, attrs in cfg.get("VLAN_MEMBER", {}).items():
        vlan, member = key.split("|")
        vlans.setdefault(member, []).append((vlan[len("Vlan"):], attrs.get("tagging_mode")))
    status = duthost.get_interfaces_status()
    usable = [p for p, attrs in cfg.get("PORT", {}).items()
              if p not in taken and attrs.get("role", "Ext") == "Ext" and attrs.get("mode") not in ("access", "trunk")
              and status.get(p, {}).get("oper") == "up"
              and [mode for _vlan, mode in vlans.get(p, [])] in ([], ["untagged"])]
    if not usable:
        pytest.skip("No oper-up front-panel port that is unused or the untagged member of one VLAN "
                    "(LAG members, mux ports and L3 ports excluded)")
    port = sorted(natsorted(usable), key=lambda p: len(vlans.get(p, [])))[0]
    return port, (vlans[port][0][0] if port in vlans else None)


@pytest.fixture(scope="module")
def reuse_duthost(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    # NOT named `duthost`: a module-scoped shadow of the session-scoped `duthost`
    # fixture makes session autouse fixtures fail with ScopeMismatch.
    return duthosts[enum_rand_one_per_hwsku_frontend_hostname]


@pytest.fixture
def reuse_env(reuse_duthost, loganalyzer):
    """Select the port and check the baseline from read-only state, then free the port.
    Function scope, after the loganalyzer start marker: setup and cleanup are analyzed too."""
    duthost = reuse_duthost
    if duthost.shell("docker exec bgp vtysh -c 'show version'", module_ignore_errors=True)["rc"] != 0:
        pytest.skip("vtysh in the bgp container is required")
    port, vlan = _select_port(duthost)
    budget = Budget(ITERATION_BUDGET, "setup")
    env = {"port": port, "port_oid": _port_oid(duthost, port, budget)}
    vrs = _snapshot(duthost, env, budget, "baseline")["vrs"]
    if len(vrs) != 1:
        pytest.skip("The test needs a DUT without VRFs; virtual routers found: {}".format(sorted(vrs)))
    env["default_vr"] = vrs.pop()
    left = _leftovers(duthost, env, budget, "baseline")
    if left:
        pytest.skip("The DUT already has state this test creates: {}".format(left))
    env["orch_pid"] = _read(duthost, "pgrep -x orchagent", budget, "orchagent PID")[0]
    if loganalyzer:
        # RIF removal retries on this port while the references of the deleted VRF's RIF drain.
        loganalyzer[duthost.hostname].ignore_regex.append(
            r".*removeRouterIntfs: Router interface {} is still referenced with ref count \d+.*".format(
                re.escape(port)))
    try:
        if vlan:
            # Registered before the delete: a change applied without a reply is restored too.
            env["restore_vlan"] = (vlan, port)
            logger.warning("Temporarily removing %s from Vlan%s (restored in teardown)", port, vlan)
            _run(duthost, "config vlan member del {} {}".format(vlan, port), budget, "freeing the VLAN member")
            pytest_assert(wait_until(budget.left("freeing the VLAN member", SETTLE_TIMEOUT), 2, 0, lambda: (
                _vlan_member(duthost, vlan, port, budget) == "/" and _oper_up(duthost, port))),
                "{} did not leave Vlan{} (CONFIG_DB and STATE_DB) or is not oper-up".format(port, vlan))
        yield env
    finally:
        _teardown(duthost, env)


def _reset(duthost, env, budget):
    """Targeted cleanup, routes first: removing the references that pin a RIF lets a wedged
    removal (the failure under test) complete. Commands with nothing to remove fail harmlessly;
    the result is judged by _leftovers(), which is returned (empty when clean)."""
    port = env["port"]
    cmds = ["docker exec bgp vtysh -f " + DRAIN_DEL_CONF]
    cmds += ["ip neigh del {} dev {}".format(ip, port) for ip in (NEW_PEER, OLD_GW)]
    cmds += ["config interface ip remove {} {}".format(port, addr) for addr in (NEW_ADDR, OLD_ADDR)]
    cmds += ["config interface vrf unbind " + port, "sonic-db-cli CONFIG_DB DEL 'INTERFACE|{}'".format(port),
             "config vrf del " + VRF_OLD]
    script = "; ".join("timeout {} {}".format(LOAD_TIMEOUT if "vtysh" in cmd else CMD_TIMEOUT, cmd) for cmd in cmds)
    _run(duthost, script + "; true", budget, "cleanup commands", cap=LOAD_TIMEOUT + 6 * CMD_TIMEOUT)
    return _wait_clean(duthost, env, budget, "cleanup check")


def _reset_or_fail(duthost, env):
    left = _reset(duthost, env, Budget(CLEANUP_BUDGET, "cleanup"))
    pytest_assert(not left, "{}cleanup did not restore the baseline: {}".format(MACHINERY, left))


def _attempt(errors, what, func, *args):
    """One teardown step; a failure is recorded and does not stop the remaining steps."""
    try:
        return func(*args)
    except (Exception, pytest.fail.Exception) as err:
        errors.append("{}: {!r}".format(what, err))


def _reload_and_check(duthost, env):
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
    budget = Budget(CLEANUP_BUDGET, "check after config_reload")
    env["port_oid"] = _port_oid(duthost, env["port"], budget)  # the reload recreates the ASIC objects
    left = _wait_clean(duthost, env, budget, "check after config_reload")
    pytest_assert(not left, "left after config_reload: {}".format(left))


def _restore_vlan(duthost, vlan, port):
    """Idempotent: add the member back unless CONFIG_DB has it, then wait until it is applied."""
    budget = Budget(CLEANUP_BUDGET, "VLAN member restore")
    if not _vlan_member(duthost, vlan, port, budget).startswith("untagged/"):
        _run(duthost, "config vlan member add -u {} {}".format(vlan, port), budget, "VLAN member restore")
    pytest_assert(wait_until(budget.left("VLAN member restore", 120), 3, 0, lambda: (
        _vlan_member(duthost, vlan, port, budget) == "untagged/ok" and _oper_up(duthost, port))),
        "{} is not back as an applied, oper-up untagged member of Vlan{}".format(port, vlan))


def _teardown(duthost, env):
    errors = []
    left = _attempt(errors, "targeted cleanup", _reset, duthost, env, Budget(CLEANUP_BUDGET, "cleanup"))
    if left or errors:
        logger.warning("Targeted cleanup left %s %s; falling back to config_reload", left, errors)
        errors = []
        _attempt(errors, "config_reload fallback", _reload_and_check, duthost, env)
    _attempt(errors, "removing the drain route files", _run, duthost,
             "rm -f {0} {1} && docker exec bgp rm -f {0} {1}".format(DRAIN_ADD_CONF, DRAIN_DEL_CONF),
             Budget(CMD_TIMEOUT, "cleanup"), "removing the drain route files")
    if env.get("restore_vlan"):
        _attempt(errors, "VLAN member restore", _restore_vlan, duthost, *env["restore_vlan"])
    _attempt(errors, "critical processes", wait_critical_processes, duthost)
    pytest_assert(not errors, "Cleanup left the DUT in a bad state: {}".format("; ".join(errors)))


def _prepare(duthost, env, budget):
    """Bind the port to VRF_OLD and address it, then load DRAIN_ROUTE_COUNT static routes through
    a gateway on it (staticd -> zebra -> fpmsyncd -> orchagent, the normal path)."""
    port = env["port"]
    for path, remove in ((DRAIN_ADD_CONF, False), (DRAIN_DEL_CONF, True)):
        duthost.copy(content=drain_route_lines(remove=remove), dest=path)
        # Written from inside the container: `docker cp` would land under the container's /tmp mount.
        _run(duthost, "docker exec -i bgp sh -c 'cat > {0}' < {0}".format(path), budget, "copying " + path)
    for cmd in ("config vrf add " + VRF_OLD, "config interface vrf bind {} {}".format(port, VRF_OLD),
                "config interface ip add {} {}".format(port, OLD_ADDR)):
        _run(duthost, cmd, budget, cmd)
    found = {}

    def _in_old_vrf():
        snap = _snapshot(duthost, env, budget, "setup")
        rif = snap["port_rifs"][0] if len(snap["port_rifs"]) == 1 else None
        found.update(rif=rif, vr=rif and snap["rifs"][rif]["vr"], vrs=snap["vrs"])
        before = {"vr": found["vr"], "routes": [OLD_SUBNET, OLD_HOST], "on_rif": [OLD_SUBNET]}
        found["violations"] = find_violations(snap, before)
        return rif and found["vr"] != env["default_vr"] and len(snap["vrs"]) == 2 and found["violations"] == ([], [])

    pytest_assert(wait_until(budget.left("setup", SETTLE_TIMEOUT), 2, 0, _in_old_vrf),
                  "{}{} did not come up in {}: {}".format(MACHINERY, port, VRF_OLD, found))
    # After the port is in the VRF: enslaving it to the VRF device flushes its kernel neighbors.
    _run(duthost, "ip neigh replace {} lladdr {} dev {} nud permanent".format(OLD_GW, OLD_GW_MAC, port), budget,
         "gateway neighbor")
    _run(duthost, "docker exec bgp vtysh -f " + DRAIN_ADD_CONF, budget, "loading the drain routes", cap=LOAD_TIMEOUT)
    counts = {}

    def _programmed():
        counts.update(_drain_counts(duthost, budget, "drain routes"))
        return counts.get(found["vr"], 0) >= DRAIN_ROUTE_COUNT

    pytest_assert(wait_until(budget.left("drain routes", LOAD_TIMEOUT), 5, 0, _programmed),
                  "{}only {}/{} static routes of {} reached ASIC_DB".format(
                      MACHINERY, counts.get(found["vr"], 0), DRAIN_ROUTE_COUNT, VRF_OLD))
    return {"vr": env["default_vr"], "old_vr": found["vr"], "old_rif": found["rif"], "neighbor": NEW_PEER,
            "routes": [NEW_SUBNET, NEW_HOST], "on_rif": [NEW_SUBNET], "absent": [OLD_SUBNET, OLD_HOST]}


def _label(state):
    kinds = set(v["kind"] for v in state.get("hard", []) + state.get("gaps", []))
    if "neighbor_on_rif_of_other_vr" in kinds:
        return RACE + "the new subnet's neighbor was bound to the RIF of the deleted VRF"
    if "route_on_rif_of_other_vr" in kinds:
        return RACE + "a route was programmed through a RIF of another virtual router"
    if kinds & {"old_rif_still_present", "old_vr_still_present"}:
        return RACE + "the RIF or virtual router of the deleted VRF stayed in ASIC_DB"
    if "snap" not in state:
        return MACHINERY + "ASIC_DB could not be read after the reuse"
    return "The reused port did not converge; missing: {}".format(sorted(kinds))


def _fail(duthost, env, state, expected, start):
    """Fail with the ASIC_DB observation first; excerpts of the current recorder files are best effort."""
    excerpts, port = [], env["port"]
    swss = r"\|(VRF_TABLE:{}|INTF_TABLE:{}|NEIGH_TABLE:{}:{})\|".format(VRF_OLD, port, port, re.escape(NEW_PEER))
    for rec_file, pattern in ((SWSS_REC, swss), (SAIREDIS_REC, re.escape(expected["old_rif"]))):
        try:
            res = duthost.shell("timeout {} awk -F'|' -v s='{}' '$1 >= s' {} | grep -aE '{}' | tail -n 12".format(
                CMD_TIMEOUT, start, rec_file, pattern), module_ignore_errors=True)
            excerpts.append("{} since the delete:\n{}".format(rec_file, res.get("stdout", "")))
        except Exception as err:
            excerpts.append("{} unavailable: {!r}".format(rec_file, err))
    snap = state.get("snap")
    pytest.fail("{}\nviolations: {}\nconvergence gaps: {}\nport RIF -> VR: {}\nexpected: {}\n{}".format(
        _label(state), state.get("hard"), state.get("gaps"),
        snap and dict((rif, snap["rifs"][rif]["vr"]) for rif in snap["port_rifs"]),
        dict((k, expected[k]) for k in ("vr", "old_vr", "old_rif")), "\n".join(excerpts)))


def _reuse_iteration(duthost, env):
    """Delete VRF_OLD, then re-address the port and add a neighbor on the new subnet in the same
    shell on the DUT, so nothing but the CLI separates them. The port must then converge."""
    port, budget = env["port"], Budget(ITERATION_BUDGET, "iteration")
    expected = _prepare(duthost, env, budget)
    start = _read(duthost, "date '+%Y-%m-%d.%H:%M:%S.%6N' && config vrf del {} && config interface ip add {} {} && "
                  "ip neigh replace {} lladdr {} dev {} nud permanent".format(
                      VRF_OLD, port, NEW_ADDR, NEW_PEER, NEW_PEER_MAC, port), budget, "VRF delete and reuse")[0]
    state = {}

    def _settled():
        state["snap"] = _snapshot(duthost, env, budget, "convergence")
        state["hard"], state["gaps"] = find_violations(state["snap"], expected)
        return bool(state["hard"]) or not state["gaps"]

    settled = wait_until(budget.left("convergence", SETTLE_TIMEOUT), 2, 0, _settled)
    if state.get("hard") or not settled:
        _fail(duthost, env, state, expected, start)
    pid = (_read(duthost, "pgrep -x orchagent || true", budget, "orchagent PID") or [""])[0]
    pytest_assert(pid == env["orch_pid"], "orchagent restarted during the iteration ({} -> {})".format(
        env["orch_pid"], pid))


@pytest.mark.supported_completeness_level(CompletenessLevel.debug, CompletenessLevel.basic,
                                          CompletenessLevel.confident, CompletenessLevel.thorough)
def test_vrf_del_immediate_port_reuse_keeps_route_rif_vr_consistent(reuse_duthost, reuse_env, request):
    """Delete the VRF of a port during a slow route drain and reuse the port right away. In every
    iteration no route or neighbor may be bound to a RIF of another virtual router, and the port
    must converge to one RIF in the default virtual router."""
    iterations = ITERATIONS[CompletenessLevel.get_normalized_level(request)]
    for index in range(1, iterations + 1):
        _reuse_iteration(reuse_duthost, reuse_env)
        _reset_or_fail(reuse_duthost, reuse_env)
        logger.info("Iteration %d/%d converged", index, iterations)
