#!/usr/bin/env python3
"""
fencing-setup.py: preflight checks and manifest generation for Node Health Check (NHC) and
Fence Agents Remediation (FAR) on bare-metal workers fenced through their BMC over Redfish.

It does by itself what docs/preflight.md does by hand:

  1. reads the cluster: version, topology, operators, nodes, other health checks, VMs, memory
  2. reaches every BMC from every FAR replica (the network path fencing uses, proxy included)
  3. logs in to each BMC, matches each node's serial to its BMC, reads the power state, the
     Reset action and the account role
  4. creates the credential Secret if it does not exist (warns and uses it if it does)
  5. runs `fence_redfish --action status` from the FAR pod with the Secret's own values
  6. only when nothing failed: writes the FAR template, one drill CR per node and the
     NodeHealthCheck, and has the API validate them (server-side dry-run, strict)

It never applies a manifest and never powers anything on or off. The BMC password is typed
at a hidden prompt (or piped with --password-stdin) and only travels through stdin.

Requirements: Python 3.6+ (standard library only) and `oc`, logged in as cluster-admin.
Usage:        python3 fencing-setup.py -c fencing.conf
"""

import argparse
import base64
import collections
import concurrent.futures
import configparser
import datetime
import getpass
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

VERSION = "1.0"

NS = "openshift-workload-availability"
SECRET = "fence-agents-credentials-shared"
TEMPLATE = "fartemplate-redfish"
NHC_NAME = "nhc-workers-far"
FAR_DEPLOY = "fence-agents-remediation-controller-manager"
FAR_POD_SELECTOR = "app.kubernetes.io/name=fence-agents-remediation-operator"
WORKER_LABEL = "node-role.kubernetes.io/worker"
CONTROL_PLANE_LABELS = ("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")
OUT_OF_SERVICE_TAINT = "node.kubernetes.io/out-of-service"
FAR_TAINT = "remediation.medik8s.io/fence-agents-remediation"
NODEPOOL_LABEL = "hypershift.openshift.io/nodePool"
MIN_OPENSHIFT = (4, 15)
MIN_FAR_FOR_OFF = (0, 6, 0)
DEFAULT_SYSTEMS_URI = "/redfish/v1/Systems/System.Embedded.1"

# What firmware writes into DMI fields the vendor left blank. Never an identity: many boards
# share them. A value that two nodes share is treated the same way.
PLACEHOLDER_SERIALS = {
    "", "0", "none", "null", "n/a", "na", "unknown", "invalid", "not specified", "not applicable",
    "default string", "to be filled by o.e.m.", "system serial number", "chassis serial number",
    "serial number", "0123456789", "123456789", "1234567890",
}
PLACEHOLDER_UUIDS = {
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
}

DNS_SUBDOMAIN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
HOSTNAME = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?(\.[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?)*$")
SYSTEMS_URI = re.compile(r"^/redfish/v1/Systems/[A-Za-z0-9._-]+$")
DURATION = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
THRESHOLD = re.compile(r"^(\d+)(%?)$")


# Runs inside the FAR manager container, with the same Python, `requests` and environment
# (proxy variables included) that fence_redfish uses there. Input is one JSON document on
# stdin, which is also the only place the password travels; output is one JSON line.
PROBE = r'''
import json, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
import requests, urllib3
urllib3.disable_warnings()

HEADERS = {"accept": "application/json", "OData-Version": "4.0"}
cfg = json.load(sys.stdin)
verify = not cfg.get("ssl_insecure", True)
creds = (cfg["username"], cfg["password"]) if cfg.get("password") else None

def describe(e, timeout):
    text = str(e)
    if isinstance(e, requests.exceptions.ProxyError):
        return "proxy error: " + text[-200:]
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return "no TCP connection within %d s" % timeout[0]
    if isinstance(e, requests.exceptions.ReadTimeout):
        return "connected, but no reply within %d s" % timeout[1]
    if isinstance(e, requests.exceptions.SSLError):
        return "TLS error (with ssl_insecure = false the BMC certificate must be trusted): " + text[-160:]
    for needle, short in (("Connection refused", "connection refused"), ("No route to host", "no route to host"),
                          ("Name or service not known", "the name does not resolve"),
                          ("Network is unreachable", "network unreachable")):
        if needle in text:
            return short
    return ("%s: %s" % (type(e).__name__, text))[:240]

def get(ip, path, auth=True, timeout=(5, 25)):
    t0 = time.time()
    try:
        r = requests.get("https://%s%s" % (ip, path), headers=HEADERS, verify=verify,
                         auth=creds if auth else None, timeout=timeout)
    except Exception as e:
        return {"status": 0, "error": describe(e, timeout), "secs": round(time.time() - t0, 1)}
    out = {"status": r.status_code, "secs": round(time.time() - t0, 1)}
    try:
        out["json"] = r.json()
    except ValueError:
        out["json"] = None
    return out

def link(doc, key):
    v = (doc or {}).get(key) if isinstance(doc, dict) else None
    return v.get("@odata.id") if isinstance(v, dict) else None

def reach(t):
    url = "https://%s/redfish/v1/" % t["ip"]
    proxy = requests.utils.select_proxy(url, requests.utils.get_environ_proxies(url))
    r = get(t["ip"], "/redfish/v1/", auth=False, timeout=(5, 15))
    return {"node": t["node"], "ip": t["ip"], "proxy": proxy, "status": r["status"],
            "error": r.get("error"), "secs": r["secs"]}

def account(ip):
    root = get(ip, "/redfish/v1/")
    svc_path = link(root.get("json"), "AccountService") or "/redfish/v1/AccountService"
    svc = get(ip, svc_path)
    if svc["status"] == 401:
        return {"unauthorized": True}
    if svc["status"] != 200:
        return {"error": "HTTP %s on %s" % (svc["status"], svc_path)}
    accounts_path, roles_path = link(svc["json"], "Accounts"), link(svc["json"], "Roles")
    col = get(ip, accounts_path or svc_path + "/Accounts")
    if col["status"] != 200 or not isinstance(col.get("json"), dict):
        return {"error": "HTTP %s listing accounts" % col["status"]}
    for m in (col["json"].get("Members") or [])[:64]:
        a = get(ip, m.get("@odata.id", ""))
        if a["status"] == 401:
            return {"unauthorized": True}
        j = a.get("json")
        if a["status"] != 200 or not isinstance(j, dict) or j.get("UserName") != cfg["username"]:
            continue
        out = {"found": True, "RoleId": j.get("RoleId"), "Enabled": j.get("Enabled"), "Locked": j.get("Locked")}
        role_path = link(j.get("Links"), "Role")
        if not role_path and roles_path and j.get("RoleId"):
            role_path = roles_path.rstrip("/") + "/" + j["RoleId"]
        if role_path:
            rr = get(ip, role_path)
            if rr["status"] == 200 and isinstance(rr.get("json"), dict):
                out["privileges"] = rr["json"].get("AssignedPrivileges")
        return out
    return {"found": False}

def auth(t):
    ip = t["ip"]
    out = {"node": t["node"], "ip": ip}
    r = get(ip, cfg["systems_uri"])
    out["status"], out["error"] = r["status"], r.get("error")
    if r["status"] == 401:
        out["unauthorized"] = True
        return out
    if r["status"] != 200 or not isinstance(r.get("json"), dict):
        if r["status"] == 404:
            c = get(ip, "/redfish/v1/Systems")
            if c["status"] == 200 and isinstance(c.get("json"), dict):
                out["systems"] = [m.get("@odata.id") for m in c["json"].get("Members") or []]
        return out
    s = r["json"]
    reset = (s.get("Actions") or {}).get("#ComputerSystem.Reset") or {}
    for k in ("SKU", "SerialNumber", "UUID", "PowerState", "Manufacturer", "Model", "HostName"):
        out[k] = s.get(k)
    out["reset_target"] = reset.get("target")
    out["reset_types"] = reset.get("ResetType@Redfish.AllowableValues")
    out["account"] = account(ip)
    return out

def agent(t):
    opts = "ip=%s\nusername=%s\npassword=%s\nsystems_uri=%s\naction=status\n" % (
        t["ip"], cfg["username"], cfg["password"], cfg["systems_uri"])
    if not verify:
        opts += "ssl_insecure=1\n"
    try:
        p = subprocess.run(["fence_redfish"], input=opts, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True, timeout=90)
        return {"node": t["node"], "ip": t["ip"], "rc": p.returncode, "out": p.stdout.strip()[-400:]}
    except subprocess.TimeoutExpired:
        return {"node": t["node"], "ip": t["ip"], "rc": None, "out": "no answer in 90 s"}

def refused(r):
    return bool(r.get("unauthorized") or (r.get("account") or {}).get("unauthorized"))

targets = cfg["targets"]
mode = cfg["mode"]
if mode == "reach":
    with ThreadPoolExecutor(max_workers=min(8, len(targets) or 1)) as ex:
        results = list(ex.map(reach, targets))
elif mode == "auth":
    # The first BMC alone: a wrong password then costs one failed login, not one per BMC.
    results = [auth(targets[0])] if targets else []
    if results and refused(results[0]):
        results += [{"node": t["node"], "ip": t["ip"], "skipped": True} for t in targets[1:]]
    elif len(targets) > 1:
        with ThreadPoolExecutor(max_workers=min(8, len(targets) - 1)) as ex:
            results += list(ex.map(auth, targets[1:]))
elif mode == "agent":
    with ThreadPoolExecutor(max_workers=min(4, len(targets) or 1)) as ex:
        results = list(ex.map(agent, targets))
else:
    results = []
print(json.dumps({"results": results}))
'''


class ConfigError(Exception):
    pass


class Report:
    COLORS = {"PASS": "32", "WARN": "33", "FAIL": "31", "INFO": "36"}

    def __init__(self):
        self.rows = []
        self.lines = []
        self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def say(self, text=""):
        self.lines.append(text)
        print(text, flush=True)

    def add(self, status, area, message):
        self.rows.append(status)
        parts = message.split("\n")
        body = parts[0] + "".join("\n" + " " * 18 + p for p in parts[1:])
        plain = "[%s] %-10s %s" % (status, area, body)
        self.lines.append(plain)
        if self.color:
            tag = "\033[%sm[%s]\033[0m" % (self.COLORS[status], status)
            print("%s %-10s %s" % (tag, area, body), flush=True)
        else:
            print(plain, flush=True)

    def count(self, status):
        return self.rows.count(status)


class Oc:
    def __init__(self, context=None, kubeconfig=None):
        self.base = ["oc"]
        if kubeconfig:
            self.base += ["--kubeconfig", kubeconfig]
        if context:
            self.base += ["--context", context]

    def run(self, args, input=None, timeout=120):
        kw = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
        try:
            p = subprocess.run(self.base + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=timeout, **kw)
        except subprocess.TimeoutExpired:
            return 124, "", "timed out after %d s" % timeout
        except FileNotFoundError:
            raise SystemExit("ERROR: `oc` was not found in PATH")
        return p.returncode, p.stdout, p.stderr.strip()

    def get(self, args, timeout=120):
        rc, out, err = self.run(["get"] + args + ["-o", "json"], timeout=timeout)
        if rc != 0:
            return None, err or "exit code %d" % rc
        try:
            return json.loads(out), None
        except ValueError:
            return None, "unexpected output from oc get %s" % " ".join(args)


def missing_type(err):
    return any(s in (err or "") for s in ("doesn't have a resource type", "no matches for kind",
                                          "could not find the requested resource"))


def not_found(err):
    return "NotFound" in (err or "") or "not found" in (err or "")


def labels_of(node):
    return node["metadata"].get("labels") or {}


def is_ready(node):
    for c in node.get("status", {}).get("conditions") or []:
        if c.get("type") == "Ready":
            return c.get("status") == "True"
    return False


def plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def short_list(items, limit=8):
    items = list(items)
    text = ", ".join(items[:limit])
    return text + (" and %d more" % (len(items) - limit) if len(items) > limit else "")


def mask_url(url):
    return re.sub(r"//[^@/]*@", "//***@", url or "")


def b64(text):
    return base64.b64decode(text or "").decode("utf-8", "replace")


def norm(value):
    return (value or "").strip().lower()


def csv_version(csv):
    m = re.search(r"\.v(\d+)\.(\d+)\.(\d+)", csv or "")
    return tuple(int(x) for x in m.groups()) if m else None


def placeholder_serial(serial):
    s = norm(serial)
    return s in PLACEHOLDER_SERIALS or len(set(s)) == 1


# ---------------------------------------------------------------------------------- config

class Config:
    def __init__(self):
        self.path = None
        self.username = None
        self.systems_uri = DEFAULT_SYSTEMS_URI
        self.ssl_insecure = True
        self.duration = "300s"
        self.duration_secs = 300
        self.threshold = ("min_healthy", 51, True)
        self.nodes = collections.OrderedDict()
        self.by_name = []
        self.hosted_cluster = None


def parse_duration(value):
    m = DURATION.match(value)
    if not value or not m:
        raise ConfigError("duration %r: use a whole number of seconds, minutes or hours, like 300s or 5m" % value)
    h, mi, s = (int(x or 0) for x in m.groups())
    secs = h * 3600 + mi * 60 + s
    if secs <= 0:
        raise ConfigError("duration %r must be greater than zero" % value)
    return secs


def load_config(path):
    cp = configparser.ConfigParser(delimiters=("=",), inline_comment_prefixes=("#", ";"),
                                   interpolation=None)
    cp.optionxform = str
    try:
        with open(path) as f:
            cp.read_file(f)
    except (OSError, configparser.Error) as e:
        raise ConfigError(str(e))
    allowed = {"bmc": {"username", "systems_uri", "ssl_insecure"},
               "nhc": {"duration", "min_healthy", "max_unhealthy"},
               "hosted": {"hosted_cluster"},
               "nodes": None}
    for section in cp.sections():
        if section not in allowed:
            raise ConfigError("unknown section [%s]" % section)
        for key in cp[section] if allowed[section] is not None else ():
            if key not in allowed[section]:
                raise ConfigError("unknown key %r in [%s]" % (key, section))
    for section in ("bmc", "nodes"):
        if not cp.has_section(section):
            raise ConfigError("missing section [%s]" % section)

    c = Config()
    c.path = path
    c.username = cp.get("bmc", "username", fallback="").strip()
    if not c.username:
        raise ConfigError("[bmc] username is required (the BMC account FAR logs in with)")
    c.systems_uri = cp.get("bmc", "systems_uri", fallback=DEFAULT_SYSTEMS_URI).strip()
    if not SYSTEMS_URI.match(c.systems_uri):
        raise ConfigError("[bmc] systems_uri %r: expected /redfish/v1/Systems/<id>" % c.systems_uri)
    try:
        c.ssl_insecure = cp.getboolean("bmc", "ssl_insecure", fallback=True)
    except ValueError:
        raise ConfigError("[bmc] ssl_insecure must be true or false")

    if cp.has_section("nhc"):
        c.duration = cp.get("nhc", "duration", fallback="300s").strip()
        mn = cp.get("nhc", "min_healthy", fallback="").strip()
        mx = cp.get("nhc", "max_unhealthy", fallback="").strip()
        if mn and mx:
            raise ConfigError("[nhc] min_healthy and max_unhealthy are mutually exclusive; keep one")
        key, value = ("max_unhealthy", mx) if mx else ("min_healthy", mn or "51%")
        m = THRESHOLD.match(value)
        if not m:
            raise ConfigError("[nhc] %s %r: use a whole number or a percentage, like 2 or 51%%" % (key, value))
        n, pct = int(m.group(1)), bool(m.group(2))
        if pct and not 0 < n <= 100:
            raise ConfigError("[nhc] %s %r: a percentage must be between 1%% and 100%%" % (key, value))
        c.threshold = (key, n, pct)
    c.duration_secs = parse_duration(c.duration)

    seen = {}
    for node, bmc in cp.items("nodes"):
        bmc = bmc.strip()
        if not DNS_SUBDOMAIN.match(node) or len(node) > 253:
            raise ConfigError("[nodes] %r is not a valid node name (lowercase, as in `oc get nodes`)" % node)
        if not bmc:
            raise ConfigError("[nodes] %s has no BMC address" % node)
        try:
            addr = ipaddress.ip_address(bmc)
        except ValueError:
            addr = None
        if addr is not None and addr.version == 6:
            raise ConfigError("[nodes] %s: IPv6 BMC addresses are not handled by this script" % node)
        if addr is None:
            if not HOSTNAME.match(bmc):
                raise ConfigError("[nodes] %s: %r is neither an IPv4 address nor a host name" % (node, bmc))
            c.by_name.append(node)
        if bmc.lower() in seen:
            raise ConfigError("[nodes] %s and %s have the same BMC %s" % (seen[bmc.lower()], node, bmc))
        seen[bmc.lower()] = node
        c.nodes[node] = bmc
    if not c.nodes:
        raise ConfigError("[nodes] is empty: list every worker as  <node name> = <BMC IP>")

    if cp.has_section("hosted"):
        hc = cp.get("hosted", "hosted_cluster", fallback="").strip()
        if hc:
            ns, _, name = hc.partition("/")
            if not (DNS_LABEL.match(ns) and DNS_SUBDOMAIN.match(name)):
                raise ConfigError("[hosted] hosted_cluster %r: expected <namespace>/<name>" % hc)
            c.hosted_cluster = (ns, name)
    return c


def threshold_text(threshold):
    key, n, pct = threshold
    return "%s %s" % (key, "%d%%" % n if pct else n)


def allowed_unhealthy(threshold, total):
    """How many selected nodes NHC remediates at the same time, the way NHC computes it:
    percentages are scaled with round-up (intstr.GetScaledValueFromIntOrPercent)."""
    key, n, pct = threshold
    value = (n * total + 99) // 100 if pct else n
    if key == "min_healthy":
        return total - value, value
    return value, total - value


# ---------------------------------------------------------------------------------- checks

def check_cluster(oc, rep):
    facts = {"hosted": False, "single_node": False, "infra": "cluster", "version": "?"}
    cv, err = oc.get(["clusterversion", "version"])
    if cv is None:
        rep.add("FAIL", "cluster", "cannot read the ClusterVersion: %s" % err)
    else:
        status = cv.get("status") or {}
        version = (status.get("desired") or {}).get("version", "")
        facts["version"] = version
        m = re.match(r"(\d+)\.(\d+)", version)
        if not m:
            rep.add("WARN", "cluster", "cannot parse the OpenShift version %r" % version)
        elif (int(m.group(1)), int(m.group(2))) < MIN_OPENSHIFT:
            rep.add("FAIL", "cluster", "OpenShift %s: the out-of-service taint is GA from 4.15 on" % version)
        else:
            rep.add("PASS", "cluster", "OpenShift %s supports the out-of-service taint (4.15 and later)" % version)
        for c in status.get("conditions") or []:
            if c.get("type") == "Progressing" and c.get("status") == "True":
                rep.add("WARN", "cluster", "a cluster update is in progress: NHC postpones every remediation "
                        "until it ends. Do not run the drill now.")
    infra, err = oc.get(["infrastructure", "cluster"])
    if infra is None:
        rep.add("FAIL", "cluster", "cannot read the Infrastructure object: %s" % err)
        return facts
    st = infra.get("status") or {}
    facts["infra"] = st.get("infrastructureName") or "cluster"
    topology = st.get("controlPlaneTopology")
    if topology == "External":
        facts["hosted"] = True
        rep.add("INFO", "cluster", "hosted cluster: the control plane runs on a management cluster, so fencing "
                "a worker never touches etcd")
    elif topology == "SingleReplica":
        facts["single_node"] = True
        rep.add("FAIL", "cluster", "single-node OpenShift: no other node can take the VMs, and the fencing "
                "operators would die with the node they fence")
    else:
        rep.add("INFO", "cluster", "standard cluster (control plane topology %s)" % topology)
    return facts


def check_operators(oc, rep):
    subs, err = oc.get(["subscriptions.operators.coreos.com", "-n", NS])
    if subs is None:
        rep.add("FAIL", "operators", "cannot list Subscriptions in %s: %s" % (NS, err))
        return False
    by_pkg = {s["spec"].get("name"): s for s in subs.get("items", [])}
    csvs, _ = oc.get(["clusterserviceversions.operators.coreos.com", "-n", NS])
    phase = {c["metadata"]["name"]: (c.get("status") or {}).get("phase") for c in (csvs or {}).get("items", [])}
    far_ok = True
    for pkg in ("node-healthcheck-operator", "fence-agents-remediation"):
        s = by_pkg.get(pkg)
        if s is None:
            rep.add("FAIL", "operators", "%s is not installed in %s (no Subscription for it)" % (pkg, NS))
            far_ok = far_ok and pkg != "fence-agents-remediation"
            continue
        source = s["spec"].get("source")
        csv = (s.get("status") or {}).get("installedCSV")
        if source != "redhat-operators":
            rep.add("FAIL", "operators", "%s comes from %r, not redhat-operators. The community catalog ships "
                    "packages with the same names; this setup was validated with the Red Hat builds." % (pkg, source))
        elif phase.get(csv) != "Succeeded":
            rep.add("FAIL", "operators", "%s: CSV %s is %s, not Succeeded" % (pkg, csv, phase.get(csv)))
            far_ok = far_ok and pkg != "fence-agents-remediation"
        else:
            rep.add("PASS", "operators", "%s Succeeded, from redhat-operators" % csv)
        version = csv_version(csv)
        if pkg == "fence-agents-remediation" and version and version < MIN_FAR_FOR_OFF:
            rep.add("FAIL", "operators", "%s: --action off needs FAR 0.6.0 or later. This version accepts the "
                    "template and rejects the action only when it fences. Update the operator." % csv)
    groups, err = oc.get(["operatorgroups.operators.coreos.com", "-n", NS])
    n = len((groups or {}).get("items", []))
    if groups is None:
        rep.add("WARN", "operators", "cannot list OperatorGroups: %s" % err)
    elif n != 1:
        rep.add("FAIL", "operators", "%s in %s: OLM needs exactly one per namespace" % (plural(n, "OperatorGroup"), NS))
    snr = "self-node-remediation" in by_pkg or any(name.startswith("self-node-remediation") for name in phase)
    if snr:
        rep.add("WARN", "operators", "Self Node Remediation is installed. Its agent reboots a node it believes is "
                "isolated even when no NodeHealthCheck points at it. If you do not use it, uninstall it.")
    return far_ok


def check_nodes(conf, nodes, rep):
    selected = sorted(n for n, o in nodes.items() if WORKER_LABEL in labels_of(o))
    if not selected:
        rep.add("FAIL", "nodes", "no node has the %s label: the health check would select nothing" % WORKER_LABEL)
        return selected
    cp_workers = [n for n in selected if any(l in labels_of(nodes[n]) for l in CONTROL_PLANE_LABELS)]
    if cp_workers:
        rep.add("FAIL", "nodes", "%s %s the worker label and a control-plane or master label. NHC treats any "
                "node with either label as control plane and guards etcd quorum on it, so it would skip "
                "remediation there. The generated health check is for dedicated workers."
                % (short_list(cp_workers), "carries" if len(cp_workers) == 1 else "carry"))
    unknown = [n for n in conf.nodes if n not in nodes]
    if unknown:
        rep.add("FAIL", "nodes", "not in the cluster (the name must match `oc get nodes` exactly): %s" % short_list(unknown))
    missing = [n for n in selected if n not in conf.nodes]
    if missing:
        rep.add("FAIL", "nodes", "the config has no BMC for %s, which the health check would watch: a real "
                "failure there could not be fenced. Add every worker to [nodes]." % short_list(missing))
    extra = [n for n in conf.nodes if n in nodes and n not in selected]
    if extra:
        rep.add("WARN", "nodes", "in the config but without the worker label, so the health check never fences "
                "them: %s" % short_list(extra))
    if not unknown and not missing:
        rep.add("PASS", "nodes", "%s selected by the health check (label %s), all in the config"
                % (plural(len(selected), "worker"), WORKER_LABEL))
    not_ready = [n for n in conf.nodes if n in nodes and not is_ready(nodes[n])]
    if not_ready:
        rep.add("WARN", "nodes", "not Ready now: %s. Once the health check is armed, a node NotReady for the "
                "duration is powered off." % short_list(not_ready))
    for n in sorted(nodes):
        keys = {t.get("key") for t in nodes[n].get("spec", {}).get("taints") or []}
        for taint in (OUT_OF_SERVICE_TAINT, FAR_TAINT):
            if taint in keys:
                rep.add("WARN", "nodes", "%s has the %s taint: a fence or a drill was not cleaned up (FAR removes "
                        "it when its CR is deleted, after the node is Ready)" % (n, taint))
    return selected


def check_threshold(conf, selected, rep):
    total = len(selected)
    if not total:
        return
    key, n, pct = conf.threshold
    allowed, _ = allowed_unhealthy(conf.threshold, total)
    text = threshold_text(conf.threshold)
    if key == "max_unhealthy" and not pct and n > total:
        rep.add("FAIL", "nhc", "max_unhealthy %d is greater than the %s selected: NHC treats that as an error and "
                "remediates nothing" % (n, plural(total, "worker")))
    elif allowed < 1:
        rep.add("FAIL", "nhc", "with %s, %s lets NHC fence %d nodes at a time: it would never remediate. "
                "Use max_unhealthy = 1." % (plural(total, "worker"), text, max(0, allowed)))
    elif allowed > 2:
        rep.add("WARN", "nhc", "with %s, %s lets NHC fence up to %d nodes at once. A switch or power failure "
                "takes several nodes down together; consider max_unhealthy = 1 or 2 in [nhc]."
                % (plural(total, "worker"), text, allowed))
    else:
        rep.add("PASS", "nhc", "with %s, %s lets NHC fence at most %d at a time" % (plural(total, "worker"), text, allowed))
    if conf.duration_secs < 300:
        rep.add("WARN", "nhc", "duration %s is below the NHC default of 300s: a slow reboot or a short network "
                "blip then powers a node off. Go lower only with data." % conf.duration)
    else:
        rep.add("INFO", "nhc", "duration %s: a worker NotReady for that long gets fenced" % conf.duration)


def selector_matches(selector, node_labels):
    if not selector:
        return True
    for k, v in (selector.get("matchLabels") or {}).items():
        if node_labels.get(k) != v:
            return False
    for e in selector.get("matchExpressions") or []:
        k, op, values = e.get("key"), e.get("operator"), e.get("values") or []
        if op == "In" and node_labels.get(k) not in values:
            return False
        if op == "NotIn" and k in node_labels and node_labels[k] in values:
            return False
        if op == "Exists" and k not in node_labels:
            return False
        if op == "DoesNotExist" and k in node_labels:
            return False
    return True


def check_conflicts(oc, conf, nodes, selected, rep):
    """Returns the state of the NodeHealthCheck this script generates: None (absent), 'armed' or 'paused'."""
    ours = None
    nhcs, err = oc.get(["nodehealthchecks.remediation.medik8s.io"])
    if nhcs is None:
        rep.add("WARN", "conflicts", "cannot list NodeHealthChecks: %s" % err)
    for nhc in (nhcs or {}).get("items", []):
        name, spec = nhc["metadata"]["name"], nhc.get("spec") or {}
        if name == NHC_NAME:
            ours = "paused" if spec.get("pauseRequests") else "armed"
            if spec.get("pauseRequests"):
                rep.add("WARN", "conflicts", "NodeHealthCheck %s is paused (pauseRequests: %s): nothing is fenced "
                        "automatically until it is resumed (README)" % (name, ", ".join(spec["pauseRequests"])))
        overlap = [n for n in selected if selector_matches(spec.get("selector"), labels_of(nodes[n]))]
        if not overlap:
            continue
        tmpl = spec.get("remediationTemplate") or {}
        what = "%s %s" % (tmpl.get("kind"), tmpl.get("name")) if tmpl else "escalating remediations"
        if name == NHC_NAME:
            rep.add("INFO", "conflicts", "NodeHealthCheck %s already exists and is %s (remediation: %s); applying "
                    "the generated 04 updates it" % (name, ours.upper(), what))
        else:
            rep.add("FAIL", "conflicts", "NodeHealthCheck %s already covers %s (remediation: %s). Two health "
                    "checks on one node means two remediations. Delete it or narrow its selector."
                    % (name, short_list(overlap), what))
    mhcs, _ = oc.get(["machinehealthchecks.machine.openshift.io", "-n", "openshift-machine-api"])
    if (mhcs or {}).get("items"):
        machines, err = oc.get(["machines.machine.openshift.io", "-n", "openshift-machine-api"])
        machine_labels = {}
        for m in (machines or {}).get("items", []):
            ref = ((m.get("status") or {}).get("nodeRef") or {}).get("name")
            if ref in selected:
                machine_labels[ref] = m["metadata"].get("labels") or {}
        for mhc in mhcs["items"]:
            name = mhc["metadata"]["name"]
            if machines is None:
                rep.add("WARN", "conflicts", "MachineHealthCheck %s exists and the Machines cannot be listed (%s): "
                        "make sure it does not cover these workers" % (name, err))
                continue
            selector = (mhc.get("spec") or {}).get("selector")
            covered = sorted(n for n, ml in machine_labels.items() if selector_matches(selector, ml))
            if covered:
                rep.add("FAIL", "conflicts", "MachineHealthCheck %s covers the Machines of %s: a second remediator "
                        "acting on the node FAR powers off. Narrow its selector or delete it."
                        % (name, short_list(covered)))
    bmhs, err = oc.get(["baremetalhosts.metal3.io", "-A"])
    check_bmh(bmhs, err, conf, rep, where="this cluster")
    fars, err = oc.get(["fenceagentsremediations.fence-agents-remediation.medik8s.io", "-n", NS])
    for far in (fars or {}).get("items", []):
        rep.add("WARN", "conflicts", "FenceAgentsRemediation %s exists: a fence is running or a drill CR was not "
                "deleted (the node keeps the out-of-service taint until it is)" % far["metadata"]["name"])
    return ours


def check_bmh(bmhs, err, conf, rep, where):
    if bmhs is None:
        if not missing_type(err):
            rep.add("INFO", "conflicts", "cannot list BareMetalHosts on %s (%s): check by hand that none "
                    "holds these BMCs (docs/preflight.md section 2)" % (where, err))
        return
    hits = []
    for bmh in bmhs.get("items", []):
        address = ((bmh.get("spec") or {}).get("bmc") or {}).get("address", "")
        for node, ip in conf.nodes.items():
            if re.search(r"(^|[/@\[:])%s([\]:/]|$)" % re.escape(ip), address):
                hits.append("%s/%s (BMC %s, node %s)" % (bmh["metadata"]["namespace"], bmh["metadata"]["name"], ip, node))
    if hits:
        rep.add("WARN", "conflicts", "BareMetalHosts on %s hold these BMCs: %s. The Bare Metal Operator then also "
                "has power control and a desired power state (spec.online). Settle who owns the power button."
                % (where, short_list(hits)))


def check_vms(oc, rep):
    vms, err = oc.get(["virtualmachines.kubevirt.io", "-A"], timeout=180)
    if vms is None:
        if missing_type(err):
            rep.add("INFO", "vms", "OpenShift Virtualization is not installed: no VM checks")
        else:
            rep.add("WARN", "vms", "cannot list VirtualMachines: %s" % err)
        return
    counts, stay_down, legacy = collections.Counter(), [], 0
    for vm in vms.get("items", []):
        spec = vm.get("spec") or {}
        strategy = spec.get("runStrategy")
        if not strategy and "running" in spec:
            legacy += 1
            strategy = "Always" if spec["running"] else "Halted"
        strategy = strategy or "unset"
        counts[strategy] += 1
        running = (vm.get("status") or {}).get("printableStatus") == "Running"
        if running and strategy in ("Manual", "Once"):
            stay_down.append("%s/%s (%s)" % (vm["metadata"]["namespace"], vm["metadata"]["name"], strategy))
    if not counts:
        rep.add("INFO", "vms", "no VirtualMachines yet")
        return
    rep.add("INFO", "vms", "VMs by runStrategy: %s" % ", ".join("%s %d" % kv for kv in counts.most_common()))
    if stay_down:
        rep.add("WARN", "vms", "%s would stay down after a fence: %s. Use RerunOnFailure."
                % (plural(len(stay_down), "running VM"), short_list(stay_down)))
    if legacy:
        rep.add("INFO", "vms", "%s use the legacy spec.running field (true behaves like Always)" % plural(legacy, "VM"))


UNITS = {"Ki": 2 ** 10, "Mi": 2 ** 20, "Gi": 2 ** 30, "Ti": 2 ** 40, "Pi": 2 ** 50, "Ei": 2 ** 60,
         "k": 10 ** 3, "M": 10 ** 6, "G": 10 ** 9, "T": 10 ** 12, "P": 10 ** 15, "E": 10 ** 18}


def quantity(text):
    m = re.match(r"^([0-9.]+)(?:[eE]([+-]?\d+))?(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E|m)?$", (text or "0").strip())
    if not m:
        return 0
    value = float(m.group(1)) * (10 ** int(m.group(2)) if m.group(2) else 1)
    unit = m.group(3)
    return int(value / 1000) if unit == "m" else int(value * UNITS.get(unit, 1))


def gib(n):
    return "%.1f GiB" % (n / 2 ** 30)


def check_capacity(oc, nodes, selected, rep):
    if len(selected) < 2:
        return
    pods, err = oc.get(["pods", "-A", "--field-selector=status.phase!=Succeeded,status.phase!=Failed"], timeout=300)
    if pods is None:
        rep.add("WARN", "capacity", "cannot list pods for the memory check: %s" % err)
        return
    requested, movable = collections.Counter(), collections.Counter()
    for p in pods.get("items", []):
        node = (p.get("spec") or {}).get("nodeName")
        if node not in nodes:
            continue
        spec = p["spec"]
        mem = sum(quantity(((c.get("resources") or {}).get("requests") or {}).get("memory")) for c in spec.get("containers") or [])
        init = [quantity(((c.get("resources") or {}).get("requests") or {}).get("memory")) for c in spec.get("initContainers") or []]
        mem = max([mem] + init) + quantity((spec.get("overhead") or {}).get("memory"))
        requested[node] += mem
        meta = p["metadata"]
        stays = "kubernetes.io/config.mirror" in (meta.get("annotations") or {}) or any(
            o.get("kind") == "DaemonSet" for o in meta.get("ownerReferences") or [])
        if not stays:
            movable[node] += mem
    allocatable = {n: quantity((nodes[n].get("status") or {}).get("allocatable", {}).get("memory")) for n in selected}
    busiest = max(selected, key=lambda n: movable[n])
    free = sum(max(0, allocatable[n] - requested[n]) for n in selected if n != busiest)
    note = "(memory requests, counted in aggregate; not a scheduling simulation)"
    if movable[busiest] > free:
        rep.add("WARN", "capacity", "losing %s means rescheduling %s, and the other workers have %s free: some "
                "VMs would stay Pending %s" % (busiest, gib(movable[busiest]), gib(free), note))
    else:
        rep.add("PASS", "capacity", "losing the busiest worker (%s) means rescheduling %s; the others have %s free %s"
                % (busiest, gib(movable[busiest]), gib(free), note))


def far_runtime(oc, facts, selected, rep):
    pods, err = oc.get(["pods", "-n", NS, "-l", FAR_POD_SELECTOR])
    if pods is None:
        rep.add("FAIL", "far", "cannot list the FAR pods: %s" % err)
        return [], None
    ready = []
    for p in pods.get("items", []):
        statuses = (p.get("status") or {}).get("containerStatuses") or []
        if p.get("status", {}).get("phase") == "Running" and statuses and all(s.get("ready") for s in statuses):
            ready.append((p["metadata"]["name"], p["spec"].get("nodeName")))
    leader = None
    leases, _ = oc.get(["leases.coordination.k8s.io", "-n", NS])
    for lease in (leases or {}).get("items", []):
        holder = (lease.get("spec") or {}).get("holderIdentity") or ""
        if holder.startswith(FAR_DEPLOY + "-"):
            leader = holder.split("_")[0]
    if not ready:
        rep.add("FAIL", "far", "no FAR pod is Running and ready in %s: nothing can run the fence agent" % NS)
        return ready, leader
    where = dict(ready)
    text = ", ".join("%s on %s" % (pod, node) for pod, node in ready)
    rep.add("INFO", "far", "FAR replicas: %s. Leader: %s" % (text, leader or "unknown"))
    if facts.get("hosted") and leader in where and where[leader] in selected:
        rep.add("INFO", "far", "the FAR leader runs on a worker it may fence. If it dies with that node, the other "
                "replica takes the lease and fences again (20 s in the customer drill).")
    return ready, leader


DMI_SCRIPT = ('for f in product_serial product_uuid sys_vendor product_name; do '
              'printf "%s=%s\\n" "$f" "$(cat /sys/class/dmi/id/$f 2>/dev/null)"; done')


def read_dmi(oc, node):
    rc, out, err = oc.run(["debug", "node/" + node, "--quiet", "--", "chroot", "/host", "sh", "-c", DMI_SCRIPT],
                          timeout=300)
    values = {}
    for line in out.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("product_serial", "product_uuid", "sys_vendor", "product_name"):
            values[key] = value.strip()
    if rc != 0 or "product_serial" not in values:
        last = (err or out).strip().splitlines()
        return {"error": last[-1] if last else "oc debug exit code %d" % rc}
    return values


def collect_node_identity(oc, names):
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = collections.OrderedDict((n, ex.submit(read_dmi, oc, n)) for n in names)
    return {n: f.result() for n, f in futures.items()}


def run_probe(oc, pod, payload, timeout):
    rc, out, err = oc.run(["exec", "-i", "-n", NS, pod, "-c", "manager", "--", "python3", "-c", PROBE],
                          input=json.dumps(payload), timeout=timeout)
    for line in reversed(out.splitlines()):
        if line.startswith("{"):
            try:
                return json.loads(line).get("results", []), None
            except ValueError:
                break
    return None, ((err or out).strip() or "exit code %d" % rc)[-400:]


def check_reach(oc, conf, pods, rep):
    targets = [{"node": n, "ip": ip} for n, ip in conf.nodes.items()]
    reached = {}
    for pod, node in pods:
        results, err = run_probe(oc, pod, {"mode": "reach", "targets": targets, "ssl_insecure": conf.ssl_insecure},
                                 timeout=90 + 2 * len(targets))
        if results is None:
            rep.add("FAIL", "reach", "cannot run the probe in %s: %s" % (pod, err))
            continue
        reached[pod] = {r["node"] for r in results if r["status"]}
        dead = ["%s %s: %s%s" % (r["node"], r["ip"], r.get("error"),
                                 " (through the proxy %s)" % mask_url(r["proxy"]) if r.get("proxy") else "")
                for r in results if not r["status"]]
        odd = ["%s %s: HTTP %s" % (r["node"], r["ip"], r["status"]) for r in results if r["status"] not in (0, 200)]
        proxied = ["%s via %s" % (r["ip"], mask_url(r["proxy"])) for r in results if r["status"] and r.get("proxy")]
        if dead:
            rep.add("FAIL", "reach", "from %s (on %s), no answer from:\n%s" % (pod, node, "\n".join(dead)))
        if odd:
            rep.add("WARN", "reach", "from %s, the Redfish service root did not answer 200:\n%s" % (pod, "\n".join(odd)))
        if not dead and not odd:
            rep.add("PASS", "reach", "from %s (on %s): %d of %d BMCs answer the Redfish service root"
                    % (pod, node, len(results), len(results)))
        if proxied:
            rep.add("WARN", "reach", "from %s, Redfish goes through the cluster proxy: %s. NO_PROXY does not "
                    "cover these BMCs, so fencing depends on the proxy. Add the BMC network to the cluster "
                    "proxy's noProxy." % (pod, short_list(proxied, 4)))
    for n in conf.by_name:
        rep.add("WARN", "reach", "%s: BMC given by name (%s), so fencing depends on DNS during an incident; "
                "an IP address is safer" % (n, conf.nodes[n]))
    return reached


def template_params(conf):
    return ["--action", "--systems-uri", "--ip"] + (["--ssl-insecure"] if conf.ssl_insecure else [])


def stdin_safe(value):
    """The fence agent's stdin interface strips each line and one pair of surrounding double
    quotes; FAR passes arguments as they are. Values that change in that trip cannot be tested
    through stdin."""
    return value == value.strip() and not (len(value) > 1 and value[0] == value[-1] == '"')


def read_secret(oc, conf, rep):
    """Returns (state, username, password): state is 'absent', 'ok', 'broken' or 'error'."""
    sec, err = oc.get(["secret", SECRET, "-n", NS])
    if sec is None:
        if not_found(err):
            return "absent", None, None
        rep.add("FAIL", "secret", "cannot read Secret %s: %s" % (SECRET, err))
        return "error", None, None
    data = sec.get("data") or {}
    user, password = b64(data.get("--username")), b64(data.get("--password"))
    problems = []
    if not user:
        problems.append("--username is missing or empty")
    if not password:
        problems.append("--password is missing or empty: FAR then passes a bare --password and the agent "
                        "swallows the next argument (\"You have to set login name\")")
    if password and password != password.rstrip("\r\n"):
        problems.append("--password ends with a line break (created with echo instead of printf?): the BMC "
                        "sees it as part of the password")
    clash = [k for k in data if k in template_params(conf)]
    if clash:
        problems.append("it also holds %s, which the template sets too: the FAR webhook rejects a parameter "
                        "defined twice" % ", ".join(clash))
    keys = ", ".join(sorted(data)) or "none"
    if problems:
        rep.add("FAIL", "secret", "Secret %s already exists but is not usable (keys: %s):\n%s\nNot modified. "
                "Fix it in place with the one-liner in docs/preflight.md section 10, or pause the "
                "NodeHealthCheck if it is armed, delete the Secret and run this again." % (SECRET, keys, "\n".join(problems)))
        return "broken", None, None
    rep.add("WARN", "secret", "Secret %s already exists in %s: not modified. The BMC checks below use its "
            "values, the same ones FAR will use (keys: %s)." % (SECRET, NS, keys))
    return "ok", user, password


def create_secret(oc, user, password, rep):
    rc, _, err = oc.run(["create", "secret", "generic", SECRET, "-n", NS, "--from-literal=--username=" + user,
                         "--from-file=--password=/dev/stdin"], input=password)
    if rc != 0:
        rep.add("FAIL", "secret", "could not create Secret %s: %s" % (SECRET, err))
        return None, None
    sec, err = oc.get(["secret", SECRET, "-n", NS])
    if sec is None:
        rep.add("FAIL", "secret", "created Secret %s but cannot read it back: %s" % (SECRET, err))
        return None, None
    data = sec.get("data") or {}
    stored_user, stored_password = b64(data.get("--username")), b64(data.get("--password"))
    if (stored_user, stored_password) != (user, password):
        rep.add("FAIL", "secret", "created Secret %s, but what it holds differs from what was typed "
                "(--username %d chars, --password %d chars)" % (SECRET, len(stored_user), len(stored_password)))
        return None, None
    rep.add("PASS", "secret", "created Secret %s in %s (--username %d chars, --password %d chars)"
            % (SECRET, NS, len(stored_user), len(stored_password)))
    return stored_user, stored_password


def refused(r):
    return bool(r.get("unauthorized") or (r.get("account") or {}).get("unauthorized"))


def check_bmc_logins(conf, user, nodes, results, rep):
    """Login, power state and Reset action per node. Returns the nodes whose BMC logged in."""
    ok = []
    for r in results:
        node, ip = r["node"], r["ip"]
        if r.get("skipped"):
            continue
        if refused(r):
            skipped = [x["node"] for x in results if x.get("skipped")]
            rep.add("FAIL", "login", "%s: the BMC at %s refused %s (HTTP 401): wrong password, or no such "
                    "account on that BMC.%s Stopped here on purpose: every retry is a failed login, and BMCs "
                    "lock accounts or block the source." % (node, ip, user, " Not tried: %s." % short_list(skipped) if skipped else ""))
            continue
        if r.get("status") != 200:
            hint = ""
            if r.get("systems"):
                hint = " This BMC lists these systems: %s. Set systems_uri in [bmc]." % ", ".join(r["systems"])
            rep.add("FAIL", "login", "%s: GET %s on %s answered %s.%s"
                    % (node, conf.systems_uri, ip, r.get("error") or "HTTP %s" % r.get("status"), hint))
            continue
        problems = []
        types = r.get("reset_types")
        if not r.get("reset_target"):
            problems.append("no #ComputerSystem.Reset action: fence_redfish has nothing to send the power-off to")
        elif isinstance(types, list) and not {"ForceOff", "On"} <= set(types):
            problems.append("the Reset action does not offer %s" % " and ".join(t for t in ("ForceOff", "On") if t not in types))
        power = r.get("PowerState")
        if power == "Off" and node in nodes and is_ready(nodes[node]):
            problems.append("the BMC says the server is Off while the node is Ready: this BMC does not control this node")
        desc = " ".join(x for x in (r.get("Manufacturer"), r.get("Model")) if x)
        if problems:
            rep.add("FAIL", "bmc", "%s -> %s: %s" % (node, ip, "; ".join(problems)))
            continue
        offers = ", Reset offers ForceOff and On" if isinstance(types, list) else ", Reset action present"
        rep.add("PASS", "bmc", "%s -> %s: login as %s, PowerState %s%s%s"
                % (node, ip, user, power, offers, " (%s)" % desc if desc else ""))
        ok.append(node)
    return ok


def check_identity(conf, nodes, dmi, results, rep):
    """The check that keeps FAR from powering off a healthy node: each BMC must belong to its node."""
    uuid_count = collections.Counter(norm((n.get("status") or {}).get("nodeInfo", {}).get("systemUUID"))
                                     for n in nodes.values())
    serial_count = collections.Counter(norm(d.get("product_serial")) for d in dmi.values() if "error" not in d)
    proven = []
    by_bmc = collections.defaultdict(list)
    for r in results:
        if r.get("status") != 200:
            continue
        for key in ("SKU", "UUID"):
            if norm(r.get(key)) and not (key == "UUID" and norm(r.get(key)) in PLACEHOLDER_UUIDS):
                by_bmc[(key, norm(r.get(key)))].append(r["node"])
    for (key, value), owners in sorted(by_bmc.items()):
        if len(owners) > 1:
            rep.add("FAIL", "identity", "BMCs of %s report the same %s %s: two entries point at one server"
                    % (short_list(owners), key, value.upper()))
    for r in results:
        if r.get("status") != 200 or r["node"] not in nodes:
            continue
        node, ip = r["node"], r["ip"]
        d = dmi.get(node) or {"error": "not read"}
        serial = norm(d.get("product_serial"))
        node_uuid = norm(nodes[node].get("status", {}).get("nodeInfo", {}).get("systemUUID"))
        bmc_uuid = norm(r.get("UUID"))
        bmc_serials = {"SKU": norm(r.get("SKU")), "SerialNumber": norm(r.get("SerialNumber"))}
        if "error" in d:
            why = "serial not read (%s)" % d["error"]
        elif placeholder_serial(serial):
            why = "the node's serial is empty or a firmware placeholder (%r)" % d.get("product_serial")
        elif serial_count[serial] > 1:
            why = "%d nodes share the serial %s" % (serial_count[serial], serial.upper())
        else:
            why = None
        uuid_usable = node_uuid and node_uuid not in PLACEHOLDER_UUIDS and uuid_count[node_uuid] == 1
        detail = ("\nnode %s: serial %r, SMBIOS UUID %s\nBMC  %s: SKU %r, SerialNumber %r, UUID %s"
                  % (node, d.get("product_serial"), node_uuid or "-", ip, r.get("SKU"), r.get("SerialNumber"), bmc_uuid or "-"))
        if why is None:
            field = next((f for f, v in bmc_serials.items() if v and v == serial), None)
            if field:
                rep.add("PASS", "identity", "%s: node serial %s = BMC %s %s (%s)" % (node, serial.upper(), field, serial.upper(), ip))
                proven.append(node)
            else:
                rep.add("FAIL", "identity", "%s: the serial does not match the BMC at %s. The IP in the config "
                        "probably belongs to another server, and a wrong map powers off a healthy node.%s%s"
                        % (node, ip, detail, "\n(the UUIDs do match: check the serial in the BIOS/BMC after a "
                                              "board replacement)" if uuid_usable and node_uuid == bmc_uuid else ""))
        elif uuid_usable and node_uuid == bmc_uuid:
            rep.add("PASS", "identity", "%s: node SMBIOS UUID = BMC UUID %s (%s); serial not used: %s"
                    % (node, node_uuid, ip, why))
            proven.append(node)
        else:
            uuid_why = ("the UUIDs differ" if uuid_usable else
                        "the UUID is a placeholder or shared by several nodes" if node_uuid else "no UUID on the node")
            rep.add("FAIL", "identity", "%s: cannot prove that the BMC at %s controls this node: %s, and %s.%s"
                    % (node, ip, why, uuid_why, detail))
    return proven


def check_accounts(user, results, rep):
    for r in results:
        if r.get("status") != 200:
            continue
        node, a = r["node"], r.get("account") or {}
        if a.get("unauthorized"):
            continue
        if a.get("error"):
            rep.add("WARN", "account", "%s: cannot read the account list (%s). Check the role of %s by hand "
                    "(docs/preflight.md section 9); the drill proves it." % (node, a["error"], user))
            continue
        if not a.get("found"):
            rep.add("WARN", "account", "%s: %s is not in the BMC's local accounts (a directory account?). Check "
                    "its role by hand; the drill proves it." % (node, user))
            continue
        role, privileges = a.get("RoleId"), a.get("privileges")
        if a.get("Enabled") is False or a.get("Locked") is True:
            rep.add("FAIL", "account", "%s: account %s is %s" % (node, user, "disabled" if a.get("Enabled") is False else "locked"))
            continue
        can_power = isinstance(privileges, list) and "ConfigureComponents" in privileges
        if can_power or role in ("Administrator", "Operator"):
            note = " (ConfigureComponents)" if can_power else ""
            if role == "Administrator":
                note += "; Operator would be enough"
            rep.add("PASS", "account", "%s: %s has role %s%s, enabled, not locked" % (node, user, role, note))
        elif isinstance(privileges, list) or role in ("ReadOnly", "NoAccess", "None"):
            rep.add("FAIL", "account", "%s: %s has role %s, without ConfigureComponents. status works, but "
                    "fence_redfish ignores the HTTP status of the power command, so the fence fails only when "
                    "it is real." % (node, user, role))
        else:
            rep.add("WARN", "account", "%s: %s has role %s with unknown privileges: make sure it can power the "
                    "server off (the drill proves it)" % (node, user, role))


def check_agent(oc, conf, pod, user, password, node_names, rep):
    targets = [{"node": n, "ip": conf.nodes[n]} for n in node_names]
    payload = {"mode": "agent", "targets": targets, "systems_uri": conf.systems_uri,
               "ssl_insecure": conf.ssl_insecure, "username": user, "password": password}
    results, err = run_probe(oc, pod, payload, timeout=120 + 30 * len(targets))
    if results is None:
        rep.add("FAIL", "agent", "cannot run fence_redfish in %s: %s" % (pod, err))
        return False
    good = True
    for r in results:
        last = (r.get("out") or "").splitlines()[-1:] or ["no output"]
        if r.get("rc") == 0 and "Status: ON" in (r.get("out") or ""):
            rep.add("PASS", "agent", "%s: fence_redfish status with the Secret's values says Status: ON" % r["node"])
        else:
            good = False
            rep.add("FAIL", "agent", "%s: fence_redfish status (exit code %s): %s" % (r["node"], r.get("rc"), last[0]))
    return good


def check_live_template(oc, conf, selected, rep):
    """The template already in the cluster is what NHC uses today; compare it with this config."""
    live, err = oc.get(["fenceagentsremediationtemplates.fence-agents-remediation.medik8s.io", TEMPLATE, "-n", NS])
    if live is None:
        if not not_found(err):
            rep.add("WARN", "template", "cannot read FenceAgentsRemediationTemplate %s: %s" % (TEMPLATE, err))
        return
    spec = ((live.get("spec") or {}).get("template") or {}).get("spec") or {}
    shared = spec.get("sharedparameters") or {}
    diffs = []
    if spec.get("sharedSecretName") != SECRET:
        diffs.append("sharedSecretName is %s (FAR's webhook drops it when the Secret is missing at apply time)"
                     % (spec.get("sharedSecretName") or "missing"))
    if spec.get("remediationStrategy") != "OutOfServiceTaint":
        diffs.append("remediationStrategy is %s, not OutOfServiceTaint" % spec.get("remediationStrategy"))
    if shared.get("--action") != "off":
        diffs.append("--action is %s, not off" % shared.get("--action", "unset (the agent defaults to reboot)"))
    if shared.get("--systems-uri") != conf.systems_uri:
        diffs.append("--systems-uri is %s, the config says %s" % (shared.get("--systems-uri"), conf.systems_uri))
    if ("--ssl-insecure" in shared) != conf.ssl_insecure:
        diffs.append("--ssl-insecure is %s" % ("set, the config says verify" if "--ssl-insecure" in shared
                                              else "missing: the agent verifies the BMC certificate"))
    live_ips = (spec.get("nodeparameters") or {}).get("--ip") or {}
    want = {n: conf.nodes[n] for n in conf.nodes if n in selected}
    for n in sorted(set(live_ips) | set(want)):
        if live_ips.get(n) != want.get(n):
            diffs.append("%s: --ip in the cluster %s, in the config %s" % (n, live_ips.get(n, "-"), want.get(n, "-")))
    if diffs:
        rep.add("WARN", "template", "FenceAgentsRemediationTemplate %s is already in the cluster and differs from "
                "this config:\n%s\nThat is what NHC uses today. Once this run passes, apply the generated 02."
                % (TEMPLATE, "\n".join(diffs)))
    else:
        rep.add("PASS", "template", "FenceAgentsRemediationTemplate %s already in the cluster matches this config"
                % TEMPLATE)


def check_hosted(mgmt, conf, facts, nodes, rep):
    if not facts.get("hosted"):
        if mgmt or conf.hosted_cluster:
            rep.add("INFO", "hosted", "not a hosted cluster: --mgmt-* and [hosted] are ignored")
        return
    if mgmt is None or conf.hosted_cluster is None:
        rep.add("WARN", "hosted", "the NodePool settings live on the management cluster. Run again with "
                "--mgmt-context (or --mgmt-kubeconfig) and hosted_cluster in [hosted] to check autoRepair, or "
                "check by hand (docs/preflight.md section 2).")
        return
    ns, name = conf.hosted_cluster
    hc, err = mgmt.get(["hostedclusters.hypershift.openshift.io", name, "-n", ns])
    if hc is None:
        rep.add("FAIL", "hosted", "cannot read HostedCluster %s/%s on the management cluster: %s" % (ns, name, err))
        return
    infra_id = (hc.get("spec") or {}).get("infraID")
    if infra_id != facts.get("infra"):
        rep.add("FAIL", "hosted", "HostedCluster %s/%s has infraID %s, but this cluster is %s: [hosted] points at "
                "another hosted cluster" % (ns, name, infra_id, facts.get("infra")))
        return
    rep.add("PASS", "hosted", "HostedCluster %s/%s is this cluster (infraID %s)" % (ns, name, infra_id))
    pools, err = mgmt.get(["nodepools.hypershift.openshift.io", "-n", ns])
    if pools is None:
        rep.add("FAIL", "hosted", "cannot list NodePools in %s: %s" % (ns, err))
        return
    for np in pools.get("items", []):
        spec = np.get("spec") or {}
        if spec.get("clusterName") != name:
            continue
        pool = np["metadata"]["name"]
        members = [n for n in conf.nodes if n in nodes and labels_of(nodes[n]).get(NODEPOOL_LABEL) == pool]
        m = spec.get("management") or {}
        who = " (%s)" % short_list(members, 4) if members else ""
        if m.get("autoRepair"):
            rep.add("FAIL", "hosted", "NodePool %s%s has autoRepair: true. HyperShift then runs a "
                    "MachineHealthCheck that replaces the Machine of a node NotReady for 16 min (Agent and None "
                    "platforms; 8 min on the others): a second remediator on the node FAR powered off. Set "
                    "autoRepair: false." % (pool, who))
        else:
            rep.add("PASS", "hosted", "NodePool %s%s: autoRepair false" % (pool, who))
        if m.get("upgradeType") == "InPlace":
            rep.add("INFO", "hosted", "NodePool %s: InPlace updates (maxUnavailable %s). NHC detects them and "
                    "postpones on its own." % (pool, (m.get("inPlace") or {}).get("maxUnavailable", 1)))
        else:
            rep.add("WARN", "hosted", "NodePool %s: %s updates are not detected by NHC. Pause it during NodePool "
                    "updates (README)." % (pool, m.get("upgradeType") or "Replace"))
    bmhs, err = mgmt.get(["baremetalhosts.metal3.io", "-A"])
    check_bmh(bmhs, err, conf, rep, where="the management cluster")


# ------------------------------------------------------------------------------ manifests

def far_spec_lines(conf, node_ips, indent):
    lines = ["agent: fence_redfish",
             "remediationStrategy: OutOfServiceTaint",
             "sharedSecretName: %s" % SECRET,
             "retrycount: 5",
             "retryinterval: 5s",
             "timeout: 60s",
             "sharedparameters:",
             '  "--action": "off"',
             '  "--systems-uri": "%s"' % conf.systems_uri]
    if conf.ssl_insecure:
        lines.append('  "--ssl-insecure": ""')
    lines += ["nodeparameters:", '  "--ip":']
    lines += ['    "%s": "%s"' % (node, ip) for node, ip in node_ips]
    return [" " * indent + line for line in lines]


def render_template(conf, nodes_in, stamp):
    head = ["# FAR template: how FAR fences each worker below through its BMC over Redfish.",
            "# %s" % stamp,
            "# Inert on its own: nothing uses it until the NodeHealthCheck (04) points at it.",
            "# Apply it only while Secret %s exists in %s:" % (SECRET, NS),
            "# FAR's webhook drops sharedSecretName when that Secret is missing, and the template",
            "# is then stored without credentials.",
            "apiVersion: fence-agents-remediation.medik8s.io/v1alpha1",
            "kind: FenceAgentsRemediationTemplate",
            "metadata:",
            "  name: %s" % TEMPLATE,
            "  namespace: %s" % NS,
            "spec:",
            "  template:",
            "    spec:"]
    return "\n".join(head + far_spec_lines(conf, [(n, conf.nodes[n]) for n in nodes_in], 6)) + "\n"


def render_drill(conf, node, stamp):
    head = ["# DRILL: applying this powers %s off right now (Redfish ForceOff through %s)." % (node, conf.nodes[node]),
            "# %s" % stamp,
            "# Only in an agreed window, following docs/drill.md. Afterwards: power the node back on,",
            "# wait for Ready, then delete this CR (FAR removes the out-of-service taint only then).",
            "apiVersion: fence-agents-remediation.medik8s.io/v1alpha1",
            "kind: FenceAgentsRemediation",
            "metadata:",
            "  name: %s" % node,
            "  namespace: %s" % NS,
            "spec:"]
    return "\n".join(head + far_spec_lines(conf, [(node, conf.nodes[node])], 2)) + "\n"


def render_nhc(conf, total, stamp):
    key, n, pct = conf.threshold
    allowed, _ = allowed_unhealthy(conf.threshold, total)
    field = "minHealthy" if key == "min_healthy" else "maxUnhealthy"
    value = '"%d%%"' % n if pct else str(n)
    lines = ["# ARMS automatic fencing. Apply it LAST, after a drill (03) powered a node off and its VMs",
             "# came back elsewhere. From then on, a worker NotReady for %s is powered off by its BMC." % conf.duration,
             "# %s" % stamp,
             "# %s selected; %s: %s lets NHC fence at most %d at a time." % (plural(total, "worker"), field, value, allowed),
             "apiVersion: remediation.medik8s.io/v1alpha1",
             "kind: NodeHealthCheck",
             "metadata:",
             "  name: %s" % NHC_NAME,
             "spec:",
             "  selector:",
             "    matchExpressions:",
             "      - key: %s" % WORKER_LABEL,
             "        operator: Exists",
             "  %s: %s" % (field, value),
             "  unhealthyConditions:",
             "    - type: Ready",
             '      status: "False"',
             "      duration: %s" % conf.duration,
             "    - type: Ready",
             "      status: Unknown",
             "      duration: %s" % conf.duration,
             "  remediationTemplate:",
             "    apiVersion: fence-agents-remediation.medik8s.io/v1alpha1",
             "    kind: FenceAgentsRemediationTemplate",
             "    name: %s" % TEMPLATE,
             "    namespace: %s" % NS]
    return "\n".join(lines) + "\n"


def generate(oc, conf, selected, run_dir, stamp, rep):
    nodes_in = [n for n in conf.nodes if n in selected]
    files = collections.OrderedDict()
    files["02-fartemplate-redfish.yaml"] = render_template(conf, nodes_in, stamp)
    for node in nodes_in:
        files["03-drill-%s.yaml" % node] = render_drill(conf, node, stamp)
    files["04-nodehealthcheck.yaml"] = render_nhc(conf, len(selected), stamp)
    parent = os.path.dirname(os.path.abspath(run_dir))
    os.makedirs(parent, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".fencing-", dir=parent)
    ok = True
    try:
        for name, text in files.items():
            path = os.path.join(tmp, name)
            with open(path, "w") as f:
                f.write(text)
            rc, out, err = oc.run(["apply", "--dry-run=server", "--validate=strict", "-f", path, "-o", "json"])
            if rc != 0:
                ok = False
                rep.add("FAIL", "manifests", "%s rejected by the API (server dry-run): %s" % (name, err))
                continue
            try:
                obj = json.loads(out)
            except ValueError:
                ok = False
                rep.add("FAIL", "manifests", "%s: unexpected dry-run output from oc" % name)
                continue
            spec = obj.get("spec") or {}
            far_spec = (spec.get("template") or {}).get("spec") if obj.get("kind") == "FenceAgentsRemediationTemplate" else spec
            if obj.get("kind", "").startswith("FenceAgentsRemediation") and (far_spec or {}).get("sharedSecretName") != SECRET:
                ok = False
                rep.add("FAIL", "manifests", "%s: the API accepted it but FAR's webhook removed sharedSecretName: "
                        "Secret %s does not exist in %s" % (name, SECRET, NS))
        if ok:
            rep.add("PASS", "manifests", "%s accepted by the API (server dry-run, strict validation, FAR and NHC "
                    "webhooks)" % plural(len(files), "file"))
            os.makedirs(run_dir, exist_ok=True)
            for name in files:
                shutil.move(os.path.join(tmp, name), os.path.join(run_dir, name))
        return ok, list(files)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ----------------------------------------------------------------------------------- main

def parse_args(argv):
    p = argparse.ArgumentParser(description="Check the fence path and generate NHC + FAR manifests "
                                            "(nothing is applied, nothing is powered off).")
    p.add_argument("-c", "--config", required=True, help="config file (see fencing.conf.example)")
    p.add_argument("--context", help="kubeconfig context of the cluster whose workers are fenced")
    p.add_argument("--kubeconfig", help="kubeconfig file of that cluster")
    p.add_argument("--mgmt-context", help="hosted clusters: kubeconfig context of the management cluster")
    p.add_argument("--mgmt-kubeconfig", help="hosted clusters: kubeconfig file of the management cluster")
    p.add_argument("--out", default="generated", help="base directory for the results (default: generated)")
    p.add_argument("--password-stdin", action="store_true",
                   help="read the BMC password from stdin instead of prompting (only used to create the Secret)")
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        conf = load_config(args.config)
    except ConfigError as e:
        print("ERROR in %s: %s" % (args.config, e), file=sys.stderr)
        return 2
    piped_password = None
    if args.password_stdin:
        piped_password = sys.stdin.read()
        piped_password = piped_password[:-1] if piped_password.endswith("\n") else piped_password
        piped_password = piped_password[:-1] if piped_password.endswith("\r") else piped_password

    oc = Oc(args.context, args.kubeconfig)
    mgmt = Oc(args.mgmt_context, args.mgmt_kubeconfig) if (args.mgmt_context or args.mgmt_kubeconfig) else None
    rc, user, err = oc.run(["whoami"])
    if rc != 0:
        print("ERROR: oc is not logged in to the cluster: %s" % err, file=sys.stderr)
        return 2
    _, server, _ = oc.run(["whoami", "--show-server"])

    rep = Report()
    rep.say("fencing-setup %s, %s (%s)" % (VERSION, conf.path, plural(len(conf.nodes), "node")))
    rep.say("cluster: %s as %s" % (server.strip(), user.strip()))
    rep.say("")

    facts = check_cluster(oc, rep)
    far_ok = check_operators(oc, rep)
    nodes_json, err = oc.get(["nodes"])
    if nodes_json is None:
        rep.add("FAIL", "nodes", "cannot list nodes: %s" % err)
        nodes = {}
    else:
        nodes = collections.OrderedDict((n["metadata"]["name"], n) for n in nodes_json.get("items", []))
    selected = check_nodes(conf, nodes, rep)
    check_threshold(conf, selected, rep)
    nhc_state = check_conflicts(oc, conf, nodes, selected, rep)
    check_vms(oc, rep)
    check_capacity(oc, nodes, selected, rep)
    check_hosted(mgmt, conf, facts, nodes, rep)

    pods, leader = far_runtime(oc, facts, selected, rep) if far_ok else ([], None)
    present = [n for n in conf.nodes if n in nodes]
    dmi = collect_node_identity(oc, present) if present and pods else {}

    reached = check_reach(oc, conf, pods, rep) if pods else {}
    probe_pod = leader if leader in reached else (next(iter(reached)) if reached else None)
    reachable = [n for n in conf.nodes if probe_pod and n in reached[probe_pod]]

    state, bmc_user, bmc_password = read_secret(oc, conf, rep) if far_ok else ("error", None, None)
    if state == "ok" and bmc_user != conf.username:
        rep.add("WARN", "secret", "the Secret's user is %r and the config says %r: FAR uses the Secret's"
                % (bmc_user, conf.username))
    if state == "ok" and piped_password is not None:
        rep.add("INFO", "secret", "--password-stdin ignored: the existing Secret's values are used")
    if state == "absent":
        if not reachable:
            rep.add("INFO", "secret", "Secret %s does not exist; not asking for a password, no BMC was reached" % SECRET)
        else:
            rep.add("INFO", "secret", "Secret %s does not exist: it is created once the password works on every "
                    "BMC" % SECRET)
            bmc_user = conf.username
            if piped_password is not None:
                bmc_password = piped_password
            else:
                try:
                    bmc_password = getpass.getpass("BMC password for %s (typing is hidden): " % bmc_user)
                except EOFError:
                    bmc_password = ""
            if not bmc_password:
                print("ERROR: empty password, nothing done", file=sys.stderr)
                return 2

    logged_in, proven = [], []
    if bmc_password and reachable:
        payload = {"mode": "auth", "targets": [{"node": n, "ip": conf.nodes[n]} for n in reachable],
                   "systems_uri": conf.systems_uri, "ssl_insecure": conf.ssl_insecure,
                   "username": bmc_user, "password": bmc_password}
        results, err = run_probe(oc, probe_pod, payload, timeout=180 + 60 * len(reachable))
        if results is None:
            rep.add("FAIL", "login", "cannot run the BMC checks in %s: %s" % (probe_pod, err))
        else:
            logged_in = check_bmc_logins(conf, bmc_user, nodes, results, rep)
            proven = check_identity(conf, nodes, dmi, results, rep)
            check_accounts(bmc_user, results, rep)
            if state == "absent":
                # Only a password every configured BMC accepted goes into the Secret.
                if set(logged_in) == set(conf.nodes):
                    bmc_user, bmc_password = create_secret(oc, bmc_user, bmc_password, rep)
                    state = "ok" if bmc_password else "error"
                else:
                    rep.add("INFO", "secret", "Secret %s not created: the password was confirmed on %d of %d BMCs"
                            % (SECRET, len(logged_in), len(conf.nodes)))
    if state == "ok" and logged_in:
        if stdin_safe(bmc_user) and stdin_safe(bmc_password):
            check_agent(oc, conf, probe_pod, bmc_user, bmc_password, logged_in, rep)
        else:
            rep.add("WARN", "agent", "the user or password begins or ends with a space or a double quote, which "
                    "the fence agent's stdin interface strips: the status test cannot use them as they are. The "
                    "login checks above did; the drill proves the agent path.")
    bmc_password = None
    if far_ok:
        check_live_template(oc, conf, selected, rep)

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(args.out, "%s-%s" % (facts.get("infra", "cluster"), stamp))
    header = "Generated %s by scripts/fencing-setup.py from %s against %s" % (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), os.path.basename(conf.path), server.strip())
    complete = bool(selected) and set(proven) >= {n for n in conf.nodes if n in selected}
    if rep.count("FAIL") == 0 and complete:
        ok, _ = generate(oc, conf, selected, run_dir, header, rep)
    else:
        ok = False
        if rep.count("FAIL") == 0:
            rep.add("FAIL", "manifests", "not every selected worker was matched to its BMC, so nothing was generated")

    rep.say("")
    rep.say("%d PASS, %d WARN, %d FAIL" % (rep.count("PASS"), rep.count("WARN"), rep.count("FAIL")))
    if ok:
        rep.say("Manifests in %s (nothing was applied):" % run_dir)
        rep.say("  1. review them; the WARN lines above are yours to judge")
        rep.say("  2. oc apply -f %s" % os.path.join(run_dir, "02-fartemplate-redfish.yaml"))
        rep.say("  3. drill ONE node in an agreed window, following docs/drill.md; pick the node with the")
        rep.say("     fewest critical VMs (there is one 03-drill file per node):")
        rep.say("     oc apply -f %s" % os.path.join(run_dir, "03-drill-<node>.yaml"))
        if nhc_state == "armed":
            rep.say("     %s is ARMED: pause it before the drill and resume it after (README, pauseRequests)," % NHC_NAME)
            rep.say("     or it starts its own remediation of the node you powered off")
        elif nhc_state == "paused":
            rep.say("     %s is PAUSED: resume it after the drill, or nothing is fenced automatically" % NHC_NAME)
        if nhc_state:
            rep.say("  4. %s already exists (%s); apply 04 only to change its settings:" % (NHC_NAME, nhc_state))
        else:
            rep.say("  4. after the drill (node back on, Ready, drill CR deleted), arm the health check:")
        rep.say("     oc apply -f %s" % os.path.join(run_dir, "04-nodehealthcheck.yaml"))
    else:
        rep.say("No manifests were written. Fix the FAIL lines and run again.")
    try:
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, "report.txt"), "w") as f:
            f.write("\n".join(rep.lines) + "\n")
        rep.say("Report: %s" % os.path.join(run_dir, "report.txt"))
    except OSError as e:
        print("could not write the report: %s" % e, file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        sys.exit(130)
