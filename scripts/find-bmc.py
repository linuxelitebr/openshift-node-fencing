#!/usr/bin/env python3
"""
find-bmc.py: find which BMC belongs to which node, by service tag, when nobody knows the IP.

It sweeps one or more networks for Redfish BMCs from inside the FAR pod (the same network path
fencing uses) and reads the serial of the server behind each one. Then either:

  --service-tag TAG   says which BMC belongs to that server
  --map               reads every worker's serial and prints the [nodes] block for fencing.conf
  (neither)           lists every BMC found with its serial

It never logs in blindly. Every address first gets an anonymous request to the Redfish service
root, which only says "I am a BMC". Only the BMCs that answer get one login each, to read the
serial, and a BMC that refuses the login is not tried again. Still, sweeping a whole network
looks like a scan to an IDS: agree on it with the network team first.

Read-only: it never changes a BMC or a node. The password travels only through stdin.

Requirements: Python 3.6+ (standard library only), `oc` logged in as cluster-admin, FAR installed.
Usage:        python3 find-bmc.py --username fencing --network 10.10.0.0/24 --service-tag ABC1234
"""

import argparse
import collections
import concurrent.futures
import getpass
import ipaddress
import json
import subprocess
import sys

NS = "openshift-workload-availability"
FAR_POD_SELECTOR = "app.kubernetes.io/name=fence-agents-remediation-operator"
WORKER_LABEL = "node-role.kubernetes.io/worker"
MAX_HOSTS = 4096
PLACEHOLDER_SERIALS = {
    "", "0", "none", "null", "n/a", "na", "unknown", "invalid", "not specified", "not applicable",
    "default string", "to be filled by o.e.m.", "system serial number", "chassis serial number",
    "serial number", "0123456789", "123456789", "1234567890",
}

# Runs inside the FAR manager container. Input: one JSON document on stdin (the only place the
# password travels). Output: one JSON line.
PROBE = r'''
import json, sys
from concurrent.futures import ThreadPoolExecutor
import requests, urllib3
urllib3.disable_warnings()

cfg = json.load(sys.stdin)
HEADERS = {"accept": "application/json", "OData-Version": "4.0"}

def session():
    s = requests.Session()
    s.trust_env = False  # straight to the BMC network, as fencing does when it is in noProxy
    s.verify = False
    s.headers.update(HEADERS)
    return s

def root(ip):
    try:
        r = session().get("https://%s/redfish/v1/" % ip, timeout=(2, 5))
        j = r.json()
    except Exception:
        return None
    if not isinstance(j, dict) or "RedfishVersion" not in j and "Systems" not in j:
        return None
    oem = j.get("Oem") or {}
    dell = oem.get("Dell") or {}
    # Product is optional in Redfish (a Lenovo XCC leaves it out): fall back to Vendor and the Oem keys
    vendor = " ".join(str(x) for x in [j.get("Product"), j.get("Vendor")] + sorted(oem) if x)
    return {"ip": ip, "product": j.get("Product") or j.get("Vendor") or j.get("Name") or "?", "vendor": vendor,
            "systems": (j.get("Systems") or {}).get("@odata.id") or "/redfish/v1/Systems",
            "tag": dell.get("ServiceTag")}

def systems(b):
    s = session()
    s.auth = (cfg["username"], cfg["password"])
    try:
        r = s.get("https://%s%s" % (b["ip"], b["systems"]), timeout=(5, 25))
        if r.status_code == 401:
            b["error"] = "login refused (HTTP 401)"
            return b
        members = (r.json().get("Members") or [])[:8]
        b["servers"] = []
        for m in members:
            j = s.get("https://%s%s" % (b["ip"], m["@odata.id"]), timeout=(5, 25)).json()
            b["servers"].append({k: j.get(k) for k in ("SKU", "SerialNumber", "HostName", "Model", "PowerState")})
        if not members:
            b["error"] = "the BMC lists no system (an iDRAC in that state usually needs a reboot)"
    except Exception as e:
        b["error"] = "%s: %s" % (type(e).__name__, str(e)[-120:])
    return b

with ThreadPoolExecutor(max_workers=cfg["parallel"]) as ex:
    found = [b for b in ex.map(root, cfg["hosts"]) if b]
KNOWN = ("dell", "idrac", "lenovo", "xclarity")
bmcs = [b for b in found if cfg["any_vendor"] or any(k in b["vendor"].lower() for k in KNOWN)]
skipped = {}
for b in found:
    if b not in bmcs:
        skipped[b["product"]] = skipped.get(b["product"], 0) + 1
with ThreadPoolExecutor(max_workers=min(8, len(bmcs) or 1)) as ex:
    bmcs = list(ex.map(systems, bmcs))
print(json.dumps({"answered": len(found), "bmcs": bmcs, "skipped": skipped}))
'''


def oc(base, args, input=None, timeout=600):
    kw = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    try:
        p = subprocess.run(base + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout, **kw)
    except FileNotFoundError:
        raise SystemExit("ERROR: `oc` was not found in PATH")
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %d s" % timeout
    return p.returncode, p.stdout, p.stderr.strip()


def norm(value):
    return (value or "").strip().lower()


def node_serial(base, node):
    rc, out, err = oc(base, ["debug", "node/" + node, "--quiet", "--", "chroot", "/host",
                             "cat", "/sys/class/dmi/id/product_serial"], timeout=300)
    serial = out.strip().splitlines()[-1].strip() if rc == 0 and out.strip() else ""
    return node, serial, (None if rc == 0 else (err or out).strip().splitlines()[-1:] or ["exit %d" % rc])


def parse_args(argv):
    p = argparse.ArgumentParser(description="Find the BMC of each node by service tag (read-only).")
    p.add_argument("--username", required=True, help="BMC account to read the serials with")
    p.add_argument("--network", action="append", required=True,
                   help="network to sweep, CIDR (10.10.0.0/24) or a single address; repeatable")
    p.add_argument("--service-tag", help="the serial / service tag to look for")
    p.add_argument("--map", action="store_true",
                   help="read every worker's serial (oc debug) and print the [nodes] block for fencing.conf")
    p.add_argument("--any-vendor", action="store_true", help="keep every Redfish BMC, not only Dell and Lenovo")
    p.add_argument("--parallel", type=int, default=32, help="addresses probed at once (default 32)")
    p.add_argument("--password-stdin", action="store_true", help="read the BMC password from stdin")
    p.add_argument("--context", help="kubeconfig context")
    p.add_argument("--kubeconfig", help="kubeconfig file")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    base = ["oc"] + (["--kubeconfig", args.kubeconfig] if args.kubeconfig else []) + \
        (["--context", args.context] if args.context else [])
    hosts = []
    for net in args.network:
        try:
            n = ipaddress.ip_network(net, strict=False)
        except ValueError as e:
            print("ERROR: --network %s: %s" % (net, e), file=sys.stderr)
            return 2
        hosts += [str(h) for h in (n.hosts() if n.num_addresses > 1 else [n.network_address])]
    if len(hosts) > MAX_HOSTS:
        print("ERROR: %d addresses; split the sweep (at most %d per run)" % (len(hosts), MAX_HOSTS), file=sys.stderr)
        return 2

    rc, _, err = oc(base, ["whoami"])
    if rc != 0:
        print("ERROR: oc is not logged in: %s" % err, file=sys.stderr)
        return 2
    rc, out, err = oc(base, ["get", "pods", "-n", NS, "-l", FAR_POD_SELECTOR, "-o", "json"])
    pods = [p["metadata"]["name"] for p in (json.loads(out).get("items", []) if rc == 0 else [])
            if p.get("status", {}).get("phase") == "Running"]
    if not pods:
        print("ERROR: no running FAR pod in %s: %s" % (NS, err or "none found"), file=sys.stderr)
        return 2

    serials = {}
    if args.map:
        rc, out, err = oc(base, ["get", "nodes", "-l", WORKER_LABEL, "-o", "json"])
        workers = sorted(n["metadata"]["name"] for n in json.loads(out).get("items", [])) if rc == 0 else []
        if not workers:
            print("ERROR: no node with the %s label: %s" % (WORKER_LABEL, err), file=sys.stderr)
            return 2
        print("reading the serial of %d workers (oc debug)..." % len(workers), file=sys.stderr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            for node, serial, problem in ex.map(lambda n: node_serial(base, n), workers):
                serials[node] = serial
                if problem:
                    print("  %s: serial not read (%s)" % (node, problem[0]), file=sys.stderr)

    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("BMC password for %s (typing is hidden): " % args.username)
    print("sweeping %d addresses from %s..." % (len(hosts), pods[0]), file=sys.stderr)
    payload = json.dumps({"hosts": hosts, "username": args.username, "password": password,
                          "any_vendor": args.any_vendor, "parallel": max(1, args.parallel)})
    rc, out, err = oc(base, ["exec", "-i", "-n", NS, pods[0], "-c", "manager", "--", "python3", "-c", PROBE],
                      input=payload, timeout=900)
    line = next((l for l in reversed(out.splitlines()) if l.startswith("{")), None)
    if line is None:
        print("ERROR: the probe failed in %s: %s" % (pods[0], (err or out)[-300:]), file=sys.stderr)
        return 2
    result = json.loads(line)
    bmcs = sorted(result["bmcs"], key=lambda b: ipaddress.ip_address(b["ip"]))

    rows = []
    for b in bmcs:
        for srv in b.get("servers") or [None]:
            tag = b.get("tag") or (srv or {}).get("SKU") or (srv or {}).get("SerialNumber")
            rows.append((b, srv, tag))
    print("\n%d addresses answered Redfish, %d BMCs kept" % (result["answered"], len(bmcs)))
    skipped = result.get("skipped") or {}
    if skipped:
        print("not kept, no login tried (not Dell or Lenovo): %s. --any-vendor keeps them." % ", ".join(
            "%d x %s" % (n, prod) for prod, n in sorted(skipped.items(), key=lambda kv: -kv[1])))
    print("")
    print("%-15s %-12s %-20s %-28s %s" % ("BMC", "SERIAL", "SERVER", "HOSTNAME (from the BMC)", "NOTE"))
    want = norm(args.service_tag)
    hits = []
    for b, srv, tag in rows:
        note = b.get("error") or ""
        if want and want in (norm(tag), norm((srv or {}).get("SerialNumber"))):
            note, hits = ("<- %s" % args.service_tag) + ("  " + note if note else ""), hits + [b["ip"]]
        print("%-15s %-12s %-20s %-28s %s" % (b["ip"], tag or "-", ((srv or {}).get("Model") or b["product"])[:20],
                                                ((srv or {}).get("HostName") or "-")[:28], note))

    if args.service_tag:
        print("\n%s" % ("%s: BMC %s" % (args.service_tag, ", ".join(hits)) if hits else
                        "%s: not found in %s" % (args.service_tag, ", ".join(args.network))))
        if len(hits) > 1:
            print("more than one BMC reports that serial: check by hand before using any of them")
    if args.map:
        by_serial = collections.defaultdict(list)
        for b, srv, tag in rows:
            for value in {norm(tag), norm((srv or {}).get("SerialNumber"))} - {""}:
                by_serial[value].append(b["ip"])
        print("\n[nodes]")
        missing = []
        for node in sorted(serials):
            s = norm(serials[node])
            ips = sorted(set(by_serial.get(s, [])))
            if s in PLACEHOLDER_SERIALS or len(set(s)) == 1:
                missing.append("%s (serial %r is a firmware placeholder: map it by hand)" % (node, serials[node]))
            elif len(ips) == 1:
                print("%s = %s" % (node, ips[0]))
            elif ips:
                missing.append("%s (serial %s on several BMCs: %s)" % (node, serials[node], ", ".join(ips)))
            else:
                missing.append("%s (serial %s: no BMC found in these networks)" % (node, serials[node] or "?"))
        for m in missing:
            print("# %s" % m)
        print("\nfencing-setup.py checks this map again (serial against BMC) before it writes anything.")
    return 0 if (not args.service_tag or hits) else 1


if __name__ == "__main__":
    sys.exit(main())
