# fencing-setup.py: the preflight, automated

`scripts/fencing-setup.py` runs the checks of [`preflight.md`](preflight.md) for every node,
creates the credential Secret if it is missing, and writes manifests 02, 03 and 04 with your
node names and BMC IPs. It never applies anything and never powers anything on or off. The
drill and arming the health check stay manual, on purpose.

## What you need

- Python 3.6 or later where you run `oc`. RHEL 8 and 9 ship it; the script uses only the
  standard library.
- `oc` logged in as cluster-admin to the cluster whose workers get fenced. On a hosted cluster,
  that is the hosted cluster itself.
- Node Health Check and Fence Agents Remediation installed (step 1 of the README).
- The BMC account name and its password.

## Run it

```bash
cp scripts/fencing.conf.example fencing.conf
```

Edit `fencing.conf`: the BMC account under `[bmc]`, and one line per worker under `[nodes]`,
with the node name exactly as `oc get nodes` shows it and the IP of its BMC. No password goes in
the file. Git ignores `*.conf` and the `generated/` directory, because both hold your real names
and addresses.

```bash
python3 scripts/fencing-setup.py -c fencing.conf
```

If the Secret does not exist yet, the script asks for the BMC password once, without echo, after
it has reached the BMCs. Use `--context` or `--kubeconfig` to point at a cluster other than the
current one.

On a hosted cluster, the NodePool lives on the management cluster. Set `hosted_cluster` under
`[hosted]` and pass the management cluster's kubeconfig to check it too:

```bash
python3 scripts/fencing-setup.py -c fencing.conf --mgmt-kubeconfig ~/mgmt.kubeconfig
```

Without it, the script reminds you to check `autoRepair` by hand (preflight section 2).

## What it checks

| Area | Check | Preflight |
| --- | --- | --- |
| `cluster` | OpenShift 4.15 or later; single-node refused; hosted cluster noted; update in progress | 1 |
| `operators` | NHC and FAR from `redhat-operators`, `Succeeded`, one OperatorGroup; Self Node Remediation present | 3 |
| `nodes` | every worker the health check selects has a BMC in the config; none carries a `control-plane` or `master` label; NotReady nodes; leftover fencing taints | 1 |
| `nhc` | how many nodes the threshold lets NHC fence at once, rounded the way NHC rounds; the duration | |
| `conflicts` | other NodeHealthChecks or MachineHealthChecks over these workers; BareMetalHosts holding these BMCs; leftover FAR CRs | 2 |
| `vms` | running VMs whose `runStrategy` keeps them down after a fence | 5 |
| `capacity` | memory requests on the busiest worker against free memory on the others | 4 |
| `reach` | every BMC from every FAR replica, through the pod's real proxy settings | 6, 7 |
| `bmc` | login; power state; a Reset action offering `ForceOff` and `On`; a server Off while its node is Ready | |
| `identity` | the node's serial (read on the node) equals the BMC's serial (`SKU` on Dell) | 8 |
| `account` | the BMC role has `ConfigureComponents` (Operator or Administrator) | 9 |
| `secret` | created if missing, never modified if present; empty values, a trailing line break, parameters the template also sets | 10 |
| `agent` | `fence_redfish` status from the FAR pod, with the values read back from the Secret | 10 |
| `template` | a FAR template already in the cluster (what NHC uses today) against this config: Secret reference, strategy, action, URI, certificate check, each node's BMC IP | |
| `hosted` | the HostedCluster is this cluster; NodePool `autoRepair: false`; update type; BareMetalHosts | 2 |
| `manifests` | server-side dry-run with strict validation, through the FAR and NHC webhooks; `sharedSecretName` still present | |

Every line of the report says `PASS`, `WARN`, `FAIL` or `INFO`. The manifests are written only
when no line says `FAIL`. `WARN` lines are yours to judge.

## How it behaves

- **The BMC checks run inside the FAR pod**, with the same Python, `requests` library and
  proxy variables the fence agent uses there. A check that passes from your laptop proves
  nothing about the path fencing takes.
- **The password travels only through stdin**: into `oc create secret`, and into the FAR pod.
  It never goes on a command line, to disk, or to the screen. `--password-stdin` reads it from a
  pipe instead of the prompt.
- **One failed login, not one per BMC.** The script logs in to the first BMC alone. If that BMC
  answers 401, it tries no other: a typo counts as a failed login, and BMCs lock accounts or
  block the source.
- **The Secret is created only when the password worked on every BMC in the config.** If the
  Secret already exists, the script says so, leaves it alone and tests its values instead, which
  are what FAR will use. To change the password, update the Secret in place with the one-liner in
  preflight section 10, then run the script again.
- **A node passes the identity check only when its serial equals the BMC's `SKU` or
  `SerialNumber`.** Serials that are empty, firmware placeholders such as `To Be Filled By
  O.E.M.`, or shared by several nodes prove nothing. Then the SMBIOS UUID can prove it under the
  same rule (placeholder UUIDs do not count). A serial that disagrees fails, even when the UUIDs
  match: that case needs a human.
- **Results go to `generated/<cluster>-<date>-<time>/`**, with `report.txt`. A run with failures
  leaves only the report there. Exit code 0 means manifests were written, 1 means a check failed,
  2 means a config or login problem.

When it passes, the end of the output tells you what to apply and in which order:

```
Manifests in generated/prod-7k2px-20261006-162602 (nothing was applied):
  1. review them; the WARN lines above are yours to judge
  2. oc apply -f generated/prod-7k2px-20261006-162602/02-fartemplate-redfish.yaml
  3. drill one node in an agreed window, following docs/drill.md:
     oc apply -f generated/prod-7k2px-20261006-162602/03-drill-worker-0.example.com.yaml
  4. after the drill (node back on, Ready, drill CR deleted), arm the health check:
     oc apply -f generated/prod-7k2px-20261006-162602/04-nodehealthcheck.yaml
```

## Limits

- **Dell first.** The default `systems_uri` is the iDRAC one, and the identity check knows that
  Dell keeps the service tag in `SKU`. For other Redfish BMCs, set `systems_uri`; the serial is
  compared with both `SKU` and `SerialNumber`.
- **One BMC account for all nodes** (`sharedSecretName`). Per-node credentials
  (`nodeSecretNames`) are not handled.
- **Dedicated workers only.** Single-node and compact clusters are refused.
- **IPv4 BMC addresses or host names.** IPv6 is not handled, and a host name gets a warning:
  fencing then depends on DNS during an incident.
- **Reading the node's serial needs `oc debug node`**, which runs a privileged pod on each node.
  If that is blocked, the UUID is the only possible proof.
- **Reach is tested from the nodes the FAR replicas run on right now.** After a reschedule they
  may run on another worker.
- **FAR 0.6.0 or later.** Older versions accept `--action off` in the template and reject it only
  when they fence; the script fails on them.
- **What I tested:** every check by hand on Dell iDRAC hardware (the preflight). The script ran
  against a customer's hosted cluster with three Dell PowerEdge workers (iDRAC 9) on OpenShift
  4.20 with NHC 0.10.3 and FAR 0.6.1: 22 PASS, every service tag matched. In my lab it ran on
  OpenShift 4.21 with NHC 0.11.0 and FAR 0.7.0, against a Redfish test double with the real
  `fence_redfish` agent, for the failure paths. The UUID fallback and the management-cluster
  checks have not met real hardware yet.
