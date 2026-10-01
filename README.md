# OpenShift Virtualization node fencing

Companion repo for the post
[Kill a Node in OpenShift Virtualization and the VM Never Comes Back. Here's the Fence That Fixes It](https://linuxelite.com.br/blog/openshift-virtualization-node-fencing/).

The short version: when a node running VMs hangs or dies, the VMs do not come back on their own.
Kubernetes cannot prove the node let go of its pods and volumes, so it waits. With an RWO volume
the new pod sits in `Multi-Attach error`; in my lab it never cleared until the dead node came
back. RWX does not save you either: the VM's old pod stays on the dead node, and the pod garbage
collector force-deletes the pods of a dead node only when the node is NotReady and carries the
`out-of-service` taint (or when someone deletes the Node object).

The fix is two of Red Hat's Workload Availability operators and one taint: Node Health Check
(NHC) notices the node is gone, Fence Agents Remediation (FAR) powers it off through its BMC, and
the `node.kubernetes.io/out-of-service` taint releases the pods and volumes, so the VMs restart
somewhere healthy.

The manifests in `manifests/` are for bare-metal Dell servers, fenced through the iDRAC over
Redfish. That is the setup that ran on real hardware. Other Redfish BMCs need their own
`--systems-uri`.

What I measured:

| Where | Storage | Result |
| --- | --- | --- |
| Customer: hosted cluster, three bare-metal Dell workers | RWX block and filesystem | manual fence to 4 of 4 VMs `Running` on other nodes in 79 to 120 s, including a 20 s FAR leader handover |
| Same customer, automatic path (NHC armed, `duration: 300s`) | | not measured yet; by the numbers above, about 6.5 to 7.5 minutes, mostly the `duration` |
| Lab: hosted cluster, external Ceph RBD | RWO | fence to a test pod mounting the volume on another node in 37 s (a pod, not a VM) |

Versions: OpenShift 4.21, NHC 0.11.0, FAR 0.7.0, fence-agents 4.10.

## Order of work

Every node name, BMC IP and account in these files is an example. Edit them before you apply
anything. Every step has a gate; do not move on until it passes.

| Step | What | Gate |
| --- | --- | --- |
| 0 | [`docs/preflight.md`](docs/preflight.md) sections 1 to 9 | every check as described there |
| 1 | `manifests/01-operators.yaml`, or OperatorHub (pick the tiles marked **Red Hat**) | CSVs `Succeeded`, subscriptions from `redhat-operators` |
| 2 | Secret ([preflight 10](docs/preflight.md#10-create-the-credential-secret-then-test-what-is-inside-it)), then `manifests/02-fartemplate-redfish.yaml` | no empty Secret value; `status` with the Secret's own values says `ON` |
| 3 | Drill on one node: [`docs/drill.md`](docs/drill.md) with `manifests/03-drill-far-redfish.yaml` | node powers off, its VMs come back elsewhere; then power on, wait for `Ready`, delete the CR |
| 4 | `manifests/04-nodehealthcheck.yaml` | `oc get nodehealthcheck` says `Enabled` |

The NodeHealthCheck goes last on purpose. Nothing before it fires on its own. If you install
the operators from the console, skip `01`: the console already created an OperatorGroup, and two
OperatorGroups in one namespace break OLM.

The credential Secret is not in this repo and never should be. Create it with the one-liner in the
preflight.

VMs must use `runStrategy: RerunOnFailure`. `Always` also comes back after a fence, but it also
restarts the VM after every shutdown from inside the guest. `Manual` and `Halted` stay down.

## Cluster updates and planned maintenance

**ClusterVersion updates, MCO rollouts and `InPlace` NodePool updates: NHC postpones remediation
on its own.** It checks two signals: a ClusterVersion with `Progressing=True` (postpones
everything), and a node whose `machineconfiguration.openshift.io/currentConfig` differs from
`desiredConfig` (postpones that node). MCO rollouts set those annotations, and so do HyperShift
`InPlace` NodePool updates, only on the nodes being updated, until each one is back. A slow Dell
POST during an update is fine.

**Pause it yourself for everything else:** NodePool updates of type `Replace`, firmware updates
through the BMC, hardware work, manual reboots. Otherwise a node NotReady longer than `duration`
gets powered off mid-job.

```bash
oc patch nodehealthcheck nhc-workers-far --type merge -p '{"spec":{"pauseRequests":["planned-maintenance"]}}'
```

```bash
oc patch nodehealthcheck nhc-workers-far --type json -p '[{"op":"remove","path":"/spec/pauseRequests"}]'
```

A pause blocks new remediations. A fence already in flight keeps going. While NHC postpones for
an update, its `status.phase` still says `Enabled`; the sign is an event:

```bash
oc get events -n default --field-selector reason=RemediationSkipped
```

## The lab files

These reproduce the experiments in the post. They are not part of the production setup.

| File | Experiment |
| --- | --- |
| `lab/rwo-hang.yaml` | two pods fighting over one RWO volume, to watch the `Multi-Attach` hang |
| `lab/runstrategy-vms.yaml` | three VMs, one per `runStrategy`, to see which one a fence brings back |
| `lab/snr-operator.yaml` | Self Node Remediation, only for the two SNR experiments (read its header first) |
| `lab/snr-manual-remediation.yaml` | SNR reboot of one node, the run where the node re-claimed its own volume |
| `lab/nodehealthcheck-snr.yaml` | NHC pointing at SNR, the run where NHC refused to fence a `control-plane`-labeled worker |
| `lab/vmware/fartemplate-vmware.yaml` | FAR template for a lab whose workers are vSphere VMs (`fence_vmware_rest` through vCenter) |
| `lab/vmware/drill-far-vmware.yaml` | the drill CR for that vSphere lab |

Self Node Remediation is left out of the production manifests on purpose. Its agent reboots a
node it believes is isolated even when no NodeHealthCheck points at it, it must not run on
single-node OpenShift, and an upstream issue about a cluster-wide self-reboot storm was open when
this was written. The header of `lab/snr-operator.yaml` has the details.

## Gotchas that cost real time

The post has the full troubleshooting section. The short list:

- **Defaults that bite.** FAR's `remediationStrategy` defaults to `ResourceDeletion` (no taint),
  `fence_redfish` defaults to `reboot`, verifies the BMC certificate, and has no default
  `--systems-uri`. The template sets all four on purpose.
- **An empty Secret value fails with the wrong error.** FAR passes the parameter without a value
  and the agent swallows the next argument: an empty password shows up as
  `You have to set login name`.
- **`status` proves the login, not the right to power off.** `fence_redfish` ignores the HTTP
  status of the power command. Check the account role.
- **`FenceAgentExecuted` means launched, not done.** Success is the condition
  `FenceAgentActionSucceeded=True`. The real error is in the log of the FAR leader pod.
- **FAR stops after its retries** (`FenceAgentFailed`) and does not try again on its own. Fix,
  delete the CR, apply again.
- **FAR removes the `out-of-service` taint only when its CR is deleted.**
- **Cluster-wide proxy:** fencing needs the BMC network in `noProxy`. The image's `curl` ignores
  CIDR entries there; the agent does not.
- **Map nodes to BMCs by service tag**, not by naming convention. A wrong map powers off a healthy
  node.
- **Hosted clusters:** keep NodePool `autoRepair: false` with FAR; the operators run on the same
  workers you fence, so the FAR leader can die with the node (it recovered by itself in 20 s);
  the NodePool lives on the management cluster while NHC and FAR live in the hosted one.
- **In a vSphere lab:** `--api-path=/rest` on vSphere 8, and a login that "stops working" after
  retries is usually a lockout.

Find the FAR leader pod and its node:

```bash
oc get pod -n openshift-workload-availability -o custom-columns=POD:.metadata.name,NODE:.spec.nodeName "$(oc get lease -n openshift-workload-availability -o jsonpath='{range .items[*]}{.spec.holderIdentity}{"\n"}{end}' | grep '^fence-agents' | cut -d_ -f1)"
```

## Verify

```bash
oc get fenceagentsremediationtemplate,fenceagentsremediation -n openshift-workload-availability
oc get nodehealthcheck
oc get events -A --sort-by=.lastTimestamp | grep -iE 'fence|remediation|out-of-service'
```
