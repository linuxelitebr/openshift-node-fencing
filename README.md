# OpenShift Virtualization node fencing

Companion manifests for the post *"Kill a Node in OpenShift Virtualization and the VM
Never Comes Back. Here's the Fence That Fixes It."* on [linuxelite.com.br](https://linuxelite.com.br).

The short version: when a bare-metal node running OpenShift Virtualization dies, your VMs
do not come back on their own. A `ReadWriteOnce` volume cannot move until the cluster is
certain the dead node let go of it, and without fencing there is no such certainty, so it
waits. On OpenShift 4.21 it waits forever. This repo is the fix: three Red Hat Workload
Availability operators wired to detect a dead node, power it off for real, and force the
volume loose so the VM restarts somewhere healthy.

Every file is `oc apply -f` ready. Replace the redacted passwords and the node, VM, and IP
names with your own. Nothing here is a custom controller. It is operators, a Secret, a
template, and a health check.

## What you deploy

Apply these in order. Wait for the three CSVs to reach `Succeeded` after step 1.


| File | What it is |
| --- | --- |
| `manifests/01-operators.yaml` | Namespace, OperatorGroup, and subscriptions for NHC, FAR, and SNR. |
| `manifests/02-fence-config-vmware.yaml` | Secret plus FAR template for a vSphere lab (`fence_vmware_rest`). |
| `manifests/02b-fence-config-redfish-idrac.yaml` | Same, for real Dell iDRAC (`fence_redfish`). Pick one. |
| `manifests/03-nodehealthcheck.yaml` | The armed NodeHealthCheck. This is the hands-off production piece. |


## What you use to test and measure


| File | What it is |
| --- | --- |
| `manifests/04-manual-remediation.yaml` | Fence one node on demand, without arming NHC. A FAR CR (real power-off) or an SNR CR (watchdog). |
| `manifests/05-nodehealthcheck-snr.yaml` | Armed NHC pointed at SNR, for the auto-detection demo with no BMC. |
| `manifests/06-lab-rwo-hang.yaml` | Two pods fighting over one RWO volume, to reproduce the Multi-Attach hang. |
| `manifests/07-lab-runstrategy-vms.yaml` | Three fedora VMs, one per `runStrategy`, to see which one a fence brings back. |


## The commands that are not YAML

Always validate the fence agent read-only before you let it near a power button. This
queries power state and changes nothing:

```sh
oc exec -n openshift-workload-availability <far-pod> -i -- fence_vmware_rest <<EOF
ip=vcenter.example.com
username=svc-fencing@vsphere.local
password=<VCENTER_PASSWORD>
ssl_insecure=1
api_path=/rest
plug=worker-0
action=status
EOF
```

FAR with `--action off` leaves the node powered off on purpose, so you bring it back by
hand. Same block, `action=on`.

## Gotchas that cost real time

- The `OutOfServiceTaint` fixes the Kubernetes attach and detach layer, but with external
  Ceph RBD the node has to be genuinely dead for the volume lock to release. Use `--action
  off`, not reboot. A node that reboots fast rejoins mid-failover and re-grabs its own dead
  volume. Ask me how I know.
- vSphere 8: use `--api-path=/rest`. fence-agents 4.10 mis-parses the newer `/api` session
  reply and fails with `Failed: 'value'` even though the login succeeded. `/rest` still works.
- NodeHealthCheck will not fence a node carrying the `node-role.kubernetes.io/control-plane`
  label, even on a hosted cluster where etcd is external and quorum is never at risk. Real
  dedicated workers labeled `worker` fence fine. Check your labels before you trust auto-fence.
- Put VMs on `runStrategy: RerunOnFailure`. It recovers from a fence and still lets people
  power a VM off. `Always` recreates on any stop, which is the "can't power it off" complaint.

## Verify

```sh
oc get fenceagentsremediation -A
oc get nodehealthcheck
oc get events -A | grep '\[remediation\]'
oc get volumeattachment
```
