# Drill: fence one node by hand before you arm anything

The drill powers a node off with a FenceAgentsRemediation you create yourself, so you watch the
whole fence path (BMC, taint, pods, VMs) with nobody else's automation in the way. Do it in an
agreed window, after [`preflight.md`](preflight.md) passed, and before you apply
`manifests/04-nodehealthcheck.yaml`. If the manual fence does not work, the automatic one will not
either.

Run the one-liners in bash. On macOS, start `bash` first.

If a NodeHealthCheck already covers these nodes (a repeat drill, or a cluster set up before),
pause it for the whole drill window. The drilled node stays NotReady longer than `duration`, and
NHC would start its own remediation of the node you just powered off:

```bash
oc patch nodehealthcheck nhc-workers-far --type merge -p '{"spec":{"pauseRequests":["fencing-drill"]}}'
```

Resume it after step 6, once the node is `Ready` and the drill CR is gone:

```bash
oc patch nodehealthcheck nhc-workers-far --type json -p '[{"op":"remove","path":"/spec/pauseRequests"}]'
```

## 1. Pick the node and check the room

Prefer the node with the fewest critical VMs, and make sure the others can absorb them:

```bash
oc get vmi -A -o wide | grep worker-0.example.com
```

```bash
oc describe nodes | grep -A 7 'Allocated resources'
```

Look at memory requests. OpenShift Virtualization requests only a fraction of each VM's vCPUs by
default, so CPU requests understate the real demand. Memory is the hard limit.

## 2. Find the FAR leader

FAR runs two replicas and only the leader executes the fence agent. On a hosted cluster the
operators run on the same workers you fence:

```bash
oc get pod -n openshift-workload-availability -o custom-columns=POD:.metadata.name,NODE:.spec.nodeName "$(oc get lease -n openshift-workload-availability -o jsonpath='{range .items[*]}{.spec.holderIdentity}{"\n"}{end}' | grep '^fence-agents' | cut -d_ -f1)"
```

If the leader is on the node you fence, FAR still finishes: the leader dies with the node, the
other replica takes the lease and runs the agent again, and powering off a node that is already
off returns success. In the customer drill that cost 20 seconds. Note the pod either way: its log
is where FAR's real errors land.

## 3. Record a timeline

In a second terminal. About every 6 seconds it prints the UTC time, the node state, the FAR
result, how many VMIs sit on that node and how many run cluster-wide:

```bash
N=worker-0.example.com; while true; do echo "$(date -u +%T) node=$(oc get node $N --no-headers | awk '{print $2}') far=$(oc get fenceagentsremediation $N -n openshift-workload-availability -o jsonpath='{.status.conditions[?(@.type=="Succeeded")].status}' 2>/dev/null) vmis_on_node=$(oc get vmi -A -o wide --no-headers | grep -c $N) vmis_running=$(oc get vmi -A --no-headers | grep -c Running)"; sleep 5; done | tee drill-$(date -u +%Y%m%d-%H%M).log
```

## 4. Fence it

Edit the node name and BMC IP in the file first. Applying it powers the node off right away
(Redfish `ForceOff`):

```bash
oc apply -f manifests/03-drill-far-redfish.yaml
```

## 5. Watch

The event `FenceAgentExecuted` only means the agent was launched. Success is the condition
`FenceAgentActionSucceeded=True` and the event `FenceAgentSucceeded`, followed by
`AddOutOfServiceTaint`.

```bash
oc get events -A --sort-by=.lastTimestamp | grep -iE 'fence|out-of-service|multi-attach|remediation' | tail -30
```

```bash
oc get fenceagentsremediation worker-0.example.com -n openshift-workload-availability -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason} {.message}{"\n"}{end}'
```

If the node stays on, read the leader's log (step 2):

```bash
oc logs -n openshift-workload-availability <far-leader-pod> -c manager --since=1h | grep -iE 'command failed|fence agent done'
```

After its retries (5 by default) FAR records `FenceAgentFailed` and stops. It does not try again
on its own: fix the cause, delete the CR, apply again.

What it looked like on the customer's Dell hardware, with the FAR leader on the fenced node:

| Since start | Event |
| --- | --- |
| 0 s | FAR CR created; the node powers off, taking the FAR leader with it |
| +20 s | the FAR lease moves to the other replica, which runs the agent again |
| +21 s | `FenceAgentSucceeded`, `AddOutOfServiceTaint` |
| +46 to +48 s | the node is marked `NotReady` |
| +48 s | all 4 VMIs recreated on other nodes |
| +79 to +120 s | all 4 VMs `Running` |

The VMs wait for `NotReady`, not for the taint: the pod garbage collector force-deletes the pods
of a node only when it is NotReady and has the `out-of-service` taint. Each VMI keeps its own
phase timestamps:

```bash
oc get vmi -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.status.nodeName} {range .status.phaseTransitionTimestamps[*]}{.phase}@{.phaseTransitionTimestamp} {end}{"\n"}{end}'
```

## 6. Power the node back on, wait for Ready, then delete the CR

FAR with `--action off` leaves the node off on purpose. Paste only this line and type the
password at the prompt:

```bash
read -rs -p 'BMC password: ' P; echo; if [ -z "$P" ]; then echo 'ERROR: empty password, nothing done'; else printf 'ip=10.10.0.10\nusername=fencing\npassword=%s\nssl_insecure=1\nsystems_uri=/redfish/v1/Systems/System.Embedded.1\naction=on\n' "$P" | oc exec -i -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- fence_redfish; fi; unset P
```

```
Success: Powered ON
```

A big server can take several minutes in POST. When the node is `Ready`, delete the CR. FAR
removes the `out-of-service` taint only then, which is also what NHC does on its own later:

```bash
oc delete fenceagentsremediation worker-0.example.com -n openshift-workload-availability
```

```bash
oc get node worker-0.example.com -o jsonpath='{.spec.taints}{"\n"}'
```

The output must not list `node.kubernetes.io/out-of-service` or
`remediation.medik8s.io/fence-agents-remediation`.

## 7. Only now, arm the health check

```bash
oc apply -f manifests/04-nodehealthcheck.yaml
```

```bash
oc get nodehealthcheck nhc-workers-far -o jsonpath='{.status.phase}{" "}{.status.reason}{"\n"}'
```

```
Enabled NHC is enabled, no ongoing remediation
```
