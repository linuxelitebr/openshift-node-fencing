# BMC health check: find the dead iDRAC before the dead node does

FAR talks to a BMC only when it fences. An iDRAC that hangs, or that keeps answering but loses
track of its own server, looks perfectly fine until the night a node dies and the fence fails.
Then the VMs stay down and somebody asks why OpenShift did not notice. It could not: nobody asked
the BMC anything.

[`manifests/05-bmc-healthcheck.yaml`](../manifests/05-bmc-healthcheck.yaml) asks. A CronJob reads
the FAR template that is in the cluster, builds each node's fence agent arguments the way FAR
does, and runs the agent with `--action=status` against every BMC, every 10 minutes. When a BMC
stops answering, an alert fires. Optionally, it reboots a BMC that keeps failing.

Both failures it was built for happened at a customer, on Dell iDRAC 9:

| What the iDRAC did | What the check sees | Fixed by an iDRAC reboot? |
| --- | --- | --- |
| Answered, logged in, Redfish up, but `/redfish/v1/Systems` came back empty | `Unable to get PowerState`, exit 1 | yes |
| Accepted the TCP connection and never replied | no answer within the template `timeout` | no: the reboot request never arrives either |

`fence_redfish` prints the same `Unable to get PowerState` for a wrong password and for an empty
`Systems` collection, so neither the check nor FAR can tell them apart. To find out which one it
is, run the [read-only probe](#which-failure-is-it) below.

## What it needs

Nothing new. It runs on the FAR manager image (it already has `fence_redfish`, Python and
`requests`), reads the same Secret FAR reads, and alerts through kube-state-metrics and the
Alertmanager that OpenShift already runs. No Loki, no exporter.

Someone has to evaluate the alert rules:

- **User workload monitoring enabled** (`enableUserWorkload: true` in
  `cluster-monitoring-config`): nothing to do. Its Thanos Ruler picks the rules up in
  `openshift-workload-availability`.
- **User workload monitoring off:** label the namespace and the platform Prometheus takes over.
  User workload monitoring ignores namespaces with that label, so the rules never run twice.
  Without one of the two, the alerts exist and nobody reads them: the check runs, fails, and
  nothing fires. That is not hypothetical, it happened on the first real cluster.

```bash
oc label namespace openshift-workload-availability openshift.io/cluster-monitoring=true
```

`fencing-setup.py` checks which of the two applies. When neither does, the label command shows
up in its next steps, right under the `apply` of 05. It is a separate command on purpose and not
a Namespace object inside 05: `oc delete -f 05-bmc-healthcheck.yaml` would then delete the whole
namespace, operators included.

## Apply

Right after the template (02), before you arm anything.

**1. Apply 05.** The setup script writes `05-bmc-healthcheck.yaml` with the installed FAR image
and your `[healthcheck]` settings:

```bash
oc apply -f generated/<run>/05-bmc-healthcheck.yaml
```

Without the script, apply the file from `manifests/` and point it at your FAR image:

```bash
oc apply -f manifests/05-bmc-healthcheck.yaml
```

```bash
oc set image cronjob/fencing-bmc-healthcheck -n openshift-workload-availability check="$(oc get deploy fence-agents-remediation-controller-manager -n openshift-workload-availability -o jsonpath='{.spec.template.spec.containers[?(@.name=="manager")].image}')"
```

**2. Without user workload monitoring, label the namespace.** Skip this step when user workload
monitoring is enabled. The setup script tells you which case you are in: it prints this command
in its next steps only when it is needed. Without it, the alert rules exist and nothing evaluates
them. The label starts no pod: it makes the platform Prometheus, already running in
`openshift-monitoring`, read the rules in this namespace.

```bash
oc label namespace openshift-workload-availability openshift.io/cluster-monitoring=true
```

**3. Check that the alert rules are loaded**, by whichever Prometheus applies. Three names must
come back, about half a minute after step 1 or 2. With the namespace label (platform Prometheus):

```bash
oc exec -n openshift-monitoring prometheus-k8s-0 -c prometheus -- curl -s localhost:9090/api/v1/rules | grep -o 'FencingBMC[A-Za-z]*' | sort -u
```

With user workload monitoring:

```bash
oc exec -n openshift-user-workload-monitoring thanos-ruler-user-workload-0 -c thanos-ruler -- sh -c 'curl -s localhost:10902/api/v1/rules' | grep -o 'FencingBMC[A-Za-z]*' | sort -u
```

In the console they are under **Observe > Alerting > Alerting rules**, with source **Platform**
or **User** respectively. The default filter may hide one of the two.

**4. Run it once now** instead of waiting for the schedule:

```bash
oc create job bmc-check-now -n openshift-workload-availability --from=cronjob/fencing-bmc-healthcheck
```

```bash
oc logs -n openshift-workload-availability job/bmc-check-now | grep FENCING-BMC-CHECK
```

```
FENCING-BMC-CHECK: OK node=worker-0.example.com bmc=10.10.0.10 detail=power=On/0.4s
FENCING-BMC-CHECK: OK node=worker-1.example.com bmc=10.10.0.11 detail=power=On/0.3s
FENCING-BMC-CHECK: OK node=worker-2.example.com bmc=10.10.0.12 detail=power=On/0.5s
FENCING-BMC-CHECK: SUMMARY template=fartemplate-redfish bmcs=3 failed=0 auto_reset=false
```

A Job created by hand does not count as a CronJob success for the alert; the next scheduled run
does.

## What fails a run

- a BMC that errors, times out or refuses the login
- a BMC that says the server is `Off` while its node is `Ready`: that BMC belongs to another
  server, and a fence through it would power off the wrong one
- a worker with no BMC in the template (set `WORKER_SELECTOR` to `""` to skip this check)
- the template or its Secret missing, or a template stored without `sharedSecretName`

All BMCs are checked in parallel, so a run takes as long as the slowest BMC (at most the template
`timeout`), not the sum.

## Alerts

| Alert | Fires when | Clears when |
| --- | --- | --- |
| `FencingBMCHealthCheckFailing` (critical) | no good run for 25 minutes | the next good run |
| `FencingBMCHealthCheckNeverSucceeded` (warning) | the CronJob is missing or never passed, for 30 minutes | the first good run |
| `FencingBMCAutoReset` (warning) | the check rebooted a BMC | that BMC passes a check again |

The first one also fires when the check itself stops running, which is the failure nobody
notices on their own. The rules follow the platform's own style (`job="kube-state-metrics"`
matchers, a time-since rule like `KubeJobNotCompleted`).

Each Job is deleted 14 minutes after it ends. That is on purpose: the platform's generic
`KubeJobFailed` alert watches failed Jobs in every `openshift-*` namespace for 15 minutes and
stays on while the Job object exists. Without the cleanup, one bad night would leave it firing
after the BMC is long fixed.

## Automatic BMC reboot

Off by default. With `AUTO_RESET=true` (`auto_reset = true` in `[healthcheck]`), a BMC that fails
`RESET_AFTER` runs in a row (5 by default, about 50 minutes) gets a Redfish `Manager.Reset`. The
management controller restarts; the server keeps running.

How it finds the reset, on any Redfish BMC:

1. `GET /redfish/v1/Managers` and take the first manager
2. read `Actions["#Manager.Reset"]` from it: the `target` and the allowed `ResetType` values
3. `POST` `{"ResetType": "GracefulRestart"}` to the target (or the first allowed type)

On iDRAC 9 that is `POST /redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset`, the same
as **Maintenance > Diagnostics > Reboot iDRAC** in the web UI, and `GracefulRestart` is the only
type it offers.

Guard rails:

- never while a FenceAgentsRemediation exists for that node
- at most one BMC per run, at most one reset per BMC every `RESET_COOLDOWN_HOURS` (6); a failed
  attempt also waits for the cooldown
- the account in the FAR Secret must be allowed to restart the BMC (`ConfigureManager` in Redfish
  terms; the iDRAC `Operator` role does not have it, `Administrator` does)

Every reset fires `FencingBMCAutoReset` and logs a `RESET` line. A BMC that needs this every
week has a firmware or hardware problem: compare its firmware with the healthy ones and open a
ticket. The reboot buys you fencing tonight, not a fixed iDRAC.

While an iDRAC reboots (two to three minutes) its node cannot be fenced. If the node dies in
exactly that window, FAR's retries (5 x 95 s) outlast it.

| Setting (CronJob env) | Default | |
| --- | --- | --- |
| `AUTO_RESET` | `false` | reboot a BMC that keeps failing |
| `RESET_AFTER` | `5` | failed runs in a row before the reboot |
| `RESET_COOLDOWN_HOURS` | `6` | minimum time between reboots of the same BMC |
| `WORKER_SELECTOR` | `node-role.kubernetes.io/worker` | nodes that must have a BMC in the template |
| `PARALLEL` | `8` | BMCs checked at the same time |

The failure counter lives in the ConfigMap `fencing-bmc-healthcheck-state`; each reset marker is
a ConfigMap `fencing-bmc-reset-<node>`, which the alert watches.

## Test it on real hardware without breaking an iDRAC

First, read-only: check that the iDRAC offers the reset and with which types. Replace the IP:

```bash
read -rs -p 'BMC password: ' P; echo; printf '%s\n' "$P" | oc exec -i -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- python3 -c '
import sys,requests,urllib3
urllib3.disable_warnings()
pw=sys.stdin.readline().strip(); ip="10.10.0.10"
s=requests.Session(); s.auth=("fencing",pw); s.verify=False; s.headers.update({"accept":"application/json","OData-Version":"4.0"})
m=s.get("https://%s/redfish/v1/Managers"%ip,timeout=(5,25)).json()["Members"][0]["@odata.id"]
a=s.get("https://%s%s"%(ip,m),timeout=(5,25)).json().get("Actions",{}).get("#Manager.Reset",{})
print("manager:",m); print("target:",a.get("target")); print("types:",a.get("ResetType@Redfish.AllowableValues"))
'; unset P
```

```
manager: /redfish/v1/Managers/iDRAC.Embedded.1
target: /redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset
types: ['GracefulRestart']
```

Use the BMC IP, not its host name: with a cluster-wide proxy, an IP inside `noProxy` goes
direct, a host name that is not in it goes to the corporate proxy.

Then the full path, on a test cluster or with the NodeHealthCheck paused: make one node fail the
check while its IP and password stay real. A node parameter wins over the shared one, so give
that node a Redfish URI that does not exist:

**1. Break one node's check.** It now gets a 404, like an iDRAC with an empty `Systems`
collection:

```bash
oc patch fenceagentsremediationtemplate fartemplate-redfish -n openshift-workload-availability --type merge -p '{"spec":{"template":{"spec":{"nodeparameters":{"--systems-uri":{"worker-0.example.com":"/redfish/v1/Systems/Does.Not.Exist"}}}}}}'
```

**2. Make the test short.** Reboot after 2 failed runs, run every 3 minutes:

```bash
oc set env cronjob/fencing-bmc-healthcheck -n openshift-workload-availability AUTO_RESET=true RESET_AFTER=2
```

```bash
oc patch cronjob fencing-bmc-healthcheck -n openshift-workload-availability --type merge -p '{"spec":{"schedule":"*/3 * * * *"}}'
```

**3. Watch.** The second run sends the reset to the real iDRAC and `FencingBMCAutoReset` shows
up in the Alertmanager:

```bash
oc logs -n openshift-workload-availability -l job-name --tail=20 --prefix | grep FENCING-BMC-CHECK
```

That node keeps failing afterwards (the URI is still wrong), and the cooldown keeps it from
being rebooted again.

**4. Put everything back.** Remove the node override, then reapply 05 (or the generated copy) to
restore the schedule and the settings:

```bash
oc patch fenceagentsremediationtemplate fartemplate-redfish -n openshift-workload-availability --type json -p '[{"op":"remove","path":"/spec/template/spec/nodeparameters/--systems-uri"}]'
```

```bash
oc apply -f generated/<run>/05-bmc-healthcheck.yaml
```

The next good run of that node clears the alert. To start the counters from zero, delete the
state ConfigMap:

```bash
oc delete configmap fencing-bmc-healthcheck-state -n openshift-workload-availability
```

## Test it without hardware

[`lab/bmc-stub.yaml`](../lab/bmc-stub.yaml) is a fake Redfish BMC with five behaviours (healthy,
powered off, empty `Systems` that recovers after a reset, hung, wrong password). Point a test
template's node IPs at its Services, keep it away from any NodeHealthCheck, and the CronJob runs
against it. What it showed in my lab, with `RESET_AFTER=2` and a 3-minute schedule:

| Time (UTC) | Event |
| --- | --- |
| 15:12, 15:15 | two failed runs (empty `Systems`) |
| 15:16:39 | `RESET`: `Manager.Reset GracefulRestart` accepted (HTTP 204) |
| 15:17:23 | `FencingBMCAutoReset` active in the Alertmanager |
| 15:20:13 | the BMC passes again, marker deleted |
| 15:21:39 | alert resolved |

The hung BMC in the same run got `RESET-FAILED` (read timeout) and then `RESET-SKIPPED` for the
cooldown, which is the point: a reset cannot save a BMC that does not answer.

## FAR's own validation (FAR 0.7.0 and later)

The template can also ask FAR to run `status` against every node once:
`spec.statusValidationSample: "100%"`. FAR does it when the template is created or changed and
writes the result into the template status. The setup script turns it on when the installed FAR
supports it.

```bash
oc get fenceagentsremediationtemplate fartemplate-redfish -n openshift-workload-availability -o jsonpath='{.status.conditions[?(@.type=="FenceAgentStatusValidationSucceeded")].message}{"\n"}{.status.validationFailed}{"\n"}'
```

It is a good check at apply time and nothing more: it never runs again until the spec changes,
and it uses a fixed 15-second timeout, so a slow but working iDRAC can show up there as failed
and still fence fine. The CronJob uses the template `timeout`, the same budget a real fence gets.

## Which failure is it?

Read-only, from inside the FAR pod (same network path and proxy as the fence). It reads the
service root, the `Systems` collection and the system itself on the broken BMC and on a healthy
one. Replace both IPs:

```bash
read -rs -p 'BMC password: ' P; echo; printf '%s\n' "$P" | oc exec -i -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- python3 -c '
import sys,requests,urllib3
urllib3.disable_warnings()
pw=sys.stdin.readline().strip()
for ip,label in [("10.10.0.11","broken"),("10.10.0.10","healthy")]:
  print("==",label,ip)
  for path in ["/redfish/v1/","/redfish/v1/Systems","/redfish/v1/Systems/System.Embedded.1"]:
    try:
      r=requests.get("https://%s%s"%(ip,path),auth=("fencing",pw),headers={"accept":"application/json","OData-Version":"4.0"},verify=False,timeout=(5,25))
      j=r.json() if r.headers.get("content-type","").startswith("application/json") else {}
      extra=[m.get("@odata.id") for m in j.get("Members",[])] if path.endswith("Systems") else (j.get("Product"),j.get("RedfishVersion")) if path.endswith("v1/") else j.get("PowerState")
      print("  ",path,r.status_code,extra)
    except Exception as e:
      print("  ",path,"ERR",str(e)[:100])
'; unset P
```

How to read it:

- `401` everywhere: wrong password or locked account.
- service root `200` with the vendor's product name, `Systems` `200 []`, system `404`: the BMC lost
  its server inventory. An iDRAC reboot fixed it at the customer.
- a timeout on every path: the BMC is hung. A reboot through Redfish cannot reach it; it needs
  the web UI, the chassis manager (OME-Modular on an MX chassis), or someone at the server.
- a product name that is not your BMC: the IP points at another device. Check the map (preflight
  section 8).

## Remove it

```bash
oc delete -f manifests/05-bmc-healthcheck.yaml
```

```bash
oc delete configmap fencing-bmc-healthcheck-state -n openshift-workload-availability --ignore-not-found
```

```bash
oc delete configmap -n openshift-workload-availability -l fencing-bmc-healthcheck/reset=true
```
