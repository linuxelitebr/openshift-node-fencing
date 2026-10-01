# Preflight: prove the fence path before you arm anything

Everything here is read-only except section 10, which creates the credential Secret. Run it top
to bottom before applying `manifests/02-*`. Each section says what you should see; if you see
something else, stop and fix it, because every item below is a way fencing fails silently on the
day you need it.

Outputs shown are real, from a hosted cluster with three bare-metal Dell workers (and, for the
vSphere variant at the end, from a lab), with names, IPs and service tags replaced.

Three rules for the commands that need a password:

- **The password never goes on a command line.** It is read with `read -s` (or Python
  `getpass`) and fed to `oc` or the fence agent through stdin, so it stays out of your shell
  history and out of the process list.
- **Paste one line at a time.** While `read` waits for the password, any line you paste after it
  becomes the password.
- **Run them in bash.** On macOS, start `bash` first: in zsh, `read -p` means something else, and
  the guard would answer "empty password".

## 1. Cluster shape

```bash
oc get clusterversion version -o jsonpath='{.status.desired.version}{"\n"}'
```

```bash
oc get infrastructure cluster -o jsonpath='{.status.platform} {.status.controlPlaneTopology}{"\n"}'
```

```
None External
```

`External` means a hosted cluster: the control plane runs on a management cluster, so fencing a
worker can never touch etcd. Do section 2. `HighlyAvailable` is a standard cluster: skip it.

```bash
oc get nodes -L node-role.kubernetes.io/control-plane,node-role.kubernetes.io/worker
```

The nodes you want fenced should not carry the `node-role.kubernetes.io/control-plane` label.
NodeHealthCheck treats nodes with that label as control plane and runs an etcd quorum guard on
them. The hosted lab in the post had the label on every worker on purpose (to place OpenShift
Virtualization components there), etcd was not even on those nodes, and NHC still answered
`Skipping remediation ... for preventing control plane / etcd quorum loss`. Automatic fencing
never fired there.

## 2. Hosted clusters only (run on the management cluster)

The NodePool and anything else that remediates these nodes live on the management cluster, not
in the hosted one. Check where you are before running anything:

```bash
oc whoami --show-server
```

```bash
oc get nodepool -A
```

```bash
oc get nodepool hosted-lab -n clusters -o jsonpath='{.spec.management}{"\n"}'
```

```
{"autoRepair":false,"replace":{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0},"strategy":"RollingUpdate"},"upgradeType":"InPlace"}
```

- `autoRepair` must be `false`. With `true`, HyperShift creates a MachineHealthCheck that replaces
  the Machine of a node NotReady for 16 minutes (Agent and None platforms; 8 minutes on the
  others). That is a second remediator acting on the node FAR just powered off.
- `upgradeType: InPlace` is covered by NodeHealthCheck's update detection. `Replace` is not:
  pause NHC during NodePool updates (README). The `replace` block above is ignored when the type
  is `InPlace`.

```bash
oc get bmh -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,ONLINE:.spec.online,BMC:.spec.bmc.address
```

Empty is what you want. A BareMetalHost for these nodes means the Bare Metal Operator also holds
their BMC credentials and a desired power state (`spec.online`). Settle who owns the power
button before letting FAR switch anything off.

Switch back to the hosted cluster for the rest of this file.

## 3. Operators from the Red Hat catalog

```bash
oc get packagemanifests -n openshift-marketplace -l catalog=redhat-operators -o custom-columns=PKG:.metadata.name,CSV:.status.channels[*].currentCSV | grep -E 'node-healthcheck|fence-agents|self-node'
```

```
node-healthcheck-operator    node-healthcheck-operator.v0.11.0
fence-agents-remediation     fence-agents-remediation.v0.7.0
self-node-remediation        self-node-remediation.v0.12.1
```

That is OpenShift 4.21. The community catalog has packages with the same names and newer
versions, and OperatorHub shows both tiles. After installing, confirm the source:

```bash
oc get subscription -n openshift-workload-availability -o custom-columns=NAME:.metadata.name,SOURCE:.spec.source,CSV:.status.installedCSV
```

`SOURCE` must be `redhat-operators`.

## 4. Storage and capacity

```bash
oc get pvc -A -o jsonpath='{range .items[*]}{.spec.storageClassName}{" "}{.spec.accessModes[0]}{" "}{.spec.volumeMode}{"\n"}{end}' | sort | uniq -c
```

```bash
oc get csidriver -o custom-columns=NAME:.metadata.name,ATTACH:.spec.attachRequired
```

RWO volumes are where a dead node hurts first (`Multi-Attach error`). RWX volumes do not block
the new pod, but they also do not stop a second writer: a VM must never run twice, and the
power-off is what guarantees it. `ATTACH true` means the driver uses VolumeAttachments, which is
what the out-of-service taint force-detaches.

```bash
oc describe nodes | grep -A 7 'Allocated resources'
```

Fencing restarts the VMs of one node on the others. Add up memory requests: the nodes that remain
must hold them. OpenShift Virtualization requests only a fraction of each VM's vCPUs by default,
so CPU requests understate real demand; memory is the hard limit.

## 5. VM runStrategy

```bash
oc get vm -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,RUNSTRATEGY:.spec.runStrategy,RUNNING:.spec.running
```

VMs that must come back after a fence need `RerunOnFailure` (or `Always`). `Manual` and `Halted`
stay down. `RerunOnFailure` is the one to use: a fenced VM counts as a failure and is restarted,
and a clean guest shutdown still stays off. If `RUNNING` is set, the VM uses the legacy
`spec.running` field, which is mutually exclusive with `runStrategy`.

When you change `runStrategy` on running VMs, check on the first few that the VMI was not
recreated (same `metadata.creationTimestamp` before and after).

## 6. Cluster-wide proxy

FAR inherits the cluster proxy settings (OLM injects them into operator deployments). Look:

```bash
oc exec -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- sh -c 'env | grep -i _proxy || echo none'
```

If there is a proxy, `NO_PROXY` must cover your BMC network, or every fence goes through the
corporate proxy (and fails with it). The fence agents use Python `requests`, which understands
CIDR entries like `10.0.0.0/8`. The `curl` in the FAR image (7.76.1) does not: CIDR support in
`NO_PROXY` arrived in curl 7.86.0. So a plain `curl` test from that pod goes through the proxy
and fails (exit code 56) while the agent works. Always pass `--noproxy '*'` to curl there.

## 7. Reach every BMC from every FAR replica

FAR runs two replicas and the leader can be on any worker. Test from each, against each BMC. The
Redfish service root needs no login:

```bash
for p in $(oc get pod -n openshift-workload-availability -l app.kubernetes.io/name=fence-agents-remediation-operator -o name); do for ip in 10.10.0.10 10.10.0.11 10.10.0.12; do echo "$p node=$(oc get $p -n openshift-workload-availability -o jsonpath='{.spec.nodeName}') bmc=$ip http=$(oc exec -n openshift-workload-availability $p -c manager -- curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 10 https://$ip/redfish/v1/ 2>/dev/null)"; done; done
```

Every line must end in `http=200`. `000` means no connection from that node.

## 8. Map every node to its BMC by service tag

This is the check that keeps FAR from powering off a healthy node. The `status` action proves a
login works, not that the BMC belongs to the node you think. Read the serial on the node side:

```bash
oc debug node/worker-0.example.com -- chroot /host cat /sys/class/dmi/id/product_serial
```

```
DELL001
```

Repeat for every node. Then read it on the BMC side. Python `getpass` asks for the password
without echo:

```bash
oc exec -it -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- python3 -c "
import requests, getpass, urllib3
urllib3.disable_warnings()
p = getpass.getpass('BMC password: ')
for ip in ('10.10.0.10', '10.10.0.11', '10.10.0.12'):
    r = requests.get('https://%s/redfish/v1/Systems/System.Embedded.1' % ip, auth=('fencing', p), verify=False, timeout=15)
    j = r.json() if r.ok else {}
    print(ip, r.status_code, j.get('SKU'), j.get('HostName'), j.get('PowerState'))
"
```

```
10.10.0.10 200 DELL001 worker-0.example.com On
10.10.0.11 200 DELL002 worker-1.example.com On
10.10.0.12 200 DELL003 worker-2.example.com On
```

On Dell, `SKU` is the service tag. Each BMC must show the serial of the node it is mapped to in
the template. A `401` on all of them is the password. Do not retry in a loop: a typo counts as a
failed login, BMCs can lock the account or block the source, and these requests leave with the
node's IP, which is the same path fencing uses.

## 9. The BMC account can power-cycle

`status` only reads. `fence_redfish` does not check the HTTP status of the power command it
sends, so an account without power privileges passes every read test and fails only when it
has to fence for real. Read the account's role:

```bash
oc exec -it -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- python3 -c "
import requests, getpass, urllib3
urllib3.disable_warnings()
p = getpass.getpass('BMC password: ')
h = {'accept': 'application/json'}
for ip in ('10.10.0.10', '10.10.0.11', '10.10.0.12'):
    base = 'https://%s' % ip
    col = requests.get(base + '/redfish/v1/AccountService/Accounts', headers=h, auth=('fencing', p), verify=False, timeout=15)
    found = False
    for m in (col.json().get('Members', []) if col.ok else []):
        a = requests.get(base + m['@odata.id'], headers=h, auth=('fencing', p), verify=False, timeout=15).json()
        if a.get('UserName') == 'fencing':
            found = True
            print(ip, 'RoleId=%s' % a.get('RoleId'), 'Enabled=%s' % a.get('Enabled'), 'Locked=%s' % a.get('Locked'))
    if not found:
        print(ip, 'HTTP %s listing accounts' % col.status_code)
"
```

```
10.10.0.10 RoleId=Operator Enabled=True Locked=False
10.10.0.11 RoleId=Operator Enabled=True Locked=False
10.10.0.12 RoleId=Operator Enabled=True Locked=False
```

`Operator` is what powered a node off in the drill. Anything else, check it before you trust it.

## 10. Create the credential Secret, then test what is inside it

Paste only this line, press Enter, then type the password at the prompt. It creates the Secret
or updates it if it exists, shows any `oc` error as is, and refuses an empty password. The YAML
with the password goes through the pipe straight to `oc apply`, never to the screen:

```bash
read -rs -p 'BMC password: ' P; echo; if [ -z "$P" ]; then echo 'ERROR: empty password, nothing done'; else printf '%s' "$P" | oc create secret generic fence-agents-credentials-shared -n openshift-workload-availability --from-literal=--username=fencing --from-file=--password=/dev/stdin --dry-run=client -o yaml | oc apply -f -; fi; unset P
```

Check that no value is empty. This prints only the length of each value, in base64: any non-zero
number is fine, `0` means empty.

```bash
oc get secret fence-agents-credentials-shared -n openshift-workload-availability -o go-template='{{range $k, $v := .data}}{{$k}} {{len $v}}{{"\n"}}{{end}}'
```

```
--password 24
--username 12
```

A `0` here is the most confusing failure in this whole setup. FAR passes each parameter as
`--name=value`, but an empty value goes out as a bare `--name`, and the agent then swallows the
NEXT argument as that value. An empty password in front of `--username=fencing` produces
`Failed: You have to set login name`, with a username that is fine. The argument order comes from
a Go map, so the same broken Secret can fail differently on the next attempt.

Now test the Secret's own values with the agent, read-only. This is the test that matters,
because it uses what FAR will use, not what you typed:

```bash
printf 'ip=10.10.0.10\nusername=%s\npassword=%s\nssl_insecure=1\nsystems_uri=/redfish/v1/Systems/System.Embedded.1\naction=status\n' "$(oc get secret fence-agents-credentials-shared -n openshift-workload-availability -o go-template='{{index .data "--username" | base64decode}}')" "$(oc get secret fence-agents-credentials-shared -n openshift-workload-availability -o go-template='{{index .data "--password" | base64decode}}')" | oc exec -i -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- fence_redfish
```

```
Status: ON
```

### vSphere variant (lab only)

For a lab whose workers are vSphere VMs, with the files in `lab/vmware/`. Same Secret one-liner
with the vCenter account (`--from-literal=--username=svc-fencing@vsphere.local`). List
the VM names that go into `--plug`, then check one, both read-only:

```bash
read -rs -p 'vCenter password: ' P; echo; if [ -z "$P" ]; then echo 'ERROR: empty password, nothing done'; else printf 'ip=vcenter.example.com\nusername=svc-fencing@vsphere.local\npassword=%s\nssl_insecure=1\napi_path=/rest\naction=list\n' "$P" | oc exec -i -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- fence_vmware_rest; fi; unset P
```

On vSphere 8, keep `api_path=/rest`. fence-agents 4.10 misreads the newer `/api` session reply
and fails with `Failed: 'value'` even though the login worked. If a vCenter login "stops working"
after a few tries, suspect the account lockout before the password.

## Powering a node back on

FAR with `--action off` leaves the node off on purpose. Same pattern, `action=on`:

```bash
read -rs -p 'BMC password: ' P; echo; if [ -z "$P" ]; then echo 'ERROR: empty password, nothing done'; else printf 'ip=10.10.0.10\nusername=fencing\npassword=%s\nssl_insecure=1\nsystems_uri=/redfish/v1/Systems/System.Embedded.1\naction=on\n' "$P" | oc exec -i -n openshift-workload-availability deploy/fence-agents-remediation-controller-manager -c manager -- fence_redfish; fi; unset P
```

```
Success: Powered ON
```
