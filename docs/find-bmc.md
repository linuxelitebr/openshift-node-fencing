# find-bmc.py: the node whose iDRAC IP nobody knows

Every fleet has one. The spreadsheet says one thing, DNS another, and the person who racked the
server left two years ago. Fencing needs that IP, and it needs the right one: a wrong map powers
off a healthy node.

The node cannot tell you. `dmidecode` describes the internal interface to the BMC, not its network
address, and RHCOS ships no `ipmitool` (neither does the `support-tools` image, nor the UBI
repositories). Asking the BMC through the host would mean kernel modules and a privileged image
from outside Red Hat on a production node.

So ask the other way around. The server's serial (the service tag, on Dell) is written in two
places: in the node's firmware and in its BMC. `scripts/find-bmc.py` sweeps the BMC network for
Redfish, reads the serial behind each BMC it finds, and tells you which one matches.

The one-liner this script grew from found the iDRAC of exactly such a node at a customer. The
script itself was tested against the lab stub (below), not yet on a real BMC network.

## What it does

From inside the FAR pod, the same network path fencing uses:

1. an anonymous request to the Redfish service root of every address in the networks you give
   (a BMC answers it without a login; anything else is skipped)
2. one login per BMC that answered, to read the serial, model and host name of its server
3. a BMC that refuses the login is reported and not tried again

It never logs in blindly, never changes anything, and the password only travels through stdin.
Still, a sweep of a whole network looks like a scan to an IDS. Agree on it with the network team
before you run it.

By default it keeps Dell (iDRAC) and Lenovo (XClarity Controller) BMCs, recognized by the
`Product`, `Vendor` or `Oem` fields of the service root (an XCC leaves `Product` out).
`--any-vendor` keeps every Redfish BMC. The Lenovo detection is checked against the formats
Redfish allows, not yet against a real XCC sweep: if a sweep keeps none of your XCCs, add
`--any-vendor`.

## Find one node's BMC

**1. The node's serial:**

```bash
oc debug node/worker-3.example.com --quiet -- chroot /host cat /sys/class/dmi/id/product_serial
```

**2. Sweep the BMC network for it.** `--network` takes a CIDR or a single address and can be
repeated (at most 4096 addresses per run):

```bash
python3 scripts/find-bmc.py --username fencing --network 10.10.0.0/24 --service-tag ABC1234
```

The output looks like this (example addresses and serials):

```
10 addresses answered Redfish, 8 BMCs kept

BMC             SERIAL       SERVER               HOSTNAME (from the BMC)      NOTE
10.10.0.10      ABC1230      PowerEdge R650       worker-0.example.com
10.10.0.11      ABC1231      PowerEdge R650       worker-1.example.com
10.10.0.13      ABC1234      PowerEdge R650       -                            <- ABC1234
...

ABC1234: BMC 10.10.0.13
```

The exit code is 0 when it finds the serial and 1 when it does not. The host name column comes
from the BMC, and only when the OS reports it there (on Dell, with the iDRAC Service Module), so
it is often empty. The serial is what counts.

## Map every worker at once

`--map` also reads every worker's serial (one `oc debug` per node) and prints the `[nodes]` block
for `fencing.conf`:

```bash
python3 scripts/find-bmc.py --username fencing --network 10.10.0.0/24 --map
```

```
[nodes]
worker-0.example.com = 10.10.0.10
worker-1.example.com = 10.10.0.11
worker-3.example.com = 10.10.0.13
# worker-2.example.com (serial ABC1232: no BMC found in these networks)
```

A node whose serial is empty or a firmware placeholder, or whose serial shows up on more than one
BMC, is left as a comment to sort out by hand. It never guesses. Either way,
`fencing-setup.py` checks the map again (node serial against BMC serial) before it writes any
manifest.

## What the notes mean

| Note | Meaning |
| --- | --- |
| `login refused (HTTP 401)` | the account does not exist on that BMC, or the password differs. Not tried again |
| `the BMC lists no system` | the BMC answers but lost track of its server. On iDRAC, a reboot of the iDRAC fixes it ([bmc-healthcheck.md](bmc-healthcheck.md)) |
| an address missing from the list | nothing there, or a BMC so hung it does not answer the service root either |

## Test it without hardware

[`lab/bmc-stub.yaml`](../lab/bmc-stub.yaml) reports serials `LABOK`, `LABOFF` and so on. Point
`--network` at its Service IPs and add `--any-vendor`.
