# packetdrill
This is the official Google release of packetdrill.

The packetdrill scripting tool enables quick, precise tests for entire TCP/UDP/IPv4/IPv6 network stacks, from the system call layer down to the NIC hardware. packetdrill currently works on Linux, FreeBSD, OpenBSD, and NetBSD. It can test network stack behavior over physical NICs on a LAN, or on a single machine using a tun virtual network device.

The code is GPLv2. Currently the source for the testing tool and a number of test scripts is in the git repository. We will continue to post more tests from our team's Linux TCP test suite (described in our USENIX paper), as time permits.

Links:
* [the Google packetdrill git repository on github.com](https://github.com/google/packetdrill)
* [packetdrill tutorial at NetDev in March 2025](https://netdevconf.info/0x19/sessions/tutorial/tutorial-using-packetdrill-to-write-automated-tests-for-the-linux-networking-stack.html)
* [packetdrill USENIX ATC paper from June 2013](http://research.google.com/pubs/pub41316.html) describing the tool and our team's experiences
* [packetdrill USENIX ;login: article](http://research.google.com/pubs/pub41848.html) from October 2013
* [packetdrill mailing list](https://groups.google.com/forum/#!forum/packetdrill) for questions, discussions and patches
* [packetdrill language syntax reference](https://github.com/google/packetdrill/blob/master/syntax.md)

External links:
* [using packetdrill for teaching TCP](http://beta.computer-networking.info/syllabus/default/exercises/tcp-2.html)

# How To Get Started with packetdrill

First, download the dependencies that you will need in order to build and run
packetdrill. If you are on a Linux system based on Debian/Ubuntu then you can
use a command like:

```
sudo apt install git gcc make bison flex python3 net-tools
```

To check out and build packetdrill:

```
git clone https://github.com/google/packetdrill.git
cd packetdrill/gtests/net/packetdrill
./configure
make
```

# How To Run All Local Tests for Linux

If you are on a machine with a recent Linux kernel you can su to root and
run all of the TCP stack tests included in the packetdrill distribution
in the tcp/ directory:

```
cd ..
./packetdrill/run_all.py -S -v -L -l tcp/
```

# packetdrill's Design

## Execution Model

packetdrill parses an entire test script, and then executes each timestamped
line in real time -- at the pace described by the timestamps -- to replay and
verify the scenario. The packetdrill interpreter has one thread for the main
flow of events and another for executing any system calls that the script
expects to block (e.g., poll()).

For convenience, scripts use an abstracted notation for packets. Internally,
packetdrill models aspects of TCP and UDP behavior; to do this, packetdrill
maintains mappings to translate between the values in the script and those in
the live packet. The translation includes IP, UDP, and TCP header fields,
including TCP options such as SACK and timestamps. Thus packetdrill tracks each
socket and its IP addresses, port numbers, TCP sequence numbers, and TCP
timestamps.

## Local and Remote Testing

packetdrill enables two modes of testing: local mode, using a TUN
virtual network device, or remote mode, using a physical NIC.

In local mode, packetdrill uses a single machine and a TUN virtual network
device as a source and sink for packets. This tests the system call, sockets,
TCP, and IP layers, and is easier to use because there is less timing
variation, and users need not coordinate access to multiple machines.

In remote mode, users run two packetdrill processes, one of which is on a
remote machine and speaks to the system under test over a LAN. This approach
tests the full networking system: system calls, sockets, TCP, IP, software and
hardware offload mechanisms, the NIC driver, NIC hardware, wire, and switch;
however, due to the inherent variability in the many components under test,
remote mode can result in larger timing variations, which can cause spurious
test failures.

The packet plumbing is, naturally, a bit different in local and remote
modes. To capture outgoing packets packetdrill uses a packet socket (on Linux)
or libpcap (on BSD-derived OSes). To inject packets locally packetdrill uses a
TUN device; to inject packets over the physical network in remote mode
packetdrill again uses a packet socket or libpcap. To consume test packets in
local mode packetdrill uses a TUN device; remotely, packets go over the
physical network and packetdrill sets up filtering rules to drop the packets
before layer 4 (UDP or TCP) processing in the remote kernel sees them.

## Local Mode

Local mode is the default, so to use it you need no special command line flags; you only need to provide the path of the script to
execute:

```
./packetdrill foo.pkt
```

## Remote Mode

To use remote mode, on the machine under test (the "client" machine), specify
the --wire_server_at option to specify the DNS name or IP address of the remote
server machine to which the client packetdrill instance will connect. Only the
client instance takes a packetdrill script argument, which can be the path of
any ordinary packetdrill test script:

```
client# ./packetdrill --wire_server_at=<server_name_or_ip> foo.pkt
```

On the remote machine, run the following to have a packetdrill process act as a
"wire server" daemon to inject and sniff packets remotely on the wire:

```
server# ./packetdrill --wire_server
```

How does this work? First, the client packetdrill instance connects to the
server packetdrill instance (using TCP), and sends the command line options and
the contents of the script file to the server instance. Then the client and
server packetdrill instances work in concert to execute the script and test the
client machine's network stack.

## IP Addresses for packetdrill Tests

Remote or local mode tests may optionally specify arbitrary IP addresses to use
for the test traffic, using the following command line arguments:

```
--local_ip=<local_ip_addr>     # test traffic address for machine under test
--netmask_ip=<netmask_ip>      # test traffic netmask (if testing IPv4)
--gateway_ip=<gateway_ip_addr> # test traffic address for gateway
--remote_ip=<remote_ip_addr>   # test traffic address for remote endpoint
```

By default, remote mode tests use the "primary" IP address of the client and
server machines for the test traffic (where the "primary" address is the IP
address to which the hostname resolves). With this configuration, the client
and server can be anywhere in the same layer-3 routable domain (though it is
highly recommended to only use packetrill in an internal RFC 1918 IP address
space, for "lab" testing, rather than in the public Internet).

When a remote mode test uses arbitrary IP addresses, the packetdrill client and
server processes must be on the same layer 2 broadcast domain (e.g., on the
same Ethernet switch), so that the server machine may act as a gateway to reach
the remote IP address configured via the --remote_ip command line argument.

# How To Submit a Patch for packetdrill

We welcome patches with bug fixes or new features for packetdrill. The packetdrill project uses git for source code management. Please follow the following steps when sending in a patch for packetdrill:

1. join the packetdrill e-mail list, so your e-mails to the list will be accepted by Google groups
2. edit some files, compile, test
3. verify that you can certify the origin of this code with a `Signed-off-by` footer, according to the [standards of the Linux open source project](https://www.kernel.org/doc/html/v4.17/process/submitting-patches.html#developer-s-certificate-of-origin-1-1)
4. git commit your change with a message like:
 
 ```
packetdrill: add amazing feature foo

This commit adds amazing feature foo, which ...

Tested on FooOS and BarOS by doing the following:
  ...

Signed-off-by: John Doe <john.doe@gmail.com>
```

5. Generate git patches using: `git format-patch HEAD~1`
6. Check style for the patches by running `checkpatch.pl` from the Linux source tree, e.g.:
```
wget http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/scripts/checkpatch.pl
chmod u+x checkpatch.pl
./checkpatch.pl --no-tree --ignore FSF_MAILING_ADDRESS 00*.patch
```
7. You can submit your patch as either a GitHub pull request or an e-mail patch series, with something like:
```
git send-email --to packetdrill@googlegroups.com 00*.patch
```
