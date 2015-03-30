The packetdrill scripting tool enables quick, precise tests for entire
TCP/UDP/IPv4/IPv6 network stacks, from the system call layer down to
the NIC hardware. packetdrill currently works on Linux, FreeBSD,
OpenBSD, and NetBSD. It can test network stack behavior over physical
NICs on a LAN, or on a single machine using a tun virtual network
device.

The code is GPLv2. Currently the source for the testing tool and a number of test scripts is in the git
repository. We will continue to post more tests from our team's Linux TCP test suite (described in our USENIX paper), as time permits.

Links:
  * [packetdrill git repository](https://code.google.com/p/packetdrill/source/checkout)
  * [packetdrill USENIX ATC paper](http://research.google.com/pubs/pub41316.html) from June 2013 describing the tool and our team's experiences
  * [packetdrill USENIX ;login: article](http://research.google.com/pubs/pub41848.html) from October 2013
  * [packetdrill mailing list](http://groups.google.com/group/packetdrill) for questions, discussions and patches
  * [submitting patches for packetdrill](https://code.google.com/p/packetdrill/wiki/SubmittingPatches)
  * [packetdrill language syntax reference](https://code.google.com/p/packetdrill/wiki/Syntax)
