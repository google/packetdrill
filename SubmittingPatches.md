# How To Submit a Patch for packetdrill #

We welcome patches with bug fixes or new features. The packetdrill project uses git for source code management. Please follow the following steps when sending in a patch for packetdrill:

  1. join the packetdrill e-mail list, so your e-mails to the list will be accepted by Google groups
  1. edit some files, compile, test
  1. `git commit` your change with a message like:
```
packetdrill: add amazing feature foo

This commit adds foo, which ...

Tested on FooOS and BarOS by doing the following: 

Signed-off-by: John Doe <jdoe@doe.org>
```
  1. `git format-patch HEAD~1`
  1. check style by running "checkpatch.pl" from the Linux source tree; you can get this here:
```
      wget http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/scripts/checkpatch.pl
      chmod u+x checkpatch.pl
      ./checkpatch.pl --no-tree --ignore FSF_MAILING_ADDRESS 00*.patch
```
  1. `git send-email --to packetdrill@googlegroups.com 00*.patch`