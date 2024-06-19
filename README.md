# dumpshell

``dumpshell`` is a proof-of-concept for an exploit allowing the shell user to spawn a shell with the ``crash_dump`` context as ``root``.

## Requirements

* Vulnerable ``aee_aed`` in ``vuln/`` installed on the device
* ``python``
* ``zig`` (``0.12.0-dev.789+e6590fea1`` at the time of this writing)
* ``adb``
* Debuggable APK made via ``gradle`` or ``Android Studio``

## Instructions

If the vulnerable ``aee_aed`` cannot be installed in ``/system/system_ext/bin``, you'll have to go into the Zig code in ``src`` and change offsets and gadgets apropriately. Chances are, the only variable that needs to be changed is ``SYSTEM_GADGET`` in ``main.zig``.

```
const SYSTEM_GADGET = <Offset to invocation of libc's system(r6 register) from base address>
```

Install a debuggable APK to the device so ``shell`` can replace its context with ``run-as``.
See [Bypassing dynamic_security_check](#bypassing-dynamic_security_check) for why this needs to be done.
```sh
# Use Android Studio or Gradle to make a basic debuggagle APK (com.foo.bar)
./gradlew assembleDebug

# Installs package com.foo.bar
adb install com.foo.bar.apk
```

Run ``pwn.py`` with the name of the package which replaces the ``shell`` context.
```sh
./pwn.py com.foo.bar
```

The exploit should spawn a shell in a few seconds.
```
# id
uid=0(root) gid=0(root) groups=0(root),1000(system),1001(radio),1007(log),1032(package_info),1045(debuggerd),3009(readproc) context=u:r:crash_dump:s0
```

If ASLR in ``aee_aed`` introduces blacklisted characters into the payload (See [Sscanf Buffer Overflow](#sscanf-buffer-overflow) for what is blacklisted), you'll have to restart the device and try again.

Similarly, if you try too many times in a row, ``aee_aed`` will stop servicing the duplicate exception when trying to dump itself. You also have to restart the device in this case.

## Implications

* The dumped state of the machine as well as any process (including ``init``) can be leaked via ``aee_dumpstate``. This state includes...
  - ``/proc/pid/maps`` (This defeats ASLR!)
  - ``/proc/pid/fd``
  - ``dmesg``
  - Much, much more...
* Most files in ``/system`` and ``/vendor`` not normally accessible to ``shell`` are now accessible, like...
  - Kernel modules in ``/vendor/lib/modules``
  - Firmware configs and binaries in ``/vendor/firmware``
  - MTK-Specific binaries in ``/system/system_ext`` (like ``aee_dumpstate`` or ``mdlogger``)
* Some properties not normally writable to ``shell`` are now writable, like...
  - ``persist.vendor.mtk.aee.explevel``
  - ``persiste.vendor.mtk.aee.mode``
  - etc...
* The attacker can use ``aee_dumpstate`` to make dumps in ``/data/local/tmp`` that are difficult to remove and inconvenience the user
* If the selinux policy of a device has a flaw, the root shell could allow further privilege escalations

## Exploit overview

This exploit chains multiple vulnerabilities together to gain code execution as ``aee_aed``.

## Bypassing dynamic_security_check

In order to bypass the dynamic security check preventing ``su`` and ``shell`` from accessing certain endpoints, including the vulnerable one we're trying to access, the program must use ``run-as`` to execute itself in a different selinux context.

One quirk about this is that debuggable apps also don't have permissions to connect to the abstract UNIX sockets presented by ``aee_aed`` which ``shell`` has. However, this is also trivial to bypass because we can just open the file descriptors as ``shell`` and then have ``run-as`` inherit these file descriptors.

There is also a check like this if the selinux mode is ``permissive``

```c
int enforcing = security_getenforce();
if (!enforcing) {
  if (!check_socket(peer, "/system")
    && !check_socket(peer, "/system_ext")
    && !check_socket(peer, "/apex")
    && !check_socket(peer, "/vendor")) {
    __android_log_print("client check failed!\n");
  }
}
```

However, this is a useless check if the mode is ``permissive`` because one could define a preload which overrides ``__libc_init`` and run the following.

```sh
LD_PRELOAD="/data/local/tmp/libmypreload.so" /system/bin/sh
```

This theoretically means that, if the selinux mode is ``permissive``, it's possible to make an app that escalates privileges to ``root`` using ``aee_aed``. However, there are better and more general exploits like [Magica](https://github.com/vvb2060/Magica) for escalating privileges in a ``permissive`` mode.

### Sscanf Buffer Overflow

The most important vulnerability it takes advantage of is a buffer overflow present in ``aee_report_dump_cmd``, reachable from abstract socket ``com.mtk.aee.aed``. When the daemon requests information about the current executing process, it checks for a trigger time and then uses ``sscanf`` to parse it. However, the ``sscanf`` format string used combined with the size of the input allows for a very significant buffer overflow.

```c
peer_cmd peerreq = { /* Fill in data struct here */ };
peer_cmd peercmd;
char trigger_time[40];
fop_safe_write_timeout(peersock, &peerreq, sizeof(peerreq));
fop_safe_read_timeout(peersock, &peercmd, sizeof(peercmd));
if (peercmd.len < 0x20000) {
    peercmd.len = 0x20000;
}
char *input = malloc(peercmd.len);
safe_read_and_discard(peersock, input, peercmd.len);
if (strstr(input, "Trigger time:")) {
    // Uh-oh! strlen(input) is much greater than sizeof(trigger_time)
    sscanf(input,"Trigger time:[%[^]]]",trigger_time);
}
```

There are a couple of caveats to keep in mind.

First, the ``sscanf`` format string blacklists the ``'\x00'`` and ``]`` characters, so if a malicious payload requires these, the attack is thwarted and the attacker must reboot the phone.

Second, the binary is compiled with stack canaries and ASLR enabled. This means we need a primitive to leak the stack canary. A primitive to defeat ASLR would be a nice-to-have, but brute forcing ASLR is also computationally feasible.

Luckily, we have primitives to defeat both!

### Stack Canary Leak

In ``rttd_handle_request``, reachable from abstract socket ``aee:rttd``, there is a mishandling of string functions that makes the program leak more bytes than it intended!

```c
struct
{
    int dontcare;
    int cmd;
    int dontcare2[4];
    char message[84];
} cmd;
fop_safe_read_timeout(fd, &cmd, sizeof(cmd));
// cmd.message is not null-terminated!
switch (cmd.type)
{
// MORE COMMANDS ABOVE
case RTT_AEE_CLEANDAL:
    // Bytes after cmd.message are leaked!
    __android_log_print("Got RTT_AEE_CLEANDAL: %s", cmd.message);
    dal_ui_clean();
    break;
// MORE COMMANDS BELOW
}
```

Because ``cmd.message`` is not null-terminated, anything afterwards that's also not null-terminated are also leaked to logs.

If the compiler decides to place ``cmd`` before the stack canary, writing a message that is not null-terminated will leak the stack canary to logs.

Unfortunately, this is far from theoretical. In fact, it's quite common for the compiler to do so. See [Vulnerable Commit Hashes](#vulnerable-commit-hashes) for vulnerable versions.

### Defeating ASLR

Stack ASLR is trivially defeated by a log message.

```c
    void (*generator)(void);
    aed_worker workers[WORKER_MAX];
    int worker_fd;
    // Choose worker here...
    // This defeats stack ASLR because workers is laid out on the stack!
    // It's also very predictable because 'i' tends to be 0.
    __android_log_print(3,"AEE_AED","%s: generator %p, worker %p, recv_fd %d",
        "aed_main_fork_worker", generatorFn,&workers[i],worker_fd);
    // Act on worker here...
```

Because stack ASLR is defeated and the stack canary is leaked, we can overwrite ``r4`` on ARM, which stores the address to restore the ``aed_report_dump`` object in ``dump_exp_info``. Then, when ``aed_report_dump_cmd`` is called again to specify the current module, we can then overwrite the temporary database path with the module name and then close the socket immediately! This will trick ``aee_aed`` into calling ``aee_dumpstate`` with a custom path, like ``/sdcard/db.malicious`` instead of ``/data/aee_exp/tmp/db.XXXXXXXX`` which was inaccessible to us!

This defeats ASLR because, if we specify that we want to dump the state of ``aee_aed`` by providing its own pid, it will then happily do so. Part of this dump is a dump of ``/proc/pid/maps``, which leaks the base address of ``aee_aed`` mapped in memory, successfully defeating ASLR in ``aee_aed``.

As a bonus, you get to leak a lot of other information as described in [Implications](#implications).

Again, this would intuitively seem coincidental, but it's common for the compiler to put ``aed_report_dump`` in ``r4``.

### Easiest ROP of my Life

``aee_aed`` calls ``system`` with ``r6 + 0x38`` as the address of the ``/system/bin/sh`` command, so all that needs to be done is to write the system command to the stack, write its address to ``r6``, which we know because of the stack address leak, and then overwrite ``lr`` with the address of that gadget.

## Vulnerable Commit Hashes

The commit hashes given in ``/vendor/etc/aee-commit`` have been tested and are vulnerable to this exploit.
* a5a730e76f371a3f8b3ac40ef31aa3bdc6d67f5b

I have looked at other versions of ``aee_aed`` and I have seen the same vulnerabilities present in
those as well, even the stack canary leak and worker log statement, as coincidental as that may be.
In general, it's better to assume that the version of ``aee_aed`` you have is vulnerable.

## Fix

MediaTek has assigned `CVE-2024-20032` to this vulnerability.

`CVE-2024-20032` has already been fixed by MediaTek and was published as part of the [March 2024 MediaTek Security Bulletin](https://corp.mediatek.com/product-security-bulletin/March-2024).
