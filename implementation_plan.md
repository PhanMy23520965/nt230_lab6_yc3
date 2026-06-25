# Implementation Plan - Hiding Backdoor Port in `/proc/net/tcp` (Requirement 6)

This implementation plan covers the design and execution steps to modify the `b4rnd00r` kernel rootkit so that it conceals any TCP socket/connection on port `9474` (used by the remote backdoor bind shell) from tools like `netstat`.

## Proposed Changes

We will modify the source file [b4rnd00r.c](file:///d:/nt230/Lab06/nt230_lab6_yc3/b4rnd00r.c) to implement the sequence operations hook on `/proc/net/tcp`.

### Red-Black Tree and PDE Traversal
In Linux kernels around version `4.8.x`, directories and files under the `/proc` filesystem are stored in a Red-Black tree under their parent directory entry.
* The parent directory for network info is `/proc/net/`, represented internally by the `init_net.proc_net` variable.
* We will traverse this tree to find the child entry with the name `"tcp"`.
* We will define the internal `struct proc_dir_entry` structure in our code, since it is not exposed in public headers for kernel modules.

### Sequence Operations Hooking
Once we find the `tcp` directory entry, we will:
1. Extract the `struct tcp_seq_afinfo` pointer from its `data` field.
2. Hook the `.show` callback in its `seq_ops` structure.
3. Unprotect the page containing the sequence operations (which is read-only) before modifying it, then restore protections.
4. Implement our hooked function (`new_tcp_seq_show`), which casts the socket pointer `v` to `struct inet_sock` using `inet_sk()`, checks the local/remote ports against `9474`, and omits the output line if there is a match.

### [b4rnd00r.c](file:///d:/nt230/Lab06/nt230_lab6_yc3/b4rnd00r.c)

#### [MODIFY] [b4rnd00r.c](file:///d:/nt230/Lab06/nt230_lab6_yc3/b4rnd00r.c)
* Add includes: `<net/tcp.h>` and `<net/net_namespace.h>`.
* Define `struct proc_dir_entry` with its correct layout.
* Define `BACKDOOR_PORT` as `9474`.
* Implement `new_tcp_seq_show` callback to filter out connections using `inet_sk(v)`.
* Implement `init_proc_net_tcp_hook` to locate and hook `/proc/net/tcp`.
* Implement `deinit_proc_net_tcp_hook` to restore the original `show` handler.
* Call these helper functions in `b4rn_init` and `b4rn_deinit` respectively.

## Verification Plan

### Manual Verification
1. Load the compiled kernel module using `sudo insmod b4rnd00r.ko`.
2. Launch a bind shell on the target machine:
   `nohup nc -nvlp 9474 -e /bin/bash >/dev/null 2>&1 &`
3. Verify that the backdoor port `9474` is NOT visible in:
   * `netstat -tl` or `netstat -an | grep 9474`
   * `cat /proc/net/tcp | grep 2502` (where `0x2502` is the hex representation of `9474`)
4. Confirm that client connections can still succeed (the port is active but hidden from local inspection).
5. Unload the module using `sudo rmmod b4rnd00r` and verify that the port becomes visible again.
