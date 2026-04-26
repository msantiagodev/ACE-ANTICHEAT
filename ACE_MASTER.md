# ACE (Tencent Anti-Cheat Expert) — Complete System Reference

**Goal:** 100% understanding of every check, every balance, every flow. End-state: removal or full emulation.

**Iterating in:** Ralph loop (continuous). See `PROGRESS.md` for progress ledger.

---

## 0. Top-Level Picture

ACE ships as **two cooperating native libraries** loaded into the game process:

| Library | Role | Size | .text | Functions |
|---|---|---|---|---|
| `libanogs.so` | "Game Service" — heartbeats, reports, runs the kill chain. **NEVER patch.** | 5,707,192 B | 0x35BDD0 | 24,207 |
| `libanort.so` | "Runtime" — detection sensors (ptrace, mprotect, file integrity, virtual env). **Safe to patch (sensor NOPs).** | 1,691,784 B | 0x138A94 | (TBD this iteration) |

Both libraries:
- Are **AArch64** ELF DYN shared objects
- Use **identical** rolling-XOR string encryption with 100 decoder variants (skill: `ace-string-decryptor`)
- Communicate via shared TLS/data structures + via the SDK API surface (`AnoSDKIoctl`, `AnoSDKForExport`)

The `libanogs.so` library:
- Imports **socket/connect/send/recv/sendto/recvmsg/sendmsg/inet_ntop/inet_pton/getaddrinfo** — **phones home over network**
- Imports **ptrace, prctl, syscall, mmap, mprotect, munmap** — full process control
- Imports **inotify_init / inotify_add_watch** — **watches the filesystem for tampering**
- Imports **fork/waitpid/execl/popen** — can spawn helper processes
- Imports **dlopen/dlsym/dlclose/dl_iterate_phdr** — enumerates loaded modules
- Has **18 published AnoSDK entry points** (the contract the game uses)

---

## 1. AnoSDK Public API Surface (libanogs.so exports)

These are the symbols the GAME calls. Anything we patch should **leave these working** (if we want the game to launch normally) OR **stub them out** (for full bypass).

| Address | Symbol | Purpose (inferred) |
|---|---|---|
| `0x1DA368` | `AnoSDKInit` | Primary init. Called from `JNI_OnLoad`. |
| `0x1DA694` | `AnoSDKInitEx` | Extended init w/ extra args. |
| `0x1DACD0` | `AnoSDKSetUserInfo` | Push user identity to ACE. |
| `0x1DB0D4` | `AnoSDKSetUserInfoWithLicense` | Same + license token. |
| `0x1DB760` | `AnoSDKOnPause` | Game lifecycle hook. |
| `0x1DBB84` | `AnoSDKOnResume` | Game lifecycle hook. |
| `0x1DC070` | `AnoSDKGetReportData` | Pull report payload (v1). |
| `0x1DC5DC` | `AnoSDKDelReportData` | Free report buffer (v1). |
| `0x1DCDA0` | `AnoSDKOnRecvData` | Server → SDK feedback. |
| `0x1DD0EC` | `AnoSDKIoctlOld` | Legacy ioctl-style command channel. |
| `0x1DD9FC` | `AnoSDKIoctl` | Modern ioctl-style command channel. **Most-used.** |
| `0x1DDEEC` | `AnoSDKFree` | Generic free for SDK-allocated buffers. |
| `0x1DE420` | `AnoSDKGetReportData2` | v2 report. |
| `0x1DE48C` | `AnoSDKGetReportData3` | v3 report. |
| `0x1DE4F8` | `AnoSDKDelReportData3` | v3 free. |
| `0x1DEB18` | `AnoSDKGetReportData4` | v4 report. |
| `0x1DEE20` | `AnoSDKDelReportData4` | v4 free. |
| `0x1DF440` | `AnoSDKOnRecvSignature` | Signature verification feedback. |
| `0x1DF7C8` | `AnoSDKRegistInfoListener` | Subscribe to info events. |
| `0x1DFB78` | `AnoSDKForExport` | Generic export for libanort to call. |
| `0x1E2444` | `JNI_OnLoad` | Java->native registrar. **Single entry from Java.** |

**Emulation strategy:** stub all 21 functions to return success/empty. Reports = empty byte arrays. Ioctl returns 0. SDKs see "ACE present, no detections." This is what the bypass would ultimately become.

---

## 2. Hottest Internal Functions (top 15 by xref count)

These are the load-bearing infrastructure of ACE. Renaming applied where obvious; deeper analysis pending.

| Address | Name | xrefs | Type | Purpose |
|---|---|---|---|---|
| `0x2F4E88` | `ace_pool_free_sized` | 856 | dispatcher | Free sized buffer from pool allocator. |
| `0x1E67B0` | `ace_pool_alloc_wrapper` | 624 | complex | Allocate from pool. |
| `0x2E424C` | `ace_string_util_core` | 593 | complex | String utility (used everywhere strings are decrypted). |
| `0x2D9E64` | `ace_noop_leaf` | 571 | leaf | Pure return — likely a vtable fill / null implementation. |
| `0x1D4264` | `ace_log_dispatch` | 547 | complex | Internal log dispatcher. |
| `0x238834` | `ace_get_timestamp_leaf` | 492 | leaf | Read time / monotonic clock. |
| `0x238AD0` | `ace_validate_and_dispatch` | 399 | complex | Generic validate-then-call wrapper. |
| `0x2D9E84` | `ace_ref_release` | 384 | wrapper | Reference counting / release. |
| `0x1F36F8` | `ace_check_flag_leaf` | 328 | leaf | Read a flag. |
| `0x1E3148` | `ace_context_get_field` | 296 | wrapper | Read a field from ACE's context object. |
| `0x2D9E74` | `ace_noop_ret0` | 268 | leaf | Pure `return 0`. |
| `0x27AA7C` | `ace_report_builder` | 230 | complex | Build a report packet. |
| `0x1F36CC` | `ace_is_initialized_leaf` | 229 | leaf | Init flag check. |
| `0x2D9CE0` | `ace_linked_list_ops` | 226 | complex | Linked list manipulator. |
| `0x20305C` | `ace_buffer_write` | 212 | complex | Write to buffer. |

---

## 3. Section Layout (libanogs.so)

| Section | Range | Size | Permissions | Purpose |
|---|---|---|---|---|
| `LOAD` | `0x0` – `0x93A38` | 0x93A38 | rx | Initial load segment. |
| `.gcc_except_table` | `0x93A38` – `0x9E35C` | 0xA924 | r | C++ exception unwind data. |
| `.rodata` | `0x9E380` – `0x11FEC4` | 0x81B44 | r | **Encrypted string table lives here. Plus PLT GOT tables.** |
| `.eh_frame_hdr` | `0x11FEC4` – `0x13F198` | 0x1F2D4 | r | Exception frame index. |
| `.eh_frame` | `0x13F198` – `0x1C7F3C` | 0x88DA4 | r | Exception frames. |
| `.text` | `0x1C7F40` – `0x523D10` | **0x35BDD0 (3.5 MB)** | rx | **All ACE code.** |
| `.plt` | `0x523D10` – `0x524A40` | 0xD30 | rx | PLT stubs for libc imports. |
| `.data.rel.ro` | `0x528A40` – `0x531910` | 0x8ED0 | rw | **Vtables, decoder dispatch table, function pointer arrays.** |
| `.fini_array` | `0x531910` – `0x531920` | 0x10 | rw | Destructors run by `__cxa_finalize`. |
| `.init_array` | `0x531920` – `0x531B00` | 0x1E0 | rw | Constructors run on dlopen. |
| `.got` | `0x531CF0` – `0x5326B0` | 0x9C0 | rw | GOT for non-PLT imports. |
| `.got.plt` | `0x5326B0` – `0x532D50` | 0x6A0 | rw | GOT for PLT imports. |
| `.data` | `0x536E00` – `0x578D98` | 0x41F98 | rw | **All global state: report queue, hook tables, init flag.** |
| `.bss` | `0x578DA0` – `0x593108` | 0x1A368 | rw | Zero-initialized globals. |
| `extern` | `0x593108` – `0x5937C8` | 0x6C0 | --- | External symbol stubs. |

**Image size:** `0x5937C8` (~5.6 MB).

---

## 4. libc Import Categories (libanogs.so)

| Category | Imports | What it tells us |
|---|---|---|
| **Network** | socket, recv, recvfrom, recvmsg, send, sendto, sendmsg, connect, bind, listen, accept, setsockopt, inet_ntoa, inet_ntop, inet_pton, getaddrinfo, freeaddrinfo, poll, select | ACE has a **full networking stack** for phoning home. |
| **File I/O** | fopen, fread, fclose, fwrite, fileno, open, openat, read, write, lseek, close, stat, fstat, fstatat, statfs, access, chmod, mkdir, rmdir, unlink, rename, readlink, symlink | ACE reads/writes filesystem extensively. |
| **Directory ops** | opendir, readdir, closedir | Enumerates directories — used for `/proc/self/fd`, `/proc/self/maps`, etc. |
| **Process / threading** | fork, waitpid, execl, popen, pclose, pthread_*, gettid, getpid, getppid, getuid, sched_yield, kill, abort, _exit, exit, signal, sigaction, sigemptyset, sigaddset, prctl, ptrace, syscall, getauxval | Full process control + **ptrace** for anti-debug + **syscall** for raw kernel calls. |
| **Memory** | mmap, munmap, mprotect, madvise, mincore, malloc, calloc, free, realloc, posix_memalign | Direct virtual memory manipulation. |
| **Dynamic linking** | dlopen, dlsym, dlclose, dladdr, dl_iterate_phdr | Walks the loaded module list — critical for hook detection. |
| **System info** | uname, sysconf, getauxval, __system_property_get, __system_property_find_nth, __system_property_read | Reads kernel/system properties — used for emulator/root detection. |
| **Filesystem watching** | **inotify_init, inotify_add_watch** | **Watches files for modification** — protects its own asset files. |
| **Logging** | __android_log_print, syslog, openlog, closelog | Outputs to logcat (decrypted strings → categorized log channels). |
| **Misc** | nanosleep, sleep, usleep, gettimeofday, clock_gettime, time, localtime, gmtime, mktime, srand, rand, random, ioctl | Standard time / random / ioctl. |

---

## 5. Subsystems (placeholders — to be expanded each iteration)

> Each subsystem will get its own file in `ace_full_map/` as iterations progress.

- `string_decryption.md` — 100 decoders, dispatcher table, integrity check
- `init_flow.md` — JNI_OnLoad → AnoSDKInit → init_array constructors → detection thread spawns
- `detection_systems.md` — opcode_scan, opcode_scan2/3, elf_hook_scan, file_integrity, virtual_env_detect, etc.
- `kill_chain.md` — every path from "detection result" to "process death"
- `network_protocol.md` — what ACE phones home, server URLs, payload format
- `ipc_with_libanort.md` — how libanogs and libanort cooperate
- `vtables_and_dispatchers.md` — `.data.rel.ro` analysis (decoder table, scan dispatch, syscall handlers)
- `report_system.md` — how detections become reports, report data layout
- `inotify_watches.md` — what files ACE protects with inotify
- `anti_debug.md` — every ptrace, prctl, signal trick

---

## 6. Known Kill Chain (fragment, from prior session)

Already mapped:
- `0x1CE6E8` — `sub_1CE6E8` — Raw SVC #0 exit fallback (24-byte stub).
- `0x1CE750` — `ace_custom_syscall_handler` — Obfuscated state machine; mixes legit init AND kill paths via flattened computed-jump CFG.
- `0x1E1110` — `sub_1E1110` (96 bytes) — vtable-registered "InvokeCrash" wrapper. Calls `ace_custom_syscall_handler` with action=16. Reverted (caused early crash when NOPed — ACE detects bypass).
- `0x2E46F4` — `sub_2E46F4` (24 bytes) — vtable-registered SVC-exit wrapper. Reverted (same reason).
- `0x1D0ECC` — `sub_1D0ECC` — Assert/error reporter with obfuscated state machine. Calls kill at LABEL_2 (BL @ 0x1D0F78).
- `0x36FFE0` / `0x370010` — Universal syscall dispatcher (`syscall(num, arg1, ...)`). 35+ obfuscated variants exist. **Bypasses libc PLT entirely.** Cannot be hooked at libc level.

**Lesson learned:** straight NOPs of these wrappers cause ACE to detect the bypass and trigger a faster kill via an alternate path. **Conclusion:** we cannot patch the kill chain without ALSO suppressing detection. Need to find what runs the scan first.

---

## 7. Open Questions Tracker

1. What ACTUALLY runs in the first 4 seconds that detects our hooks so fast?
2. Where does `kill(getpid(), SIGKILL)` actually originate when our PLT kill hook DOESN'T fire?
3. What's the function that gates `opcode_scan` thread creation (the "IsEnable" analog from CODM)?
4. What network endpoints does ACE phone home to? (decrypt + classify hostnames in strings)
5. Where are the inotify watches set up and what files are guarded?
6. What's in `.data` at static-init time (`0x536E00` – `0x578D98`)? Vtables, init flags, function pointer arrays.
7. How do libanogs and libanort talk to each other? Shared globals? IPC?
8. How does the GP7Service process relate to main process detection?
9. Where is the heartbeat scheduler (5-min crash trigger)?
10. Does ACE have process-attach detection beyond ptrace?
