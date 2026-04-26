# ACE Libc Hook Watch List & Indirection — VERIFIED

## The big picture

ACE doesn't call libc functions directly. **All 31 watched libc functions** + `ace_custom_syscall_handler` are registered into a linked-list hook-watch table at startup by `ace_build_libc_hook_watch_list` (0x266F4C). At scan time, ACE walks this list and **compares the resolved address against the actual function code**. If the function's first bytes have been modified (Dobby trampoline pattern: `LDR/MOV + BR`), it's flagged as inline-hooked.

## The 31 watched libc functions

| # | Function | Why it matters to a bypass |
|---|---|---|
| 1 | `open` | File-open hook common for /proc/self/maps spoofing |
| 2 | `read` | File-read hook |
| 3 | `write` | Anti-write hook |
| 4 | `fopen` | High-level open |
| 5 | `fread` | High-level read |
| 6 | `fgets` | Line-by-line read |
| 7 | `fseek` | File seek |
| 8 | `readdir` | Directory enumeration |
| 9 | `syscall` | Generic raw syscall |
| 10 | `access` | File-existence test |
| 11 | `stat` | File stat |
| 12 | `fstat` | FD-stat |
| 13 | `getenv` | Env var read |
| 14 | `kill` | Send signal |
| 15 | `gettimeofday` | Time |
| 16 | `sleep` | Sleep |
| 17 | `select` | I/O multiplex |
| 18 | `connect` | Socket connect |
| 19 | `send` | Network send |
| 20 | `recv` | Network recv |
| 21 | `opendir` | Directory open |
| 22 | `ptrace` | Anti-debug hook |
| 23 | `execl` | Program exec |
| 24 | `clock_gettime` | High-res clock |
| 25 | `fdopen` | FD-to-stream |
| 26 | `getpid` | PID read (used by self-kill) |
| 27 | `dlopen` | Dynamic load |
| 28 | `dlclose` | Dynamic unload |
| 29 | `pthread_create` | Thread spawn |
| 30 | `fork` | Process fork |
| 31 | `mmap` | Memory map |
| ★ | `ace_custom_syscall_handler` | **ACE's own syscall handler — self-protection** |

The list lives in linked-list form rooted at a global pointer; `ace_hook_table_append` (0x267294) inserts each entry.

## Implication: every libc PLT hook is detectable

If you Dobby-hook any of these 31 functions, ACE's scanner reads the function bytes and compares them to the expected prologue. Mismatch = flag → eventual report → eventual kill.

**Bypass strategies:**
1. **Use Dobby's GOT/PLT mode** (replace the GOT entry, not the function code). The .text bytes stay clean.
2. **Hook the lookup itself.** ACE walks this list — if we corrupt the list head pointer or the comparison routine, scanning produces no results.
3. **Hook the comparator.** Once we find which function actually does the byte-compare, NOP it.
4. **Hook the watch-list builder.** If we can hook `ace_build_libc_hook_watch_list` and pre-empt it, we control the whole list.

## The lookup function — `ace_lookup_libc_by_name` (0x29A3E4)

Despite the original "ace_register_string_decoders" name (which I had wrong), this function is a **string-to-libc-function-pointer dispatcher**. Given an input string (e.g. "ptrace"), it walks 33 strcmp comparisons and returns the corresponding libc function pointer.

Signature (effective):
```c
void *ace_lookup_libc_by_name(const char *name);
```

The 33 entries (in order, with their decryption parameters):
| # | Decoder | Offset | String | Returns |
|---|---|---|---|---|
| 1 | xor01 | 8201 | `open` | `&open` |
| 2 | xor08 | 8208 | `read` | `&read` |
| 3 | xor0F | 8215 | `write` | `&write` |
| 4 | xor44 | 31168 | `fopen` | `&fopen` |
| 5 | xor4C | 31176 | `fread` | `&fread` |
| 6 | xor54 | 31184 | `fgets` | `&fgets` |
| 7 | xor5C | 31192 | `fseek` | `&fseek` |
| 8 | xor00 | 31200 | `readdir` | `&readdir` |
| 9 | xor0A | 31210 | `syscall` | `&syscall` |
| 10 | xor14 | 31220 | `access` | `&access` |
| 11 | xor1D | 31229 | `stat` | `&stat` |
| 12 | xor2D | 31245 | `fstat` | `&fstat` |
| 13 | xor35 | 31253 | `getenv` | `&getenv` |
| 14 | xor3E | 31262 | `kill` | `&kill` |
| 15 | xor45 | 31269 | `gettimeofday` | `&gettimeofday` |
| 16 | xor54 | 31284 | `sleep` | `&sleep` |
| 17 | xor5C | 31292 | `select` | `&select` |
| 18 | xor01 | 31301 | `connect` | `&connect` |
| 19 | xor1D | 31329 | `send` | `&send` |
| 20 | xor24 | 31336 | `recv` | `&recv` |
| 21 | xor0F | 31415 | `opendir` | `&opendir` |
| 22 | xor3B | 31359 | `ptrace` | `&ptrace` |
| 23 | xor44 | 31368 | `execl` | `&execl` |
| 24 | xor2B | 31343 | `clock_gettime` | `&clock_gettime` |
| 25 | xor24 | 31236 | `statfs` | `&statfs` |
| 26 | xor30 | 31548 | `set_errno` | `sub_3395B8` (not exported by libc — internal helper) |
| 27 | xor4C | 31376 | `fdopen` | `&fdopen` |
| 28 | xor55 | 31385 | `getpid` | `&getpid` |
| 29 | xor19 | 31425 | `tss_sdk_init` | `&ace_custom_syscall_handler` |
| 30 | xor4B | 31575 | `AnoSDKInit` | `&AnoSDKInit` |
| 31 | xor14 | 31320 | `strcmp` | `&strcmp` |
| 32 | xor58 | 53288 | **`IsEnable2`** | `nullptr` (special) |
| 33 | (sentinel) | — | — | `&ace_validate_and_dispatch` (default if no match) |

`ace_strcmp` (0x324D70) — actually **just strcmp** (was misnamed `ace_register_decoder_entry`).

### Two non-libc entries
- `tss_sdk_init` returns `&ace_custom_syscall_handler` — Tencent's "SDK init" name maps to ACE's syscall handler. Likely how the gcloud SDK shell triggers ACE init.
- `AnoSDKInit` returns its own address — symmetry with the libc-name-based dispatch.

### `IsEnable2` returning `nullptr`
This is the gate function. It's REGISTERED in the lookup but always returns `nullptr` from this dispatcher. The scan thread that asks "is opcode_scan enabled?" gets back `nullptr` ⇒ presumably treats it as "not enabled" or "no-op". **Hypothesis to verify:** the actual `IsEnable2` implementation lives elsewhere and is registered by a different code path; here we only see the *lookup-dispatch fallback*. Or it's deliberately stubbed in this build.

## Bypass implications

**Stubbing `ace_lookup_libc_by_name` to always return NULL** would break ACE's libc resolution — every subsequent indirect call would fail. ACE's init would crash. Not viable for stealth.

**Stubbing only specific names** (e.g. always return NULL for "ptrace") would let ACE think `ptrace` is unavailable, making anti-debug call-sites no-op. Cleaner.

**Best approach** for a real-world bypass: hook `ace_lookup_libc_by_name` and return our own *fake* pointers for `kill`, `getpid`, etc. — pointers to no-op stubs that we control. ACE walks its hook-watch list, finds our pointers, and they look "clean" because they're ours.

---

## Next sub-iteration target

Find where `ace_lookup_libc_by_name` is called from (xrefs) — that tells us when ACE actually resolves these names at runtime. Trace the result: it gets stored somewhere in `.data`. That somewhere is the **runtime libc dispatch table** — patching it is the cleanest universal bypass.
