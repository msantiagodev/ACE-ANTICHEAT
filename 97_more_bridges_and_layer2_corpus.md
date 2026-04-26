---
iter: 73
title: 5 More __ff_<n> Identified + Layer-2 Corpus Saved
status: bridge inventory now ~18/162; full Layer-2 string corpus on disk
---

# 5 More Native Bridges Identified

| ID | Function | Address | Purpose |
|---|---|---|---|
| `__ff_122` | `ace_vm_ff122_fstatfs` | libanort+0x13E014 | `fstatfs()` syscall — query filesystem info |
| `__ff_159` | `ace_vm_ff159_access` | libanort+0x13E804 | libc `access()` — test file existence/permissions |
| `__ff_195` | `ace_vm_ff195_atoll` | libanort+0x13F1EC | libc `atoll()` — parse string to int64 |
| `__ff_180` | `ace_vm_ff180_get_ctx_field` | libanort+0x13EC30 | Read ctx[+284]; companion to `__ff_109` (writer) |
| `__ff_169` | `ace_vm_ff169_syscall_dispatcher` | libanort+0x13E9E0 | **GENERIC SYSCALL** — invoke any syscall by number with 6 args |

## Critical: __ff_169 is a generic syscall dispatcher

This is HUGE for the bypass surface. `__ff_169` reads:
- `*a1` = syscall number
- `a1[1..6]` = up to 6 syscall arguments

Then looks up the actual syscall function pointer via `sub_120EE0()` and invokes it. So VM bytecode can invoke ANY Linux syscall through `__ff_169` — not just the ones explicitly bridged via `__ff_122` (fstatfs), `__ff_159` (access), etc.

That means there are TWO syscall paths from VM bytecode:
1. `ace_vm_op_svc_syscall` (opcode 1, libanort+0x1411DC) — direct SVC instruction
2. `__ff_169 / ace_vm_ff169_syscall_dispatcher` (libanort+0x13E9E0) — named-bridge syscall

To fully neutralize VM-side syscalls, BOTH paths need patching.

### Bypass implication
Patching `__ff_169` to return 0 (or -1) blocks every VM-bytecode syscall that goes through the named bridge. Combined with the existing Tier 1 patch on `ace_vm_op_svc_syscall`, this closes ALL VM-side kernel access.

## What ACE detection looks like

Cross-reading the bridges identified so far, ACE's bytecode toolkit consists of:

### Memory operations (most-used)
- `__ff_5` (alloc), `__ff_7` (free) — heap management
- `__ff_12` (translate VM↔host pointer) — used by every memory op
- `__ff_21` (memcpy with translation), plus libc `memcpy`/`memset`
- C++ runtime: `_Znam`/`_Znwm` (operator new), `_ZdlPv`/`_ZdaPv` (operator delete)

### File system probes
- `__ff_122` (fstatfs) — get FS info (root partition? mount type?)
- `__ff_159` (access) — does this file exist? (su, frida-server, su.bin, magisk paths)
- (likely more: open, read, close — TBD)

### Generic OS access
- `__ff_169` (syscall dispatcher) — universal syscall escape hatch

### Java/Android introspection
- `__ff_96` (CRC32 → JNIEnv vtable offset lookup)
- `__ff_97` (raw native function call — invokes resolved JNIEnv methods)

### Logic primitives
- `__ff_167` (return 0 = false), `__ff_168` (return 1 = true)
- `__ff_109` (set ctx[+284]), `__ff_180` (get ctx[+284]) — operand register

### String parsing
- `__ff_195` (atoll) — parse numbers from strings (e.g., from /proc/self/status)

This toolkit composes into the typical detection routine:
1. `__ff_159` to check if `/data/local/tmp/frida-server` exists
2. `__ff_122` to check if root partition is read-write
3. `__ff_96(CRC32("FindClass"))` then `__ff_97` to load Java class `com.frida.server.FridaService`
4. Read fields/call methods to get more info
5. `__ff_169(SYS_kill, target_pid, 0)` to ping for a process by PID
6. Compare results against expected hashes/values
7. Report status via heartbeat or `__ff_18` (ACE_BytecodeEntryValidate)

## Layer-2 string corpus saved

We ran a full Layer-2 alphanumeric-XOR scan over all 5 module bytecode files. Results:

| Module | Raw "decoded" candidates | Unique strings |
|---|---|---|
| vm_main | 5,906 | 3,195 |
| vm_hb | 166 | 77 |
| timeout_looper | 314 | 192 |
| vm_gp7service | 1,047 | 695 |
| vm_gp7worker | 526 | 305 |

Saved to `layer2_decoded_strings.txt`. Most are noise (false positives — random bytes that XOR to printable ASCII) but the corpus contains all genuine decoded strings, mixed in.

A noteworthy artifact: every module has the alphanumeric key string itself (`'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'`) at offset +0x4 of its decoded body. This is because the bytes there are **all zero** (XOR with key = key). It's a marker showing the cipher is active and a known plaintext check for the parser.

## ACE bridge inventory now: ~18 of 162 named __ff_<n>

| ID | Name |
|---|---|
| 1 | strncpy_wrapper |
| 2 | memmove_wrapper |
| 3 | memset_wrapper |
| 4 | memcpy_wrapper |
| **5** | **alloc** |
| 6 | realloc_wrapper |
| **7** | **delete** |
| 8 | register_relocator |
| 9 | unknown |
| 11 | strdup_into_buf |
| **12** | **translate_vm_to_host** |
| 18 | ACE_BytecodeEntryValidate |
| **21** | **memcpy_with_xlate** |
| **96** | **JNI dispatcher** |
| **97** | **native_funcptr_call** |
| 109 | set_ctx_field |
| 110 | hash_lookup |
| 111 | get_obfuscated_str |
| 122 | fstatfs |
| 159 | access |
| 167 | returns_0 |
| 168 | returns_1 |
| **169** | **syscall_dispatcher** |
| 180 | get_ctx_field |
| 195 | atoll |

Plus all 22 named bridges (memset, memcpy, _Znwm, _Znam, _ZdlPv, _ZdaPv, plus 16 stub returns).

## IDB updates

- 5 functions renamed (__ff_122/159/180/169/195)
- 5 explanatory IDB comments added
- Saved IDB

## Static artifacts

| File | Description |
|---|---|
| `layer2_decoded_strings.txt` | All Layer-2 decoded strings from all 5 modules |
| `full_layer2_scan.py` | Reproducible Layer-2 string scanner |

## Cross-references

| Doc | Topic |
|---|---|
| `92_vm_module_bytecode_format.md` | __ff_<n> import system |
| `94_jni_dispatch_table.md` + `95_complete_jni_table_and_more_bridges.md` | JNI dispatch (__ff_96/97) |
| `96_layer2_string_cipher_cracked.md` | Layer-2 cipher used by these bridges |
| `48_svc_syscall_bridge.md` | The OTHER syscall path (opcode 1) |

## To-do

- Identify the 144 remaining __ff_<n> bridges
- Trace VM bytecode call sites that use __ff_159 (access) to learn the file paths ACE checks
- Find what sub_120EE0 returns (the syscall function pointer table accessed by __ff_169)
- Decrypt strings with a per-string IV (the "Txy*#xP?@xxP6~C" mystery)
