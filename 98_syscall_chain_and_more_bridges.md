---
iter: 74
title: Syscall Chain Confirmed + 11 More Bridges
status: __ff_169 syscall path traced end-to-end; bridge inventory now ~29/162
---

# Syscall Chain End-to-End

`__ff_169` (`ace_vm_ff169_syscall_dispatcher`, libanort+0x13E9E0) calls `sub_120EE0()` to get the actual syscall function pointer. We decompiled `sub_120EE0`:

```c
void* sub_120EE0() {
    if (!cached_syscall_caller) {
        // Try ACE_MprotectCheck1 first
        result = ACE_MprotectCheck1_PATCHED();
        if (!result)
            result = ACE_RawSyscall;       // fallback (libanort+0x146940)
        cached_syscall_caller = result;
    }
    return cached_syscall_caller;
}
```

After our Tier 1 patch (`ANORT_PATCHES[4] = 0x120C88`), `ACE_MprotectCheck1` returns 0 — so the cache populates with `ACE_RawSyscall`.

## ACE_RawSyscall (libanort+0x146940)

Direct kernel syscall wrapper bypassing libc:
```c
unsigned __int64 ACE_RawSyscall(syscall_num, a2, a3, a4, a5, a6, a7) {
    result = linux_eabi_syscall(syscall_num, a2, a3, a4, a5, a6, a7, a7);
    if (result > 0xFFFFFFFFFFFFF000)  // negative errno?
        result = -result;
    if (overflow_check)
        return ACE_SyscallErrorHandler(result);
    return result;
}
```

This is exported as `tp_syscall_imp` and is THE syscall path for **all** ACE direct-kernel calls (not just `__ff_169`). Hooking `ACE_RawSyscall` itself would intercept every kernel call ACE makes that bypasses libc.

## Complete syscall path tree

```
VM bytecode wants kernel call
  ├── Path A: SVC #imm instruction
  │        └── ace_vm_op_svc_syscall (opcode 1, libanort+0x1411DC)
  │             └── PATCHED: returns 0 (Tier 1)
  │
  └── Path B: __ff_169 native bridge
       └── ace_vm_ff169_syscall_dispatcher (libanort+0x13E9E0)
            └── sub_120EE0() → resolves caller function pointer
                 ├── Tries ACE_MprotectCheck1_PATCHED → returns 0 (Tier 1)
                 └── Falls back to ACE_RawSyscall (libanort+0x146940)
                      └── linux_eabi_syscall (kernel)

Plus specific bridges that go DIRECTLY to ACE_RawSyscall family:
  ├── __ff_122 (fstatfs)
  ├── __ff_159 (access)
  └── (others TBD — open, read, kill, etc.)
```

So to fully neutralize VM-side kernel access, the patches are:
- ✓ `ace_vm_op_svc_syscall` (already patched, Tier 1)
- ✓ `ACE_MprotectCheck1` (already patched, Tier 1)
- TODO: hook `__ff_169` to return 0 directly
- TODO: hook `ACE_RawSyscall` to return 0 (catches everything)
- TODO: hook `__ff_122`, `__ff_159` individually for granular control

## 11 More __ff_<n> Bridges Identified

This iteration:

| ID | Function | Address | Purpose |
|---|---|---|---|
| 20 | `ace_vm_ff20_init_report_context` | 0x13ADA4 | `ACE_GetSingleton_ReportContext` + `ACE_InitObjectWithMagic` — sets up the detection report context |
| 22 | `ace_vm_ff22_update_integrity_hash` | 0x13AE40 | `ace_update_integrity_hash_table` — refreshes ACE's expected-hash table |
| 58 | `ace_vm_ff58_nullsub` | 0x13B0E0 | nullsub (placeholder) |
| 62 | `ace_vm_ff62_check_event_signal_table` | 0x13B0FC | `ACE_EventSignalTableValidator` — checks the CRC32 dispatch table integrity |
| 63 | `ace_vm_ff63_shellcode_call` | 0x13B124 | Shellcode lookup + invoke (was misnamed `_ff14`) |
| 64 | `ace_vm_ff64_linkedlist_alloc` | 0x13B1CC | `sub_124AD4` — linked list allocation |
| 65 | `ace_vm_ff65_linkedlist_new` | 0x13B214 | `sub_124BB0` — linked list constructor |
| 66 | `ace_vm_ff66_linkedlist_find` | 0x13B25C | `j_ACE_LinkedListFindValidated` — search by value |
| 67 | `ace_vm_ff67_linkedlist_search_next` | 0x13B2BC | `j_ACE_LinkedListSearchNext` — iterator |
| 68 | `ace_vm_ff68_linkedlist_insert` | 0x13B31C | `sub_124BC0` — insert |
| 69 | `ace_vm_ff69_linkedlist_size` | 0x13B37C | `sub_124BC4` — size getter |

## Updated bridge inventory: 29 of 162 named __ff_<n>

| Group | IDs Identified |
|---|---|
| String/mem | 1-9, 11 |
| VM↔host glue | 12 |
| Bytecode validator | 18 |
| Report context init | 20 |
| memcpy with translation | 21 |
| Integrity hash update | 22 |
| nullsub | 58 |
| Network version + signal table | 61, 62 |
| Shellcode dispatcher | 63 |
| Linked list ops | 64-69 |
| JNI dispatcher | 96, 97 |
| ctx field accessors | 109, 110, 111, 180 |
| Filesystem ops | 122, 159 |
| Constants | 167, 168 |
| Generic syscall | 169 |
| atoll | 195 |

## Bridge functional categories (interpretation)

The 29 identified bridges show ACE's bytecode runtime falls into these functional buckets:

1. **Memory & data structures** (12 bridges): allocation, copy, linked-list ops
2. **Java introspection** (2 bridges): JNI dispatch (covers entire JNIEnv vtable)
3. **OS access** (5 bridges): syscall dispatch, fstatfs, access, atoll, raw syscall
4. **VM internals** (8 bridges): pointer translation, ctx accessors, integrity check, report context, network version, signal table, shellcode dispatch
5. **Logic constants** (2 bridges): true, false

These five buckets together compose every detection workflow in ACE's VM bytecode.

## IDB updates this iteration

- 11 functions renamed
- 2 explanatory comments added (sub_120EE0, ACE_RawSyscall)
- IDB saved

## Cross-references

| Doc | Topic |
|---|---|
| `97_more_bridges_and_layer2_corpus.md` | Previous bridge batch |
| `48_svc_syscall_bridge.md` | The other syscall path (opcode 1) |
| `92_vm_module_bytecode_format.md` | Bridge import system |

## To-do

- Identify the remaining ~133 __ff_<n> bridges
- Find the RSA-2048 public key for a64.sig
- Trace VM bytecode call sites that load specific JNI method names (use Layer-2 cipher to identify them)
- Decompile `ace_update_integrity_hash_table` to learn what hashes ACE expects
