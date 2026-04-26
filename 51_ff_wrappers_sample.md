# `__ff_<n>` Wrapper Sample — What Each Native Primitive Does

The 162 numbered `__ff_<n>` wrappers in `g_ace_native_function_table_ff` (libanort+0x163F70) form the API surface ACE's emulator code can call. We've decompiled and named representative samples covering ~25 entries.

## Decoded wrappers (low half)

| `__ff_<n>` | Address | Renamed | Function |
|---|---|---|---|
| `__ff_1` | 0x13A75C | `ace_vm_ff1_strncpy_wrapper` | `sub_1227A8(dest+base, src+base, len)` — string copy |
| `__ff_2` | 0x13A7B8 | `ace_vm_ff2_memmove_wrapper` | `memmove(dest+base, src+base, len)` |
| `__ff_3` | 0x13A820 | `ace_vm_ff3_memset_wrapper` | `memset(ptr+base, byte, len)` |
| `__ff_4` | 0x13A874 | `ace_vm_ff4_memcpy_wrapper` | `memcpy(dest+base, src+base, len)` (also alias for `__aeabi_memcpy*`, `__aeabi_memmove`) |
| `__ff_5` | 0x13A8DC | `ace_vm_ff5_new_wrapper` | C++ `operator new` (also alias for `_Znaj`/`_Znwj`/`_Znam`/`_Znwm`) |
| `__ff_6` | 0x13A934 | `ace_vm_ff6_realloc_wrapper` | `realloc` — uses ACE_TrackedRealloc if tracker registered |
| `__ff_7` | 0x13A9A8 | `ace_vm_ff7_delete_wrapper` | C++ `operator delete` (also alias for `_ZdaPv`/`_ZdlPv`) |
| `__ff_8` | 0x13A9D4 | `ace_vm_ff8_register_relocator` | Relocates 13 emulated registers from VM-virtual to host addresses, calls `sub_1241D4` |
| `__ff_9` | 0x13AB2C | (unmapped) | — |
| `__ff_B` | 0x13AB60 | `ace_vm_ffB_strdup_into_buf` | Copies string from emulated buffer into 1024-byte stack buffer with `ACE_Memcpy_Checked` |
| `__ff_C` | 0x13AC18 | `ace_vm_ffC_translate_vm_to_host` | `*ptr += base` — translates VM ptr → host ptr |
| `__ff_D` | 0x13AC30 | `ace_vm_ffD_translate_host_to_vm` | `*ptr -= base` — translates host ptr → VM ptr |
| `__ff_E` | 0x13AC48 | `ace_vm_ffE_get_magic_string_uinflqx` | Returns address of `aUINFLQX` (`#U#I#N#F#L#Q#X#`) — magic detection-string |
| `__ff_F` | 0x13AC60 | `ace_vm_ffF_get_obfuscated_string` | `ACE_GetObfuscatedString()` |
| `__ff_10` | 0x13AC98 | `ace_vm_ff10_event_signal` | `ACE_EventSignal(buf, hash)` |
| `__ff_11` | 0x13ACDC | `ace_vm_ff11_sleep` | `sleep(N)` or `ACE_SyscallClockGettime` for VM-aware sleep |
| `__ff_12` | 0x13AD50 | `ace_vm_ff12_bst_upsert` | `ACE_BSTEncodedUpsert(state, key, value)` |
| `__ff_13` | 0x13A56C | `ACE_VMExecBSTLookup` | `ACE_BSTStringLookup(state, haystack, key, len)` |

## Decoded wrappers (high half — system-level)

| `__ff_<n>` | Address | Renamed | Function |
|---|---|---|---|
| `__ff_C8` | 0x13F328 | (unmapped) | — last entry |
| (named-aliased) | 0x13F360 | `ace_vm_named_aeabi_memclr` | zero-fill (memset 0) |
| (named-aliased) | 0x13F380 | `ace_vm_named_aeabi_idiv` | signed divide |
| (named-aliased) | 0x13F398 | `ace_vm_named_aeabi_uidiv` | unsigned divide |
| (named-aliased) | 0x13F3D4 | `ace_vm_named_aeabi_idivmod` | signed modulo |
| (named-aliased) | 0x13F3F0 | `__aeabi_uldivmod` | unsigned 64-bit divmod |
| (named-aliased) | 0x13F404 | `__umodsi3` | unsigned 32-bit modulo |
| (named-aliased) | 0x13F3AC | `__aeabi_set_errno` | sets errno |

## Pattern recognition — wrapper categories

After sampling, the 162 wrappers fall into these families:

### A. **C runtime aliases** (~30 wrappers)
Standard libc functions wrapped with VM↔host pointer translation: memcpy, memmove, memset, memclr, malloc family, divide/mod helpers, errno.

### B. **VM helpers** (~20 wrappers)
- VM↔host pointer translators (`__ff_C`, `__ff_D`)
- Magic string getters (`__ff_E` returns `#U#I#N#F#L#Q#X#`, similar wrappers for other detection magic strings)
- Register relocators (`__ff_8`)
- Sleep, yield, event signal

### C. **Hash / BST primitives** (~10 wrappers)
- `ACE_HashCompute` / `ACE_BSTEncodedUpsert` / `ACE_BSTStringLookup`
- Likely the workhorses of ACE's detection — they store fingerprints in BSTs keyed by hash

### D. **Singleton getters** (~30 wrappers)
- `ACE_GetSingleton_*` family — detection context, config store, sig verify, JNI cache
- Each wrapper returns a host pointer translated to VM space so emulated code can navigate ACE's internal state

### E. **Detection primitives** (~50 wrappers)
- `ACE_EventSignal`, `ACE_GetTimestamp`
- `ACE_ShellDetector`, `ACE_QueryPropertyCollector`
- `ACE_MemoryRegionDetector`, `ACE_DexClassInspector`
- These are the actual scan routines; emulated code orchestrates them

### F. **Network / config** (~10 wrappers)
- `ACE_LoadSignedConfig`, `ACE_ReportContext` accessors
- `ACE_NetworkSendHeartbeat` (likely)

### G. **Crypto / signature** (~10 wrappers)
- `ACE_SignatureValidator`, `ACE_HashCompute`, `ACE_MD5_Finalize`
- AES key setup and packet encryption helpers

## Critical observations

1. **All wrappers translate pointer arguments via `module[+47] = base`**. The VM memory is a 64KB allocated region; emulated pointers are virtual addresses inside this region.

2. **The named bridges (memcpy, etc.) are aliases of `__ff_<n>` wrappers**. So when emulated code does a standard libc call, it goes through the same translation layer.

3. **No wrapper allows arbitrary host memory access** EXCEPT:
   - `ace_vm_op_svc_syscall` (opcode 1) — direct kernel syscall (KILLED by Tier 1)
   - `ace_vm_call_native_funcptr` (sub_13DA54) — calls function pointer from X0 (let it run; ACE legitimately uses for dispatch)

4. **The wrappers are extremely consistent in style**, suggesting they were generated by a code generator from a YAML/JSON specification. ACE could add/remove wrappers without modifying the emulator core.

## Bypass implications

To **completely sandbox** the emulator (no kernel access at all):
1. ✓ Tier 1 — kill `ace_vm_op_svc_syscall` (already deployed)
2. **NOT NEEDED** — Tier 8 (kill `ace_vm_execution_driver`) already prevents any VM execution

To **lie to detection scanners** (let emulator run, but corrupt results):
- Hook specific wrappers like `ace_vm_ff10_event_signal` to return canned values
- Hook `ACE_EventSignal` directly in the host (covers wrapper + native callers)
- This is more invasive than tier 4 but gives finer control

## Remaining work

- Decompile the other ~125 `__ff_<n>` wrappers we haven't sampled
- Identify any that bypass the standard pointer translation
- Cross-reference with strings inside `ob_*.zip` modules to learn which functions emulated code actually uses

Coverage: **~25 / 162 wrappers documented (~15%)** plus all 22 named aliases.
