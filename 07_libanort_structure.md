# libanort.so — Sister Library Analysis

## Identity

| Field | Value |
|---|---|
| Name | `libanort.so` (ACE "RuNTime") |
| Version | **`4.9.30.24277_oversea`** (international build, embedded in `.rodata` at `0x169FF6`) |
| File size | 1,691,784 bytes (~1.6 MB) |
| Image size | `0x1A8A28` (1.66 MB) |
| `.text` | `0x138A94` (1.2 MB) |
| Functions | 2,395 (1,589 named — 66%) |
| Strings | 1,745 |
| MD5 | `8ceba7a9e569df1903947d208e209b50` |

Compared to libanogs.so (5.7 MB, 24,207 functions): **libanort is much smaller and far better named** in the IDB. Many detection sensors already have meaningful names from prior reverse-engineering.

## Public API surface

Only **6 entry points exported** (vs libanogs's 21):

| Address | Symbol | Role |
|---|---|---|
| `0x2630C` | `JNI_OnLoad` | Java→native registrar |
| `0x1A4948` | `g_aco_array` | Exported global (anti-cheat object array — vtables likely live here) |
| `0x1A3010` | `g_acf_array` | Exported global (anti-cheat function array) |
| `0xBA56C` | `unwind_xx_info_query` | Stack-unwinding info |
| `0xBA8F4` | `unwind_xx_ioctl` | Stack-unwinding ioctl |
| `0x146940` | `tp_syscall_imp` | **TP-syscall handler — the core syscall hook** |

`tp_syscall_imp` is libanort's primary export. It's the **Tencent-Protection syscall handler** — game code (or libanogs) calls it to invoke an ACE syscall. This explains the indirection we saw on the libanogs side: libanogs's syscall hook table eventually routes here.

## Detection sensors (already named in the IDB)

These are functions that scan for tampering / hooks. Each runs from `ACE_DetectionPoller`:

| Function | Purpose |
|---|---|
| `ace_detect_memory_integrity` | RWX page detection (Dobby trampolines map RWX) |
| `ace_detect_elf_section_tamper` | ELF section bytes vs expected hash |
| `ace_detect_segment_tamper` | Segment header tampering |
| `ace_detect_dlopen_library_hijack` | Loaded library list integrity |
| `ace_detect_dex_assembly_csharp` | Unity Mono / IL2CPP detection (we're a UE4 game so likely no-op for us) |
| `ace_detect_dex_file_tamper` | DEX bytecode integrity |
| `ace_detect_runtime_integrity` (+ `_2`) | Generic runtime checks |
| `ACE_JNIClassEnumerator` | Walks loaded JNI classes |
| `ACE_JNIClassDataValidator` | Validates JNI class data |
| `ACE_DetectionPoller` | **The scan thread loop itself** |

## Internals

| Function | Purpose |
|---|---|
| `JNI_ACE_Initialize` | Top-level init (called from JNI_OnLoad) |
| `JNI_ACE_CommandDispatch` | Java→native command router |
| `ACE_DecryptString` (0x11149C, 48 bytes, 562 xrefs!) | THE string decryptor — same algo as libanogs |
| `ACE_Free` (172 xrefs) | Generic free |
| `ACE_HashCompute` (1972 bytes) | Computes hash for integrity checks |
| `ACE_DataEncoder` (1496 bytes) | Encodes data for transmission |
| `ACE_Memcpy_Checked` (188 bytes) | Bounds-checking memcpy |
| `ACE_RBTree_Insert` | Red-black tree insert (used for module lookups) |
| `ACE_MutexLock` | Mutex wrapper |
| `ACE_GetTimestamp` | Timestamp leaf |
| `ACE_FlushInstructionCache` | I-cache flush after self-modifying writes |
| `ACE_GetPageSize` | Page size leaf (probably caches `getpagesize`) |
| `ACE_InstallApiHooks` | **Installs ACE's own hooks on libc functions** — this is what makes libanort.so the "runtime" library |
| `ACE_MmapRecordStore` | Records mmap'd pages for later integrity scan |
| `ACE_GetSingleton_162d98` / `ACE_GetSingleton_ReportContext` | Various singletons |
| `ACE_DetectionPoller` | **The scan thread main loop** |

## `ace_detect_elf_section_tamper` mechanism (verified)

```c
__int64 ace_detect_elf_section_tamper(target_lib, section_table, section_count, ...)
{
    decoded_str = ACE_DecryptString(12377);   // (TBD what this string is)
    ACE_Memcpy_Checked(buf, 128, decoded_str, ...);
    
    for each section (i = 0..section_count) {
        // 1. Make pages writable
        j_ACE_MprotectWrapper(section_addr, section_size, RWX);
        
        // 2. Drop pages from cache
        madvise(section_addr + (i * 0x10000), 0xC000u, MADV_DONTNEED);  // 0xC000 = 3 pages of 16KB each
        
        // 3. Walk re-faulted bytes
        flush_i_cache(section_addr, section_addr + section_size);
        sub_11FF78(...);   // byte-comparator
        ACE_DetectionDataCollectAndStore(hash_buf, target_lib, ...);
    }
    
    if (mismatch_found) {
        ACE_HashCompute();
        ctx = ACE_GetDetectionContext();
        ACE_SetDetectionFlag(ctx, FLAG_ELF_TAMPERED);
        report = ACE_GetSingleton_ReportContext();
        ACE_ObfuscatedFuncCall(report, 1);   // submit
        ACE_DataFormatter(hash_buf);
    }
}
```

**Key observation:** the `madvise(MADV_DONTNEED)` line is fascinating — it tells the kernel "I don't need these pages, drop them from page cache." On next access, the kernel re-reads file-backed pages **from disk**, recovering original (un-hooked) bytes. **This means in-memory `.text` patches via Dobby become INVISIBLE to this scanner after madvise** because by the time it reads, it sees the disk version.

**HOWEVER:** if the page is **dirty** (we wrote to it) and the kernel marked it CoW, MADV_DONTNEED on Android **drops the dirty page** — meaning **our patch is effectively un-applied** during the scan. After the scan finishes, our patch is GONE. The next call to the patched function executes original code again. **We need to keep re-applying the patch periodically OR install our hook in a way that survives madvise.**

The fix: hook `madvise` to lie when ACE asks (return success without dropping pages). Or hook `mprotect` similarly. Both are in `ace_build_libc_hook_watch_list` — meaning ACE will detect our hook on these. We need a stealthier approach: GOT/PLT hook only, not inline.

## Anti-tamper escalation

libanort is the library **we previously patched** with 27 sensor NOPs. The MD5 hash matches our existing `instant_reload_mod/modding.txt` setup. The 11 patched offsets in our existing Main.cpp target individual sensors here. We extended to 27 total recently.

## Not yet mapped

1. **`ACE_DetectionPoller` deep dive.** It's heavily flattened — needs disassembly + register-tracing.
2. **The `g_aco_array` and `g_acf_array` globals.** These are exported symbols and likely contain function pointer tables for the various detection routines. Mapping these tells us the scan callback layout.
3. **`tp_syscall_imp`.** What syscall numbers does it implement? Likely a small set of "secure" syscalls.
4. **The decryption table base.** Per skill notes: libanort's encrypted table is at `0x1716F2`, ~202,850 bytes, 576 strings. Need to verify and apply same `ida_extract_decoder_calls.py` script.
5. **Cross-library IPC.** libanort and libanogs cooperate. How do they share state? Probably via `dlsym` lookups or via passing function pointers through the gcloud SDK shell.

---

## Bypass implications

`libanort.so` is the library that HAS A KILL ON FAILURE — its decoders run `exit_group(7)` if integrity check fails twice (per skill notes). Our 27 detection-sensor NOPs work because they remove specific sensors before they fire detections. But the **`ace_detect_elf_section_tamper`** sensor at byte-level checking will catch any in-memory modification of libanogs.so / libUE4.so unless we hook madvise/mprotect first.

**For the kill chain:**
- libanort: 27 sensor NOPs already in Main.cpp  ← already done
- libanogs: full scanner registry + telemetry kill switch (Tier 1+2 from blueprint)  ← documented but not yet deployed

**The combined attack:**
1. Block libanort's 11 detection sensors (already done)
2. Block libanogs's 28 active scanner-module registrations via `ace_register_scanner_module` hook
3. Disarm libanogs's TDM telemetry via byte_57E31C/D = (0, 1)
4. Verify game survives 5+ minutes (currently dies in 4s)

If 4 still dies, the killer is either:
- libanort's `ace_detect_elf_section_tamper` (doesn't go through libanogs's scanner registry)
- gcloud SDK shell's own checks (separate library)
- Server-side rejection at login

Each of those needs separate analysis.
