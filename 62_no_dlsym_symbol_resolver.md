# `ACE_ResolveDynFunc` — Symbol Resolution Without `dlsym`

ACE doesn't use `dlopen`/`dlsym` to resolve native symbols. Instead, it manually parses `/proc/self/maps` and the on-disk ELF files to find symbols. **This bypasses every common hook on the dynamic linker.**

## The function chain

```
ACE_ResolveDynFunc_NoDlsym(symbol_name, output_array)         libanort+0x136650
    │
    ├─→ ACE_OpenProcMaps()                                     libanort+0x12426C
    │   └─ ACE_DecryptString(661) = "/proc/self/maps"
    │   └─ open() the file
    │
    ├─→ ACE_ParseProcMapsLine(state)                          libanort+0x1242E8
    │   │
    │   ├─ Reads each line via ACE_FileGetLine
    │   ├─ sscanf format: "%zx-%zx %c%c%c%c %x %x:%x %u %s"
    │   │   parses: start, end, r, w, x, p, offset, dev_major, dev_minor, inode, path
    │   ├─ Matches path against caller's wanted lib name
    │   └─ Returns state with start/end/perms/path filled
    │
    ├─→ For matched library:
    │   ├─ Read the .so file FROM DISK (not from memory!)
    │   ├─ ACE_ParseELFManually(file_buf, output, mode=2)     libanort+0x129A7C
    │   │   └─ Parses ELF symtab, finds symbol by name (Timestamp = hash)
    │   └─ Compute final address: load_addr + symbol_offset - phdr_vaddr + ...
    │
    └─→ Return resolved native function pointer
```

## Why this matters — anti-hook design

| Hook target | Effective against ACE? |
|---|---|
| Hook `dlopen` | ❌ NO — ACE doesn't call dlopen |
| Hook `dlsym` | ❌ NO — ACE doesn't call dlsym |
| Hook `__dl_open`, `__dl_iterate_phdr` | ❌ NO — ACE doesn't use the linker |
| Hook `open(path)` for `/proc/self/maps` | ⚠️ MAYBE — but breaks lots of normal code |
| Hook `open(path)` for `*.so` files | ⚠️ MAYBE — same issue |
| Hook `read()` selectively | ⚠️ Possible but very invasive |
| Hook `ACE_ResolveDynFunc_NoDlsym` itself | ✅ YES — single-point kill |

The cleanest mitigation is to hook the function itself.

## The /proc/self/maps parser

`ACE_ParseProcMapsLine` reads a line and extracts:

```
00400000-00800000 r-xp 00000000 fd:00 12345  /system/lib/libart.so
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
└start  └end   └rwxp └offset  └dev   └inode └path
```

Sets these fields in the state struct:
- `+1040`: start address (load address)
- `+1048`: size (end - start)
- `+1052`: read flag (1 if 'r')
- `+1056`: write flag (1 if 'w')
- `+1060`: execute flag (1 if 'x')
- `+1064`: special filter flag (set if path doesn't start with '[')
- `+1024`: parsed library path string (~1024 bytes)

The parser also checks for `[heap]`, `[stack]`, `[anon:...]` mappings and filters them out (those don't have ELF files on disk).

## The "no-dlsym" trick

ACE uses this to:
1. **Hide which libraries it accesses** — without `dlopen` calls, IDA's import table doesn't show what ACE depends on.
2. **Survive `dlsym` hooks** — Frida's `Interceptor.attach('dlsym', ...)` does not fire.
3. **Skip dynamic linker mediation** — even if the linker is hooked, ACE goes around it.

This is a classic **anti-Frida** technique. ACE assumes any debugger/instrumentation has hooked `dlsym`.

## ELF parsing internals

`ACE_ParseELFManually(file_buffer, output_struct, mode)` walks the ELF on disk:
1. Reads ELF header at file_buffer (e_type, e_machine, e_phoff, e_shoff)
2. Walks program headers — finds `PT_LOAD` segments
3. Walks section headers — finds `.dynsym` (symbol table) and `.dynstr` (string table)
4. For each symbol, hashes its name, compares to wanted name
5. When match: returns `(symbol_value, symbol_section_offset)`

The final resolved address is computed:
```c
final_addr = load_addr_from_proc_maps + symbol_value_from_elf 
           - section_vaddr + section_load_offset
```

This accounts for ASLR (each library gets a random load address) by using the actual runtime mapping address from `/proc/self/maps`.

## Singleton caching

`g_ace_resolved_func_cache` (libanort+0x1A8270) caches the resolved address. So the parsing only happens ONCE per session. Subsequent calls return the cached pointer.

This is a side-channel: if we can write to this global before ACE first calls `ACE_ResolveDynFunc_NoDlsym`, we override the resolution. But ACE may verify the cached value before each use.

## Bypass strategy

### Cleanest: hook the function

```cpp
__int64 hooked_ACE_ResolveDynFunc_NoDlsym(_BYTE* sym_name, __int64 out) {
    // Match on specific dangerous symbols
    if (memcmp(sym_name, "_ZN3art7DexFile", 15) == 0) {
        return 0;  // Pretend symbol not found
    }
    return real_ACE_ResolveDynFunc_NoDlsym(sym_name, out);
}
```

This blocks the runtime DEX loader (Bridge documented in `59_runtime_dex_loader.md`) without breaking other resolutions.

### Alternative: corrupt the maps parser

Hook `ACE_ParseProcMapsLine` to skip lines mentioning libart.so. ACE then can't find libart and the resolution fails.

### Most surgical: cache poisoning

Set `g_ace_resolved_func_cache = 0xDEADDEAD` to force "already resolved" with garbage. ACE will jump to garbage and crash. Not useful — but interesting that the cache is exposed.

## What other libraries does ACE resolve symbols from?

We've confirmed `libart.so` (for DexFile internals). Other candidates from the strings:
- `libmono.so` (for Unity Mono detection)
- `libil2cpp.so` (for Unity IL2CPP cheat detection)

These would all use the same NoDlsym path. Each is a backdoor surface.

## To-do

- Hook `ACE_ResolveDynFunc_NoDlsym` in REPL bridge to log every (symbol_name, library) tuple
- Determine if ACE checks the on-disk ELF hash (anti-tamper)
- Map `ACE_ParseELFManually` (libanort+0x129A7C) — full ELF parser
- Document `sub_124630` — likely the library name comparator
- Compare with how ACE resolves `_ZNK4java_lang_String_*` etc. (Java native sigs)
