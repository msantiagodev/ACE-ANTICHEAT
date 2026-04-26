# The ACE Native Function Registry — What Emulated Code Can Call

The emulator's `B/BL #imm26` handlers (when the special opcode `0x48D958` is encountered) call into a **registry of named native functions** populated at module-load time. This is the API surface ACE exposes to its own downloaded detection code.

## The lookup chain

```
Emulated BL/B #0  (with magic 0x48D958)
    │
    ▼
ace_vm_op_branch_imm26 / ace_vm_op_branch_imm26_v2
    │
    ▼
ace_vm_lookup_native_function(parser_ctx, key)  (libanort+0x139118)
    │
    │ (RB-tree at parser+16)
    ▼
ace_lookup_native_function_by_name(key) ← global lookup
    │
    │ (RB-tree at g_ace_native_function_registry @ libanort+0x1A84C0)
    ▼
returns native_function_ptr
    │
    ▼
((fn_ptr)(module_struct))   ← invoked with module struct as only arg
```

## Two-layer design

There are TWO RB-trees — one local to each loaded module, one global.

### Per-module tree (parser+16)

Populated by `ace_vm_module_parse_img` (libanort+0x1386B8) when an `.img` module loads. The module specifies a list of (key, function-name-string) pairs in its v49 section. For each pair, ACE calls `ace_lookup_native_function_by_name(name)` against the GLOBAL tree to resolve the function pointer, then stores `(key, fn_ptr)` in the per-module tree.

### Global tree (`g_ace_native_function_registry` @ libanort+0x1A84C0)

Populated ONCE at boot by `ace_init_native_function_registry` (libanort+0x13A5E8). Two source tables:

| Table | Address | Format | Entries |
|---|---|---|---|
| `g_ace_native_function_table_ff` | libanort+0x163F70 | `(uint32_t idx, uint64_t fn_ptr)` × 162 | 162 entries indexed `__ff_<idx>` |
| `g_ace_native_function_table_named` | libanort+0x164990 | `(const char* name, uint64_t fn_ptr)` × 22 | 22 entries by C-symbol name |

Total **184 native functions** exposed to emulated code.

## The named functions (22 entries verified)

Every emulated module that needs C runtime support links against this list:

| Name | Wrapper | What it does |
|---|---|---|
| `memset` | `sub_13A820` | translates ptr via module+376, calls libc `memset` |
| `memcpy` | `sub_13A874` | translates dest+src via module+376, calls libc `memcpy` |
| `__aeabi_memcpy` | same | alias for memcpy |
| `__aeabi_memcpy4` | same | alias |
| `__aeabi_memcpy8` | same | alias |
| `__aeabi_memmove` | same | alias |
| `__aeabi_memclr` | `sub_13F360` | memclr (zero-fill) |
| `__aeabi_memclr4` | same | alias |
| `__aeabi_memclr8` | same | alias |
| `__aeabi_idiv` | `sub_13F380` | signed integer divide |
| `__aeabi_uidiv` | `sub_13F398` | unsigned integer divide |
| `__aeabi_set_errno` | `sub_13F3AC` | set errno |
| `__aeabi_idivmod` | `sub_13F3D4` | signed divmod |
| `__aeabi_uldivmod` | `sub_13F3F0` | unsigned 64-bit divmod |
| `__modsi3` | same as idivmod | alias |
| `__umodsi3` | `sub_13F404` | unsigned 32-bit modulo |
| `_Znaj` | `sub_13A8DC` | C++ `operator new[](size_t=uint32)` |
| `_Znwj` | same | C++ `operator new(size_t=uint32)` |
| `_Znam` | same | C++ `operator new[](size_t=uint64)` |
| `_Znwm` | same | C++ `operator new(size_t=uint64)` |
| `_ZdaPv` | `sub_13A9A8` | C++ `operator delete[](void*)` |
| `_ZdlPv` | same | C++ `operator delete(void*)` |

## The 162 `__ff_<n>` functions

Indexed slots — likely ACE-internal helpers (e.g., `__ff_1` = some scanner primitive). The `__ff_` prefix is a private convention. Need to enumerate by walking `g_ace_native_function_table_ff` — task left for next iteration.

Example seen so far (incomplete):
- `__ff_1` → `0x13A75C`
- `__ff_2` → `0x13A7B8`
- `__ff_3` → `0x13A820` (= memset wrapper, so this is "ACE memset")
- `__ff_4` → `0x13A874` (= memcpy wrapper)
- `__ff_5` → `0x13A8DC` (= operator new wrapper)
- `__ff_6` → `0x13A934`
- `__ff_7` → `0x13A9A8` (= operator delete wrapper)
- `__ff_8` → `0x13A9D4`
- `__ff_9` → `0x13AB2C`
- `__ff_11` → `0x13AB60` (note: index 10 missing!)
- `__ff_12..162` → various ACE-specific scan primitives

## Wrapper convention — pointer translation

Every wrapper takes `module_struct*` as its only arg, then unpacks emulated registers and translates pointer args:

```c
// memcpy wrapper at libanort+0x13A874
void* memcpy_wrapper(uint64_t* module) {
    char* dest = module[0]   ? (char*)(module[0] + module[47]) : NULL;  // X0 + base
    const void* src = module[1] ? (const void*)(module[1] + module[47]) : NULL;  // X1 + base
    size_t n = module[2];     // X2 (raw, no translation)
    void* result = memcpy(dest, src, n);
    if (dest) module[0] = dest - module[47];  // translate result back to VM addr
    return result;
}
```

Key insight: **`module[47] = module+376` = base of 64KB VM memory**. All pointer args are VM-virtual; wrappers add this to translate to host addresses, then subtract back when returning.

This means:
- Emulated code addresses memory in a 64KB virtual window (0..0xFFFF)
- Wrappers map this to a real malloc'd 64KB region in host memory
- Emulated code CANNOT directly access host memory through the named bridges — they're sandboxed

## The escape hatch — SVC syscall

The SVC handler (`ace_vm_op_svc_syscall` at libanort+0x1411DC) does **not** translate pointers. It passes raw register values directly to `syscall()`. This means:

```c
// Emulated code does:
//   x16 = syscall_no
//   x0..x6 = args (which can include host addresses!)
//   svc #0
// Handler calls:
syscall(module+64, module[0], module[1], ...);
```

If the emulated code somehow obtains a host address (e.g., by calling a wrapper that returns a host pointer), it can use SVC to bypass the sandbox.

**This is why `0x1411DC raw_syscall` is in our Tier 1 patch list** — it's the only sandbox escape, and we kill it.

## Bypass implications

1. **The 184-function registry is the API surface for ACE's downloaded detection code.** If we kill them all (e.g., make `ace_lookup_native_function_by_name` return NULL), every emulated module fails to load → no detections.

2. **Each wrapper is a tiny function** (~30 bytes). We could selectively patch wrappers (e.g., make `memcpy_wrapper` return zero) to corrupt detection scans.

3. **The SVC bridge is already neutralized** by Tier 1.

4. **An attacker could ADD entries to the registry** by patching `ace_init_native_function_registry` to install rogue wrappers, but that's offensive territory we don't need.

## To-do (next iteration)

- Enumerate all 162 `__ff_<n>` wrappers — what do they do?
- Look for "host memory" wrappers (any function that doesn't add `module[47]` is dangerous)
- Cross-reference each `__ff_<n>` with the strings in `ob_*.zip` modules to learn which functions emulated code actually uses
