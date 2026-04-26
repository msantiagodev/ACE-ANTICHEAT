---
iter: 68
title: VM Module Bytecode Format — Complete
status: per-module .img file format fully reverse-engineered, all 5 modules parsed end-to-end
---

# VM Module Bytecode Format — Complete

This iteration nails down the **per-module .img file format** loaded by `ACE_VMModuleLoad` at libanort+0x13761C → `ace_vm_module_parse_img` (libanort+0x1386B8).

## Module file format

After applying the cipher (`out = sbox[in XOR 0x23]`), each `.img` module decrypts to this layout. **All values are little-endian u32**. The parser cursor uses endian flag = 0 (LE).

### Header (36 bytes)

| Offset | Field | Notes |
|---|---|---|
| +0 | u32 magic = `0x20220623` | June 23, 2022 build date |
| +4 | u32 reserved = 0 | Skipped by parser |
| +8 | u32 version = 1 | Skipped by parser |
| +12 | u32 build_code = 100 | Skipped by parser |
| +16 | u32 v36 | Stored in execution context as `ctx[+96]` |
| +20 | u32 N_A | Count of Type-A entries |
| +24 | u32 N_B | Count of Type-B (named native imports) |
| +28 | u32 N_C | Count of Type-C (named symbols + 2 values) |
| +32 | u32 N_D | Count of Type-D (8-byte address pairs) |

### Type-A entries — symbol/relocation pairs (8 bytes each)
```
struct {
    u32 vm_address;     // VM-side offset
    u32 host_offset;    // host-side resolution
}
```
Inserted into RB-tree #1. Used by VM for relocation resolution at runtime.

### Type-B entries — named native function imports
```
struct {
    u32 vm_address;     // VM-side address that wants to call this native
    u32 name_len;
    u8  name[name_len]; // XOR-encoded with 36-char alphanumeric key
}
```
Names look like `__ff_<n>` (162 of these registered) or named functions like `memset`, `memcpy`, `_Znwm`, `_Znam`, `_ZdlPv`, `_ZdaPv` (22 of these).

The name is decoded via `ACE_XorEncodeAlphanumeric` (XOR with cycling key `"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"`), then resolved via `ace_lookup_native_function_by_name` against the global registry built by `ace_init_native_function_registry` (libanort+0x13A5E8).

### Type-C entries — named symbols + 2 u32 values
```
struct {
    u32 name_len;
    u8  name[name_len];   // XOR-encoded
    u32 value1;
    u32 value2;
}
```
Inserted into RB-tree #2.

### Type-D entries — address pairs (8 bytes each)
```
struct {
    u32 a;
    u32 b;
}
```
Pushed into a u64 array.

### Final blob — VM bytecode
```
u32 blob_size;
u8  bytecode[blob_size];
```
Read by `ACE_ReadLengthPrefixedBlob`. This is the **actual ARM64 emulator bytecode** that ACE_VMExecutionDriver runs through the 122-opcode emulator (doc 22/46).

## Per-module statistics (all 5 modules)

| Module | Type-A | Type-B | Type-C | Type-D | Bytecode |
|---|---|---|---|---|---|
| `vm_main.img` | 2,004 | **1,420** | 0 | 0 | **152,332** |
| `vm_hb.img` | 7 | 15 | 0 | 0 | 11,976 |
| `timeout_looper.img` | 18 | 34 | 0 | 0 | 16,260 |
| `vm_gp7service.img` | 264 | 225 | 0 | 0 | 31,956 |
| `vm_gp7worker.img` | 79 | 100 | 0 | 0 | 19,252 |

Total bytecode across all 5 modules: **231,776 bytes** (≈226 KB) of ARM64 VM bytecode that ACE runs at startup.

## Native bridge import statistics

234 unique native function names are imported across all 5 modules. Top 15 (by total call sites):

| Rank | Name | Total calls | In modules |
|---|---|---|---|
| 1 | `__ff_12` | **319** | ALL 5 modules |
| 2 | `__ff_7` | 213 | vm_main, timeout_looper, vm_gp7service |
| 3 | `__ff_5` | 108 | ALL 5 modules |
| 4 | `memset` | 89 | vm_main, vm_gp7service, vm_gp7worker |
| 5 | `__ff_21` | 82 | ALL 5 modules |
| 6 | `__ff_3` | 69 | vm_main, vm_gp7service |
| 7 | `_Znam` (operator new[]) | 64 | vm_main, vm_gp7service, vm_gp7worker |
| 8 | `__ff_4` | 51 | ALL 5 modules |
| 9 | `__ff_96` | 51 | vm_main, vm_gp7service, vm_gp7worker |
| 10 | `__ff_97` | 51 | vm_main, vm_gp7service, vm_gp7worker |
| 11 | `_Znwm` (operator new) | 44 | vm_main, vm_gp7service, vm_gp7worker |
| 12 | `__ff_13` | 38 | vm_main, vm_gp7service, vm_gp7worker |
| 13 | `__ff_71` | 29 | vm_main, timeout_looper, vm_gp7service |
| 14 | `_ZdlPv` (operator delete) | 27 | vm_main, vm_gp7service |
| 15 | `__ff_111` | 27 | vm_main only |

## The top 3 native bridges identified

These three are the **VM↔host memory model glue** — every memory operation in VM bytecode goes through them.

### `__ff_12` (= `ace_vm_ff12_translate_vm_to_host`, libanort+0x13AC18)
```c
__int64* ace_vm_ff12_translate_vm_to_host(__int64* result) {
    if (*result)
        *result += result[47];   // VM_pointer + code_base = host_pointer
    return result;
}
```
Adds the **module's code base offset** (`ctx[+376]`) to a VM-side pointer to produce a host-side pointer. Position-independence engine. Called 319 times across all 5 modules — every memory op uses this.

### `__ff_7` (= `ace_vm_ff7_delete`, libanort+0x13A9A8)
```c
void ace_vm_ff7_delete(_QWORD* a1) {
    void* host_ptr = (*a1) ? (void*)(*a1 + a1[47]) : NULL;
    if (a1[51]) sub_145B64(a1[51], host_ptr);   // custom free with allocator state
    else free(host_ptr);                         // libc free
}
```
VM memory deallocator. Translates VM ptr→host ptr, then frees.

### `__ff_5` (= `ace_vm_ff5_alloc`, libanort+0x13A8DC)
```c
char* ace_vm_ff5_alloc(size_t* a1) {
    size_t allocator_state = a1[51];
    char* result = allocator_state
        ? sub_145A40(allocator_state, *a1, ...)   // custom alloc
        : malloc(*a1);                              // libc malloc
    if (result) result -= a1[47];                  // return VM-relative
    *a1 = (size_t)result;
    return result;
}
```
VM memory allocator. Returns address as VM-relative offset (subtracts code base).

## The 162-entry __ff_<n> table

`g_ace_native_function_table_ff` at **libanort+0x163F70** (2592 bytes = 162 × 16-byte entries).

Each entry:
```c
struct {
    u32 id;          // __ff_<id>
    u32 padding;
    u64 func_ptr;
}
```

IDs are sparse — range 1..200 with gaps. The full ID list:
```
1-9, 11-30, 39, 40, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, ...
```

## The 22-entry named function table

`g_ace_native_function_table_named` at **libanort+0x164990** (352 bytes = 22 × 16-byte entries).

Each entry:
```c
struct {
    char* name;      // pointer to name string
    void* func;      // function pointer
}
```

Identified entries (string at `*offset`):
- `memset` → `ace_vm_ff3_memset_wrapper` (libanort+0x13A820)
- `memcpy` → `ace_vm_ff4_memcpy_wrapper` (libanort+0x13A874)
- C++ runtime: `_Znwm` (new), `_Znam` (new[]), `_ZdlPv` (delete), `_ZdaPv` (delete[])
- Various stub functions all return `0x13F360` (a placeholder)

## VM execution context layout

After `ACE_VMModuleLoad` succeeds, the VM execution context (passed as `a5`) has:

| Offset | Field |
|---|---|
| +96 | v36 from header |
| +240 | -1 (= 0xFFFFFFFFFFFFFFFF) sentinel |
| +256 | base + 0xFFC0 (top of 64KB VM mem - 64) |
| +264 | entry point address |
| +276 | 0x20220623 (per-module date marker) |
| +376 | code base pointer (used by ff_12/ff_5/ff_7 for translation) |
| +384 | code size |
| +393 | flag (set if module name == "builtin" AND match string 11259) |
| +400 | module struct pointer |
| +408 | aux arg |
| +416 | another base copy |

64 KB of VM memory is allocated per module (`sub_138FAC(v12, 0x10000)`). Magic check rejects modules whose ID is `0x12345678` (sentinel for "invalid").

## Bypass implications

### Surgical option: kill VM via memory glue
Hooking ANY of `__ff_12`, `__ff_7`, `__ff_5` to return error breaks the VM completely — every memory operation fails. Cleaner than killing the entire `ACE_VMExecutionDriver`. Three small patches replace one big hammer.

### Substitute module: now possible
With the parse format fully understood, we can:
1. Build a custom `vm_main.img` that imports `__ff_12` once, allocates 0 bytes, returns success
2. Re-encrypt with our cipher (`encrypted = inverse_sbox[plain] XOR 0x23`)
3. Re-package into `a64.dat` then into the ZIP wrapper
4. Patch `g_ace_embedded_vm_modules_zip_BIG` in libanort to replace it
5. Bypass the RSA signature check (NOP-out signature verifier — TBD location)

### Disassemble the bytecode
With **152,332 bytes** of decrypted bytecode for `vm_main.img` and our 80+ documented opcode handlers, we can:
1. Walk every instruction starting at the entry point
2. Map every native call site to its `__ff_<n>` target
3. Identify exact detection logic — what bytes ACE checks, what files it scans

## Renames + comments

| Address | Name |
|---|---|
| `0x163F70` | `g_ace_native_function_table_ff` (already named, comment added) |
| `0x164990` | `g_ace_native_function_table_named` (already named, comment added) |
| `0x13AC18` | `ace_vm_ff12_translate_vm_to_host` |
| `0x13A9A8` | `ace_vm_ff7_delete` |
| `0x13A8DC` | `ace_vm_ff5_alloc` |
| Various `__ff_<n>` | restored descriptive `ace_vm_ff<n>_<role>` names |

## Static artifacts

| File | Description |
|---|---|
| `walk_vm_module.py` | Per-module format walker |
| `catalog_vm_main_imports.py` | All-modules import histogram + bytecode extractor |
| `vm_module_imports.txt` | Complete import list per module |
| `*/modules/*.img.bin.bytecode` | Pure ARM64 VM bytecode for each of 5 modules |

## Cross-references

| Doc | Topic |
|---|---|
| `91_vm_modules_catalog.md` | The 5 modules and their sizes/MD5s |
| `90_a64_dat_decrypted.md` | The cipher used to decrypt module bodies |
| `22_libanort_arm64_emulator.md` | The 122-opcode VM that runs the bytecode |
| `46_arm64_emulator_handler_extension.md` | Opcode handler coverage |

## To-do

- Disassemble vm_main.img bytecode using documented opcode handlers
- Cross-reference each native call site address to its native function via Type-A entries
- Identify __ff_21, __ff_96, __ff_97 (top callers we don't know yet)
- Find the RSA-2048 signature verifier (still TBD)
- Try to read the per-module Layer-2 string cipher (still encrypted strings like `']T_@QA'`)
