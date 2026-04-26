# libanogs.so Init Array — 60 Constructors Decoded

## Summary

libanogs has **60 init_array entries** (numbered 0-59). They run in order before `JNI_OnLoad`. Each one initializes some global state.

## Pattern

Most of the ctors follow a uniform pattern:

```c
ace_init_ctor_N() {
    sub_3B8900(&global_N);                        // Init the global state struct
    __cxa_atexit(sub_3B8998, &global_N, dso);     // Register cleanup
}
```

`sub_3B8900` is a generic mutex+state initializer (the `ace_dict_init` we already mapped). `sub_3B8998` is the corresponding destructor.

## Special / non-trivial constructors

| Ctor | Function | What it does |
|---|---|---|
| 03 | `ace_init_ob_zip_filenames` (0x1E6F88) | Decrypts 6 ob_*.zip filename globals (cdn2/cs2/gs2 ×2 archs) |
| 04 | `ace_init_ctor_static_storage_4` (0x21F018) | Static storage init (data segment) |
| 06 | `ace_init_ctor_06` (0x23130C) | Init unnamed module |
| 07-15 | `ace_init_ctor_static_storage_*` | Various data-segment static storage |
| 16-17 | `ace_init_ctor_16/17` | Module mutex + cleanup register |
| 26 | `ace_init_ctor_26` (0x42FBDC) | Init 2 globals: `unk_58E2D0` and `unk_58E300` (likely scanner state pair) |
| 32 | `ace_init_ctor_32` (0x44317C, 0x5C bytes) | Larger init — multiple state globals |

The vast majority (entries 16-59 of size 0x14) are trivial wrappers that just call one `sub_XXX` function. The interesting work is in the called function, not the init_array entry itself.

## init_ctor_03 highlight

This is the most important non-trivial constructor. From `ace_init_ob_zip_filenames` (libanogs+0x1E6F88):

```c
g_ob_cdn2_filename     = ace_decrypt_xor0A(44710);  // "ob_cdn2.zip"
g_ob_cs2_filename      = ace_decrypt_xor3E(44962);  // "ob_cs2.zip"
g_ob_gs2_filename      = ace_decrypt_xor14(45020);  // "ob_gs2.zip"
g_ob_cdn2_64_filename  = ace_decrypt_xor29(44741);  // "ob_cdn2_64.zip"
g_ob_cs2_64_filename   = ace_decrypt_xor5B(44991);  // "ob_cs2_64.zip"
g_ob_gs2_64_filename   = ace_decrypt_xor31(45049);  // "ob_gs2_64.zip"
```

These 6 filenames are referenced by the rule downloader to decide which archive(s) to fetch from the CDN.

## What about the rest?

The remaining 56 ctors are:
- ~30 "static storage" inits (data segment locks)
- ~20 mutex+singleton bootstraps for per-module state (one per scanner/handler)
- ~6 large ctors that init multiple globals at once

None of them do **detection logic** at boot. They only set up STATE (mutexes, dictionaries, atomic flags). The actual scanning is started later by JNI_OnLoad or AnoSDKMethodInit.

## Why so many?

ACE is heavily modular. Each scanner module / detection target / config channel has its own state struct. C++ static initializers handle all of them. Per-module:
- 1 mutex
- 1 atomic count
- 1 list head
- 1 cleanup hook

Multiplied by 30+ modules, you get the 60 constructors.

## Bypass implications

- **Don't break init.** ALL 60 ctors must complete cleanly or ACE detects "init failure" via the exit_group(2/3) traps documented in `12_complete_kill_path_inventory.md` (Path 7).
- **Don't replace `sub_3B8900`.** Replacing the init helper would corrupt every singleton.
- **Hooking specific ctors is safe** if we don't break their state writes. For example, hooking `ace_init_ob_zip_filenames` to set the filenames to garbage would prevent ZIP downloads from ever working.
- **Tier 5 is more elegant**: just set `g_anort_config_flags |= 0x100` and the downloader skips reading these globals entirely.

## To-do

- For each "static storage" ctor, identify which scanner/module owns it.
- Cross-reference each ctor's global with the scanner registry to map "ctor → scanner".
- Verify whether any ctor has detection-relevant side effects (e.g., starts a worker thread).
