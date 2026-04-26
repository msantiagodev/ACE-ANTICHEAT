# libanogs Scanner Module Inventory

libanogs.so contains **14 distinct scanner modules**, each with its own C++ class hierarchy and vtable. They all inherit from a common base.

## Base class

`vtable_module_BASE` (libanogs+0x528BA0) is the parent vtable. All scanner modules inherit from it. Common fields:
- `+0`: vtable pointer
- `+8`: 32-byte sync object (mutex/condvar)
- `+40`: 32-byte sync object (secondary)
- `+72`: secondary vtable (multi-inheritance)
- `+80`: state flags

## The 14 scanner modules

| Module | Init function | Vtables | What it scans |
|---|---|---|---|
| `anti_root` | `ace_init_anti_root_module` (libanogs+0x299E2C) | `vtable_module_anti_root` (0x52A898) + secondary 0x52A8D8 | Magisk, SuperSU, KingRoot paths |
| `elf_hook_scan` | `ace_init_elf_hook_scan_module` (libanogs+0x29A38C) | `vtable_module_elf_hook_scan` (0x52A908) | Detects inline hooks in libraries (Dobby/Frida) |
| `pe_rep` | `ace_init_pe_rep_module` (libanogs+0x29A888) | (?) | PE (Windows) executable reporter (catches MZ signatures) |
| `cc2` | `ace_init_cc2_module` (libanogs+0x29B480) | (?) | Cheat-Client v2 detection |
| `info_publisher` | `ace_init_info_publisher_module` (libanogs+0x29B8A8) | (?) | Publishes detected info to channels |
| `module2` | `ace_init_module2_module` (libanogs+0x29F8E8) | (?) | (purpose unclear) |
| `anoscan` | `ace_init_anoscan_module` (libanogs+0x2A6954) | (?) | **The main ANO scanner** — multi-purpose detection |
| `black_app` | `ace_init_black_app_module` (libanogs+0x2AA86C) | (?) | Blacklisted apps (cheat tool installers) |
| `cps_new` | `ace_init_cps_new_module` (libanogs+0x2B5190) | (?) | CPS v3 (Continuous Process Scan) |
| `process` | `ace_init_process_module` (libanogs+0x2BB2A4) | (?) | Process enumeration |
| `collect_apk` | `ace_init_collect_apk_module` (libanogs+0x2BE5F0) | (?) | APK list collector |
| `live` | `ace_init_live_module` (libanogs+0x2C1D38) | (?) | Live detection (real-time) |
| `env_chk` | `ace_init_env_chk_module` (libanogs+0x2CA548) | (?) | Environment check |
| `anti_virapp` | `ace_init_anti_virapp_module` (libanogs+0x2D45E4) | (?) | Virtual-app detection (the 21 sigs) |

## Module loading

Each module is registered via the boot init chain. Modules are loaded as part of `init_array` execution at libanogs load time.

The modules are then driven by:
- The periodic scan thread (`ace_periodic_scan_thread_main`) — calls each module's vtable[N] periodically
- The hook descriptor registry — routes scan rules to the appropriate module

## Module API (inferred from base)

Each scanner module exposes (via its vtable):
- `vtable[0]`: destructor
- `vtable[1]`: deleting destructor
- `vtable[2]`: `start()` / module entry
- `vtable[3]`: `scan(ctx)` — actual scan
- `vtable[4]`: `report(ctx)` — emit findings
- `vtable[5]`: `stop()` — shutdown

## Cross-reference with strategies

The strategies we documented in `41_strategy_inventory.md` map to specific modules:

| Strategy | Module |
|---|---|
| `root_strategy` | `anti_root` |
| `virapp_strategy` | `anti_virapp` |
| `frida_strategy` | `elf_hook_scan` (catches Frida-installed hooks) |
| `cc_strategy` | `cc2` |
| `opcode_strategy` | (no direct match — possibly part of `anoscan`) |

## Bypass implications

To **disable a specific scanner module**, we'd:
1. Find the module's singleton instance
2. Patch its `vtable[3] = ace_module_scan_noop` (a stub that returns 0)
3. Module still loads and reports "running" but never scans

This is a fine-grained alternative to Tier 4 (which kills ALL scan rules globally).

For our deployed bypass, Tier 4 covers all of these. We don't need per-module surgery.

## To-do

- Decompile each `ace_init_*_module` to understand state allocation
- Find the singleton getters for each module
- Map the vtable layouts for non-base vtables (52A898, 52A908, etc.)
- Cross-reference with active vs. inactive modules at runtime
