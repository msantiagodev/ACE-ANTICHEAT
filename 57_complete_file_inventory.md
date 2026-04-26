# Complete File Inventory — Every Path ACE Touches

Every `.dat`, `.zip`, `.so`, `.img` filename referenced by libanort, decoded from the encrypted string table.

## VM module names (5 + boot)

| File | String ID | Purpose |
|---|---|---|
| `vm_main.img` | 11259 | **Main detection module** — special flag set when loaded |
| `vm_hb.img` | 11273 | **Heartbeat module** — sends periodic alive signals |
| `timeout_looper.img` | 11417 | **Timeout looper** — drives the periodic scan thread |
| `vm_gp7worker.img` | 11976 | **GP7 worker** — runs in main process |
| `vm_gp7service.img` | 11995 | **GP7 service** — runs in `:GP7Service` separate process |
| `a64.dat` | 11325 | The inner ZIP file containing all of the above |
| `builtin` | 11285 | The outer source name (embedded in libanort.so) |
| `shell_rom.zip` | 11309 | Filtered out (skipped) during module parse |

The 5 `.img` modules are the FULL emulated detection runtime. Each one has a different scope:
- **vm_main**: detection master logic
- **vm_hb**: heartbeat to server
- **timeout_looper**: 30-second tick loop
- **vm_gp7worker**: in-process detection (memory scans, hooks)
- **vm_gp7service**: out-of-process detection (in :GP7Service)

## ACE local data files (`<dir>/`)

| File | String ID | Purpose |
|---|---|---|
| `ace_cache_db.dat` | 7323 | **Persistent KV cache** — magic 0x20211215, XOR-0x12345678 obfuscated |
| `ace_shell_db.dat` | 7035 | Shell-protected DB |
| `ace_shell_di.dat` | 7153 | Shell-protected device info |
| `acecrh.dat` | 8768 | ACE CRH (config/rule/hash?) |
| `xx_tmp_guard.dat` | 6305 | Guard file (anti-restore?) |
| `SpeedUpCCH.dat` | 7113 | Speedup cache |
| `comm.dat` | 2574 | Communication state |
| `comm.zip` | 2585 | Communication archive |
| `h_rcd.dat` | 10942 | Record file |
| `ms_%08X%08X_tmp.dat` | 11747 | Temporary file with hash-suffix |
| `ano_tmp/%08x.xx.dat` | 9573 | ANO temp sandbox file |
| `ano_tmp/shell_foo.dat` | 9615 | ANO shell foo |
| `virap2.s.dat` | 1828 | Virtual app v2 sandbox state |

These files all reside inside the app's private storage (typically `/data/data/<pkg>/files/`).

## Detection targets — Linux .so paths

ACE checks for these libraries as detection signals (their presence indicates a tool/cheat):

| Library | String ID | What it indicates |
|---|---|---|
| `libmono.so` | 475 | **Unity Mono runtime** — Mono cheats |
| `libjdwp.so` | 5254 | **Java Debug Wire Protocol** — JDB attached |
| `libart.so` | 9642 | Android Runtime |
| `libil2cpp.so` (`SOBASE_libil2cpp.so`) | 11862 | **Unity IL2CPP** — il2cpp cheats |
| `libdrm.so.exagear` | 7202 | **Exagear** ARM emulator (running on x86) |
| `ld-android.so.exagear` | 7234 | Exagear linker |
| `audio.primary.tenc.so` | 8618 | **TenC vendor blob** (China-only emulator/cloud-phone) |
| `audio.primary.tenc_legacy.so` | 8657 | TenC legacy |
| `gatekeeper.tenc.so` | 8703 | TenC gatekeeper |
| `gps.tenc.so` | 8739 | TenC GPS |
| `assets/uniaccount_core.dat` | 9523 | Unified account core asset |

## Cross-reference with bypass

We don't currently patch any of these file accesses. ACE looks for:
1. **`libmono.so` and `libil2cpp.so`** — relevant for Unity-based cheats. Our target is UE4 so these don't fire.
2. **`libjdwp.so`** — would catch a JDB attach. We don't attach JDB; safe.
3. **`*.tenc.so`** — TenC-specific (Chinese cloud phone provider). Our MuMu emulator may or may not have these.
4. **Exagear** — ARM-on-x86 emulator. MuMu uses native ARM, not Exagear; safe.

## On the `vm_*.img` modules — how to disassemble them

Now that we know the names, the next research target is to dump these modules from a running game and disassemble the bytecode. Each `.img` is encrypted (S-box XOR 0x23) — extract via:

1. Hook `ace_parse_module_zip_entries` (libanort+0x1372FC) to capture each module's decrypted body.
2. Save to disk by name (e.g., `vm_main.img.dec`).
3. Build a Python disassembler that reads the `.img` header (magic 0x12345678 + counts) and dumps to ARM64 mnemonics.
4. Cross-reference with our handler mapping to understand what each module checks.

This would give us **complete visibility into ACE's emulated detection logic**.

## To-do

- Decompile `ACE_FormatPath_*` functions for each file (7035, 7113, 7153, 6305, 8768, etc.) — they all follow the same pattern as `ACE_FormatCacheDbPath`
- Build a runtime dumper that captures all 5 `.img` modules at boot
- Write a `.img` disassembler in Python
- Write a `.dat` parser for each persistent file
