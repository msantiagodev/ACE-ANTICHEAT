---
iter: 67
title: Complete VM Module Catalog — All 5 Modules Extracted
status: every module name, size, and MD5 confirmed
---

# Complete VM module catalog

We've now correctly parsed both `a64.dat` files. Earlier doc 89/88's "17/18 modules" claim was wrong — that was the FIRST ENTRY's name length being misread as a count. The correct numbers are **5 modules total** across both ZIPs.

## Format correction (was wrong in earlier docs)

The a64.dat header is **8 bytes plaintext**, NOT 16:
- +0..+3: u32 BE date marker `0x20220118` (Jan 18, 2022)
- +4..+7: u32 BE entry count

After that, each entry is:
- u32 BE: name length
- N bytes: XOR-encoded name (using cycling 36-char key `"0123...XYZ"` via `ACE_XorEncodeAlphanumeric`)
- u32 BE: body length
- N bytes: encrypted body (decrypted via `out = sbox[in XOR 0x23]`)

The "17" / "18" we saw at offset +8 of the file was actually the FIRST ENTRY's name length: 17 = `len("vm_gp7service.img")`, 18 = `len("timeout_looper.img")`. That's why the count "matched" coincidentally.

## The 5 modules

### Small ZIP (libanort+0x19887B, 40,302 bytes) — GP7 layer

| # | Module | Body Size | MD5 (decrypted) |
|---|---|---|---|
| 0 | `vm_gp7service.img` | 53,685 | `6c3fce310abd5aea3b3f5b7170f13364` |
| 1 | `vm_gp7worker.img` | 31,331 | `8a8fc16e5e446bd25ffdd55758e0ae04` |

**Total**: 85,016 bytes (matches the 85,077-byte a64.dat minus header overhead).

### Big ZIP (libanort+0x1748E8, 147,347 bytes) — Boot layer

| # | Module | Body Size | MD5 (decrypted) |
|---|---|---|---|
| 0 | `timeout_looper.img` | 25,360 | `0467bb799c04a5ebb7085a033a66738c` |
| 1 | `vm_hb.img` | 18,352 | `984970923fc35f44b19fb690b752b53c` |
| 2 | `vm_main.img` | **265,688** | `9156c4ffc5caeab2a50f005788eeeec7` |

**Total**: 309,400 bytes. `vm_main.img` is by far the biggest at 256 KB — this is the bulk of ACE's detection logic.

### Module roles (inferred from names)

| Module | Likely role |
|---|---|
| `vm_main.img` | **Main detection driver** — sequences calls into all detection routines (signature scan, hook scan, anti-debug, etc.) |
| `vm_hb.img` | Heartbeat module — what runs on the HB thread, emits server packets |
| `timeout_looper.img` | 21-second VM context health timer (matches doc 86's `ACE_VMContext_HealthCheck21Sec`) |
| `vm_gp7worker.img` | GP7 layer worker thread |
| `vm_gp7service.img` | GP7 layer service thread (gated by `prctl(PR_SET_DUMPABLE,1)`) |

The disjoint set means: GP7 is a separate detection layer from main detection. Tencent uses these tiers to keep critical heartbeat + anti-tamper running even if main detection fails to load.

## Inner module format (every module shares this)

Each decrypted module body starts with this **16-byte sub-header**:

```
+0..+3:  u32 LE  0x20220623   ← module-build date marker (June 23, 2022)
+4..+7:  u32 LE  0x00000000
+8..+11: u32 LE  0x00000001   ← module format version
+12..+15: u32 LE 0x00000064   ← module build code (100)
```

Then a section table starts at +16, with entries that look like 32-bit LE offset/size pairs.

After that, the body contains:
- Section data (likely VM bytecode)
- A "string pool" of further-encrypted strings (Layer 2 encryption — different per module)

### Layer-2 encryption (still TBD)

Strings like `']T_@QA'`, `'ok\\RY4'`, `'okV_dC'`, `'Qkkbal'`, `'Jh")YT'`, `'YuILfl'` appear in MULTIPLE modules. Since these strings recur across modules, they likely share a common encryption scheme (per-module key derived from build code? Or same global key as the module body but different XOR pattern?). The VM emulator decrypts them lazily during execution.

A reasonable hypothesis: same `sbox[XOR 0x23]` cipher with a different XOR offset per call site.

## Bypass implications

### Now possible
With all 5 modules extracted as decrypted bytecode files on disk:
- **Disassemble** them using our 80+ ARM64 emulator opcode handlers (doc 22/46)
- Identify exactly what each module scans/checks
- Pre-emptively patch our mod menu to hide whatever those modules look for
- Build a custom `vm_main.img` that always reports "clean"

### Still required for full bypass
- Reverse-engineer the Layer-2 string cipher (so we can read embedded format-string fragments)
- Find the RSA-2048 public key location in libanort (so we can either bypass signature check or sign substitute modules)
- Decompile `ACE_VMModuleLoad` (libanort+0x13761C) to understand how bytecode addresses get resolved at load time

## File catalog

| File | Size | Description |
|---|---|---|
| `embedded_vm_modules/modules/00_vm_gp7service.img.bin` | 53,685 | GP7 service VM bytecode (decrypted) |
| `embedded_vm_modules/modules/01_vm_gp7worker.img.bin` | 31,331 | GP7 worker VM bytecode (decrypted) |
| `embedded_vm_modules_BIG/modules/00_timeout_looper.img.bin` | 25,360 | 21s timeout looper VM bytecode (decrypted) |
| `embedded_vm_modules_BIG/modules/01_vm_hb.img.bin` | 18,352 | Heartbeat VM bytecode (decrypted) |
| `embedded_vm_modules_BIG/modules/02_vm_main.img.bin` | **265,688** | **MAIN detection VM bytecode (decrypted)** |
| `enumerate_a64_modules_v2.py` | — | Reproducible parser/extractor |

## Cross-references

| Doc | Topic |
|---|---|
| `90_a64_dat_decrypted.md` | The cipher discovered (sbox + XOR-0x23) |
| `89_a64_dat_internal_structure.md` | First-pass header analysis (some claims now superseded by doc 91) |
| `88_state_struct_and_embedded_vm_zip.md` | The two embedded ZIPs |
| `22_libanort_arm64_emulator.md` | The VM emulator that runs these modules |
| `86_crc32_and_vm_context_health.md` | The 21s timeout (matches `timeout_looper.img`) |
| `81_heartbeat_thread_internals.md` | Heartbeat thread (runs `vm_hb.img`) |

## To-do

- Disassemble vm_main.img using documented VM opcode handlers — what does it actually scan?
- Recover Layer-2 string cipher
- Find RSA-2048 public key
- Decompile `ACE_VMModuleLoad`
- Verify the section table starting at +16 of each module body
