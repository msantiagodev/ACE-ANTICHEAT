---
iter: 65
title: a64.dat — the actual VM module file inside the embedded ZIP
status: dumped + header decoded; body decryption is still TBD
---

# a64.dat — what's actually inside the embedded ZIP

We dumped the 40,302-byte ZIP from libanort+0x19887B (doc 88) and confirmed that the previously assumed filenames `vm_gp7worker.img` and `vm_gp7service.img` are **logical sub-module names**, NOT actual files in the ZIP. The ZIP contains exactly two files, both signed:

| File | Uncompressed Size | Role |
|---|---|---|
| `a64.dat` | **85,077 bytes** | Container holding multiple VM modules |
| `a64.sig` | **256 bytes** | RSA-2048 signature over a64.dat |

The 256-byte signature size is exactly RSA-2048 modulus length — confirming this is digitally signed bytecode that the loader verifies before execution.

## How the loader uses it

```c
// ACE_LoadVMModule_GP7Worker (libanort+0x1467E8)
filename_to_request = "vm_gp7worker.img";  // string ID 11976
ACE_LinkedList_Insert(file_list, "vm_gp7worker.img");

// sub_137184 → ACE_ZipExtractAndProcess
ACE_ZipExtractAndProcess(
    output,
    "builtin",                            // string ID 11285 — source tag
    file_list,                            // ["vm_gp7worker.img"]
    "a64.dat",                            // string ID 11325 — ZIP filename to read
    g_ace_embedded_vm_modules_zip,        // ZIP buffer (40 KB)
    40302,                                // ZIP size
    tree_ctx,
    mode
);
```

So `ACE_ZipExtractAndProcess`:
1. Opens the ZIP at `g_ace_embedded_vm_modules_zip`
2. Extracts `a64.dat` (85 KB)
3. Verifies signature against `a64.sig`
4. Looks up the requested submodule (`vm_gp7worker.img`) inside a64.dat by name
5. Decrypts/decompresses that submodule's bytecode
6. Hands the bytecode to `ACE_VMExecutionDriver`

So `a64.dat` is itself a container format with named modules indexed inside.

## a64.dat header (first 16 bytes — plaintext)

```
+0  | 4 BE | 0x20220118  → date marker: 2022-01-18 (build/release date)
+4  | 4 BE | 0x00000002  → format version
+8  | 4 BE | 0x00000011  → entry count = 17 (sub-modules)
+12 | 4 BE | 0x465C6D54  → header CRC or master offset
```

Date encoding follows ACE's other date constants:
- `0x20211111` = Nov 11 2021 (older constant)
- `0x20211215` = Dec 15 2021 (cache DB)
- **`0x20220118` = Jan 18 2022** ← this VM module set's release
- `0x20230726` = Jul 26 2023 (newer constant)

This implies our libanort.so was built with VM modules from January 2022.

## The 17 sub-modules

Header says **17 entries**. We've identified 2 by name:
- `vm_gp7worker.img` (string ID 11976)
- `vm_gp7service.img` (string ID 11995)

The other 15 are loaded by other code paths we haven't fully traced. They likely include:
- `vm_main.img` (core detection routines)
- `vm_hb.img` (heartbeat-side checks)
- VM modules for: ptrace detection, memory scan, signature scan, hook detection, etc.

To enumerate all 17, we need to either:
- (a) Find every caller of `ACE_ZipExtractAndProcess` and harvest its filename arg
- (b) Decrypt the body section of a64.dat (which contains a name table)

## Body encoding (offsets 16+)

The body is encoded — entropy ranges 6.5-8.0 (typical of compressed/encrypted data) but with one striking anomaly: **the byte 0x83 dominates statistically**. ~50%+ of body bytes are 0x83.

Sample (offset 0x20, 32 bytes):
```
+0020: 83 83 83 83 83 2f 70 83 83 c6 83 83 83 83 83 83 83 83 83 83 83 2f 83 83 83 8b 83 83 83 8f 83 83
```

The 0x83 dominance is too systematic to be encryption. It looks like **single-byte XOR with key 0x83** over a stream that's mostly zero in its plaintext form (which is what an entry/offset table would look like).

XORing the body with 0x83 produces:

```
+0010 c7 81 c6 d1 c9 cc ab a2 a5 e9 af a8 a3 00 00 52 36 87 22 7f 57 00 00 00 00 f3 00 00 00 88 00 00
+0020 00 00 00 00 00 ac f3 00 00 45 00 00 00 00 00 00 00 00 00 00 00 ac 00 00 00 08 00 00 00 0c 00 00
+0040 00 a6 00 00 00 b8 00 00 00 24 2b 00 00 47 08 00 00 8c 08 00 00 aa 08 00 00 8c 08 00 00 57 26 00
+0060 00 24 26 00 00 ca 26 00 00 6c fd 00 00 23 26 00 00 19 c8 00 00 c9 26 00 00 2e ce 00 00 79 26 00
```

After XOR with 0x83, the values look like 32-bit BE small numbers — typical of an offset/length table. So:

- Bytes +0x10..+0x1D = XOR'd random-looking (likely 14-byte name field for module #1: `c7 81 c6 d1 c9 cc ab a2 a5 e9 af a8 a3` — 13 chars + null padding)
- Bytes +0x1E onwards = XOR'd table of u32 BE values (offsets/lengths)

The 14 bytes at +0x10 might be the first module's name encrypted (after XOR-undo, those bytes look like char codes 0xc7, 0x81, etc. — high values, suggesting they're FURTHER encrypted with a per-module key, not just XOR). So a64.dat likely uses multiple encryption layers.

## Encryption layers (best guess)

Based on entropy patterns, the file probably has 3 layers:
1. **Outer**: XOR-by-0x83 (decoder pseudo-random byte to add noise)
2. **Per-module**: AES or similar (the strings inside are not plaintext-readable after XOR-undo)
3. **Per-instruction**: some bytecode obfuscation specific to ACE's VM instruction format

Without access to the actual decryption routine in `ACE_ZipExtractAndProcess`, we can't fully unpack. But we have the artifact in hand and can iterate.

## Signature check

The 256-byte `a64.sig` is RSA-2048 size. Likely:
1. Compute SHA-256 of `a64.dat` (32 bytes)
2. Verify against `a64.sig` using a public key embedded in libanort

To find the public key: search libanort's `.rodata` for ASN.1-style RSA modulus markers (`30 82` typical OID prefix) or for a known 256-byte block referenced by `ACE_ZipExtractAndProcess`. Future iteration.

If we patch out the signature check, we can substitute a craft-built `a64.dat` with our own VM module — gaining the ability to inject ARM64 detection-bypass code into the VM emulator itself. Powerful but requires the unpacker to be reverse-engineered first.

## Static dump artifacts

| File | Path | Size | Purpose |
|---|---|---|---|
| `embedded_vm_modules.zip` | `ace_full_map/embedded_vm_modules.zip` | 40,302 bytes | The whole ZIP from libanort+0x19887B |
| `embedded_vm_modules/a64.dat` | `ace_full_map/embedded_vm_modules/a64.dat` | 85,077 bytes | Encoded VM container |
| `embedded_vm_modules/a64.sig` | `ace_full_map/embedded_vm_modules/a64.sig` | 256 bytes | RSA-2048 signature |
| `dump_embedded_vm_zip.py` | `ace_full_map/dump_embedded_vm_zip.py` | — | Reproducible dump script |
| `analyze_a64_dat.py` | `ace_full_map/analyze_a64_dat.py` | — | First-pass structure analyzer |
| `xor_a64_dat.py` | `ace_full_map/xor_a64_dat.py` | — | XOR pattern analysis |

MD5 of full ZIP: `1cfcd8ef0d301595fc83262af670e7ea`

## Bypass implications

### Static angle
We now have the bytecode container. This makes possible (in theory):
- Audit every VM bytecode instruction the modules will run
- Identify which VM modules contain detection logic
- Pre-compute what each module would detect on our device
- Build offline simulators of each module to verify the bypass

### Dynamic angle
A simpler alternative bypass:
- Hook `ACE_LoadVMModule_GP7Worker` (libanort+0x1467E8) → no-op
- Hook `ACE_LoadVMModule_GP7Service` (libanort+0x146610) → no-op

This prevents these specific modules from EVER being loaded into the VM. Doesn't require breaking encryption. Already feasible with what we know now.

But this is still partial — there are 15 OTHER sub-modules in a64.dat we haven't located callers for yet. Until we trace all 17, the safest bypass is global VM driver suppression (current Tier 8).

## Next steps

- Find callers of `ACE_ZipExtractAndProcess` to enumerate all 17 module names
- Decompile `ACE_ZipExtractAndProcess` to find the unpack routine
- Search libanort for the 256-byte RSA public key
- Try AES-128-CBC with various key derivations against the body section

## UPDATE — there are TWO embedded VM ZIPs in libanort

While tracing callers of `ACE_ZipExtractAndProcess`, we found a SECOND embedded ZIP at libanort+0x1748E8.

| ZIP | Address | Size | Contains | a64.dat size | Version | Module count |
|---|---|---|---|---|---|---|
| **Small** (GP7 path) | libanort+0x19887B | 40,302 bytes | a64.dat + a64.sig | 85,077 | v2 | 17 |
| **Big** (boot path) | libanort+0x1748E8 | **147,347 bytes** | a64.dat + a64.sig | **309,474** | **v3** | **18** |

The Big ZIP is loaded by `ace_boot_extract_and_run_modules` (libanort+0x137CC0) — the boot-time module loader called from boot rules. Each boot rule passes a vtable callback (`*a1`) that fills the file list with module names. Unlike GP7Worker/GP7Service which hardcode names, the boot loader is polymorphic — different boot-rule objects request different module sets from the same Big ZIP.

The Big ZIP's header magic field `0x44585F56` = ASCII `"DX_V"` — likely a tag for the VM module set ("DX" probably = Detect-eXecute or similar).

MD5s for reproducibility:
- Small ZIP: `1cfcd8ef0d301595fc83262af670e7ea`
- Big ZIP: `ae9538c56cd058aea6a86e6d45a7421e`

So our 17 vs 18 module arithmetic suggests:
- Big ZIP contains 18 modules: every detection module ACE knows how to run
- Small ZIP contains 17: a strict subset, missing one module that's GP7-specific or heavyweight

## Static dump artifacts (full set)

| File | Size | Purpose |
|---|---|---|
| `embedded_vm_modules.zip` | 40,302 | Small ZIP from +0x19887B |
| `embedded_vm_modules/a64.dat` | 85,077 | Small a64.dat (v2, 17 modules) |
| `embedded_vm_modules/a64.sig` | 256 | RSA-2048 signature for small a64.dat |
| `embedded_vm_modules_BIG.zip` | 147,347 | Big ZIP from +0x1748E8 |
| `embedded_vm_modules_BIG/a64.dat` | 309,474 | Big a64.dat (v3, 18 modules) |
| `embedded_vm_modules_BIG/a64.sig` | 256 | RSA-2048 signature for big a64.dat |

## IDB renames applied

| Address | Old | New |
|---|---|---|
| 0x1748E8 | unk_1748E8 | `g_ace_embedded_vm_modules_zip_BIG` |
| 0x145948 | sub_145948 | `ACE_GetEmbeddedVMZipBigPtr` |
| 0x145954 | sub_145954 | `ACE_GetEmbeddedVMZipBigSize` |
| 0x137184 | sub_137184 | `ACE_VMModule_LoadFromSmallZip` |
| 0x137CC0 | (already named) | `ace_boot_extract_and_run_modules` (uses Big ZIP) |

## Cross-references

| Doc | Topic |
|---|---|
| `88_state_struct_and_embedded_vm_zip.md` | The embedded ZIP discovery |
| `22_libanort_arm64_emulator.md` | The VM emulator that runs the unpacked modules |
| `46_arm64_emulator_handler_extension.md` | Opcode coverage |
| `86_crc32_and_vm_context_health.md` | VM context init/health |
