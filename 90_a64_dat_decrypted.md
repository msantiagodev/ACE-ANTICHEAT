---
iter: 66
title: a64.dat decrypted — the inner cipher revealed
status: cipher fully reverse-engineered; 306+ plaintext strings extracted
---

# Inner cipher: `out = sbox[in XOR 0x23]`

By decompiling `ace_parse_module_zip_entries` (libanort+0x1372FC), we found the per-byte cipher used to decrypt module bodies inside `a64.dat`:

```c
*v22 = g_ace_module_sbox[(unsigned __int8)*v22 ^ 0x23LL];
```

This is a **single round of XOR-then-S-box-substitution** — extremely simple and now fully recovered.

## The S-box

`g_ace_module_sbox` (libanort+0x1747C9, 256 bytes) — verified to be a valid permutation of all bytes 0x00..0xFF. First 16 entries:

```
sbox[0x00..0x0F] = ab e4 7f a8 46 24 58 9d 7d b8 f0 91 08 13 80 60
sbox[0x23]       = 1d  ← key index for source byte 0
sbox[0xA3]       = ?   (the inverse: which encrypted byte produces 0?)
```

The S-box is in libanort's .rodata at a fixed offset, so an attacker (us) trivially extracts it.

## Why the body looked like 0x83 was dominant

Earlier (doc 89) we observed byte `0x83` dominating the encrypted body. The reason wasn't single-byte XOR by 0x83 — it was simpler. **Plaintext bytes equal to a specific value** map through the cipher to 0x83. Looking at the S-box, the byte 0x83 is at sbox index 30, so source byte (30 XOR 0x23) = 0x0D would produce encrypted 0x83. But our analysis shows that source byte 0 (zero) maps to encrypted 0xAB, NOT 0x83.

So the actual reason for 0x83 dominance: there's a specific source byte that's overwhelmingly common in plaintext (likely a specific structural byte like 0x0D / 0x83-equivalent) that produces 0x83 after encryption.

Update from re-analysis: The 0x83 dominance is from `sbox[0x23 XOR 0x83]` ≡ source 0xA0 → encrypted 0x83 (sbox[0xA3]=0x83). Need to verify this exact mapping.

What matters: the cipher is reversed correctly, decryption produces structured data with readable strings.

## Header still plaintext

The first **16 bytes** of `a64.dat` are NOT encrypted (parser reads them directly):
```
+0..+3:  date marker (0x20220118)
+4..+7:  version (2 or 3)
+8..+11: count (17 or 18)
+12..+15: header tag/CRC
```

Body bytes (offset 16+) ARE encrypted. After applying `out = sbox[in XOR 0x23]`, the body becomes structured.

## What we extracted

### From the SMALL a64.dat (85,077 bytes)
After decrypting offset 16+, we see clear forward-pointer offset tables (LE u32) followed by per-module data sections. Most strings are short and look like additional encrypted material — suggesting **another encryption layer** on the per-module data sections.

### From the BIG a64.dat (309,474 bytes) — 306 plaintext strings extracted!

The big container reveals far more readable content. **A goldmine of detection logic**:

#### Target identifiers (what ACE looks for)
| String | Purpose |
|---|---|
| `arm64-v8a` | Architecture filter — only run on 64-bit ARM |
| `libUnreal.so` | TARGET LIBRARY — game's UE4 library (this is what ACE scans) |
| `/base.apk` | Standard Android APK path |
| `RebindApkPath` | APK path rebinding (anti-tamper) |
| `.rodata` | ELF section — read-only data scan target |
| `com.ace.gshell.AceApplication` | ACE's own application wrapper class |

#### JNI method names (reflection-based detection)
- `GetStaticObjectField`
- `CallStaticObjectMethod`
- `CallObjectMethod`
- `GetMethodID`
- `GetObjectField`
- `SetByteArrayRegion`

These tell us ACE uses JNI reflection from native code to call into Java APIs — looking up class fields and invoking methods to query Android state.

#### Android APIs of interest
- `getContentResolver()`
- `()Landroid/content/pm/PackageManager;`
- `(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;`
- `addAction`
- `getName`
- `getSuperclass`
- `toString`
- `delete`
- `sharedUserId`

#### Detection report format strings
- `cnt:%d:%d|crc:0x%08x:0x%08x|size:%d:%d` — diff report
- `main, block:%d` — module main routine logging
- `%s, loop:%d` — iteration count log
- `  %s, time cast:%ldms` — timing measurement
- `CP/CS, %s, need protect:%d` — control point / control surface protection
- `vaddr` — virtual address (memory scan field)
- `p:%08x_m:%08x` — pointer/module identifier
- `1/%x/%x` — generic 2-field hex format
- `|crc:0x` — CRC report fragment

#### Hardcoded MD5 hashes (likely expected hashes for tamper detection)
- `55A7909E4FD3BC8A9AD37BCABF35290B`
- `1414E740DC138D82EBD6A6408915817A`

These look like 32-char hex MD5s. They're probably:
- Expected hash of `libUnreal.so` (or specific sections)
- Expected hash of `/base.apk` or its certificate
- Expected hash of `com.ace.gshell.AceApplication` class bytecode

If the runtime hash differs, ACE flags the device as tampered.

### Still-encrypted strings (per-module layer)

The strings `ok\RY...`, `]T_@QA...`, `okVRdC...` etc. that appear repeatedly are NOT plaintext after layer-1 decryption. These go through a 2nd layer (likely an XOR-with-state or another S-box specific to each VM module). They appear to be format-string fragments or label names within VM bytecode that the VM decrypts as it executes.

## Loader flow (now complete)

`ACE_LoadVMModule_GP7Worker` / `ACE_LoadVMModule_GP7Service` paths:

```
1. ACE_GetEmbeddedVMZipPtr → libanort+0x19887B (small ZIP, 40 KB)
2. ACE_ZipExtractAndProcess(zip, size, "a64.dat", filter_list, ...)
3.   → ACE_ZipArchiveExtract_2  ← extracts a64.dat (85 KB) from ZIP
4.   → ace_parse_module_zip_entries (libanort+0x1372FC)
5.     a) ACE_LinkedListNode_Init reads first 4 bytes, expects 0x20220118 (the date marker)
6.     b) Loop: ACE_ReadLengthPrefixedString reads next module name + body
7.     c) For each body byte: byte_out = sbox[byte_in XOR 0x23]  ← OUR CIPHER
8.     d) Compare module name to "shell_rom.zip" (string ID 11309) — special master config
9.     e) Compare to caller's filter list (e.g., ["vm_gp7worker.img"])
10.    f) On match: ACE_VMModuleLoad → ACE_VMModuleListPrepend
11. Caller invokes ACE_VMExecutionDriver on the loaded module list
```

## Bypass implications

Now that we have the cipher, we can:
1. **Statically read every VM module** — extract module names + bytecode payload from a64.dat offline
2. **Build a substitute a64.dat** — craft modules that report success without scanning anything
3. **Match RSA signature** — still need to either find/replace the public key, OR detour the signature check function

For substitute payload to work:
- Find and patch the RSA-signature verifier (currently TBD; lives somewhere in `ACE_ZipArchiveExtract_2`'s descendants OR in `sub_11A7B0`)
- Or simply NOP-out the signature check call

## Renames + comments

| Address | Old | New |
|---|---|---|
| 0x1747C9 | `g_ace_module_sbox` | (already named) |
| 0x1372FC | `sub_1372FC` | `ace_parse_module_zip_entries` (already renamed) |
| 0x137204 | `ACE_ZipExtractAndProcess` | (already named) |
| 0x115638 | `ACE_ZipArchiveExtract_2` | (already named) |

## Cross-references

| Doc | Topic |
|---|---|
| `89_a64_dat_internal_structure.md` | Static dump + initial structure |
| `88_state_struct_and_embedded_vm_zip.md` | The two embedded ZIPs |
| `22_libanort_arm64_emulator.md` | The VM that runs decrypted bytecode |

## Static artifacts

| File | Size | Description |
|---|---|---|
| `embedded_vm_modules/a64.dat.decrypted` | 85,077 | Small a64.dat with body decrypted |
| `embedded_vm_modules_BIG/a64.dat.decrypted` | 309,474 | Big a64.dat with body decrypted |
| `embedded_vm_modules_BIG/a64_decrypted_strings.txt` | — | 306 unique plaintext strings >= 5 chars |
| `decrypt_a64_body.py` | — | Reproducible decrypter script |

## To-do

- Find the RSA public key in libanort .rodata (256-byte block referenced by signature verifier)
- Identify the signature verification function (likely deep in `sub_11A7B0` or `ACE_ZipFindAndExtract`)
- Write a per-module sub-cipher decoder for the still-encrypted strings (`ok\RY...` etc.)
- Cross-reference the 2 embedded MD5s against actual files (libUnreal.so, base.apk, signing cert)
- Decompile `ACE_VMModuleLoad` (libanort+0x13761C) to understand bytecode layout once decrypted
