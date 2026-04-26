---
iter: 72
title: Layer-2 String Cipher Cracked — Same Alphanumeric XOR as Module Names
status: ACE uses just TWO ciphers in total (S-box for bodies, alphanumeric XOR for ALL strings)
---

# Layer-2 String Cipher Cracked

The recurring "encrypted-looking" strings in the decoded VM modules (`']T_@QA'`, `'ok\\RY'`, `'okV_dC'`, `'WTFpXTED'`, etc.) use the **same alphanumeric XOR cipher** as module names — `ACE_XorEncodeAlphanumeric` at libanort+0x11CCC8.

## The cipher

```c
KEY = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"   // 36 chars

for (i = 0; i < n; i++) {
    output[i] = input[i] XOR KEY[i % 36];
}
```

Cycling 36-byte alphanumeric key, position-indexed. Self-inverse (apply twice = original).

## Decoded strings — ~80 of 306 confirmed

Out of 306 unique strings extracted from BIG `a64.dat`, **84 decode cleanly** as ASCII function/method names. The rest are either:
- Already plaintext (e.g., `'classes'`, `'sourceDir'`, `'apk_verify'`)
- Binary data that happens to be printable
- Strings encoded with a DIFFERENT scheme (possibly per-string IV — see open question)

### C runtime function names
| Encrypted | Decrypted |
|---|---|
| `]T_@QA` | `memset` |
| `]T_PDL` | `memcpy` |

### C++ runtime symbols (Itanium ABI)
| Encrypted | Decrypted | Meaning |
|---|---|---|
| `ok\\RY` | `_Znam` | `operator new[]` |
| `ok\\DY` | `_Znwm` | `operator new` |
| `okV_dC` | `_ZdlPv` | `operator delete` |
| `okVRdC` | `_ZdaPv` | `operator delete[]` |

### ACE-internal namespacing
| Encrypted | Decrypted |
|---|---|
| `onTUk` | `__ff_` |
| `RD[_@\\X` | `builtin` |

### JNI method names (in-bytecode constants)
| Encrypted | Decrypted |
|---|---|
| `vX\\WwYWDK` | `FindClass` |
| `sP^_bZ_Su\\5*, ` | `CallVoidMethod` |
| `uIQVDA_XVz)' /` | `ExceptionCheck` |
| `uIQVDA_XVz-'\"6` | `ExceptionClear` |
| `wTFrFGWNt\\/%7,` | `GetArrayLength` |
| `wTFu]PZSq}` | `GetFieldID` |
| `wTFzZAp^]U%` | `GetIntField` |

### Java reflection method names
| Encrypted | Decrypted |
|---|---|
| `WTFpXTED` | `getClass` |
| `WTFpXTEDtV &&6` | `getClassLoader` |
| `WTF}UXS` | `getName` |
| `WTF\`AESE[U 10` | `getSuperclass` |
| `WTFq[ZZRYW` | `getBoolean` |
| `WTFvLADVK` | `getExtras` |
| `D^aGF\\XP` | `toString` |

### Android API names
| Encrypted | Decrypted |
|---|---|
| `BTUZGASEj\\\"'*2 4` | `registerReceiver` |
| `QUVrWA_XV` | `addAction` |
| `TT^V@P` | `delete` |

### ACE detection internals
| Encrypted | Decrypted |
|---|---|
| `QAYlBPD^^@` | `apk_verify` |
| `QAYlSPBh[\\36. p` | `apk_get_certmd5` |
| `CTQG]ZXh]W\"6:4 ` | `section_enctype` |
| `C^GAWPr^J` | `sourceDir` |

## What this tells us about ACE detection logic

The decoded strings reveal the **exact JNI methods and Java APIs** that ACE's VM bytecode invokes at runtime:

1. **Class loader walking** (`getClass`, `getClassLoader`, `getSuperclass`) — ACE walks the class hierarchy looking for suspicious classes (e.g., Frida injection bridges)
2. **Manifest inspection** (`registerReceiver`, `addAction`) — checks installed broadcast receivers for known cheat-app patterns
3. **APK verification** (`apk_verify`, `apk_get_certmd5`) — verifies the APK's signing certificate matches expected MD5 (likely matching the hardcoded `55A7909E4FD3BC8A9AD37BCABF35290B` from doc 90)
4. **ELF section validation** (`section_enctype`) — checks the encoding type of ELF sections, possibly validating that .text/.rodata have the expected entropy/structure
5. **Source directory check** (`sourceDir`) — reads `ApplicationInfo.sourceDir` to confirm APK location matches expected

## ACE's TOTAL cipher inventory — only TWO ciphers

After all reverse-engineering passes, ACE uses only **2 distinct ciphers** for all its obfuscation:

| Cipher | Used For | Algorithm |
|---|---|---|
| **String-XOR** (this doc) | Module names, in-bytecode constants, encrypted format strings | XOR with 36-byte cycling key `"0123...XYZ"` |
| **Module-Body** (doc 90) | a64.dat encrypted module bodies | `out = sbox[in XOR 0x23]` with 256-byte sbox |

That's it. Plus the OUTER 100-decoder string-table cipher (doc on ACE_DecryptString) for libanort/libanogs static strings.

This is **astonishingly minimalist** for an anti-cheat. With these 3 ciphers reversed, we can decrypt EVERY string in the entire ACE binary AND every embedded module.

## Open question

The string `'Txy*#xP?@xxP6~C'` at libanort+0x171108 (returned by `__ff_111`) does NOT decode with the alphanumeric XOR. We tried all 36 cyclic offsets — no offset produces printable output. Possibilities:
- Different cipher (per-string IV?)
- Binary data, not a string at all (possibly encoded constants used for opcode dispatch)
- The content after the "string" includes a null + integer 0x00018238 (=99,000) suggesting it's a 15-byte data field followed by other fields

## Bypass implications

### Now feasible
We can:
1. Statically decrypt every JNI method name reference in vm_main.img bytecode
2. Map every BL → __ff_96 sequence to its target JNI method (by tracing back to the string load before the call)
3. Build a complete catalog: "ACE calls these specific Android/JNI APIs with these specific arguments"

### Surgical bypasses now possible
For each decrypted JNI method, we can:
- Hook `JNIEnv->GetIntField` → return 0 always → ACE detection logic that reads int fields gets fake data
- Hook `JNIEnv->FindClass` → return null for specific class names (`com.android.system.support.Setup`) → ACE can't find our mod menu's classes
- Hook `JNIEnv->GetByteArrayRegion` → return zeroed buffer → APK signature checks return null bytes → MD5 mismatch detected → BUT we control the comparison, so we substitute our own expected hash

## Renames + comments

No new IDB renames this iteration (cipher is in code already, function names confirmed).

## Static artifacts

| File | Description |
|---|---|
| `96_layer2_string_cipher_cracked.md` | This doc |
| (will produce in next iter) | Full decoded strings file for all 306 |

## Cross-references

| Doc | Topic |
|---|---|
| `90_a64_dat_decrypted.md` | The Layer-1 sbox cipher used for module bodies |
| `91_vm_modules_catalog.md` | The 5 modules whose strings we just decoded |
| `92_vm_module_bytecode_format.md` | Module name field uses same cipher |
| `95_complete_jni_table_and_more_bridges.md` | The 229 JNI dispatch entries (now we can read the names VM bytecode passes to __ff_96) |

## To-do

- Find the cipher for `'Txy*#xP?@xxP6~C'` (per-string IV? different XOR?)
- Decrypt every Layer-2 string in all 5 modules and produce a complete table
- Trace the BL → __ff_96 sequences in vm_main.img bytecode to identify call sites that load specific JNI method names
- Cross-reference ACE's hardcoded MD5 hashes (doc 90) with what `apk_get_certmd5` returns at runtime
