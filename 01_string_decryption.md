# ACE String Decryption — VERIFIED

## Big picture

Every "interesting" string in libanogs.so is XOR-encrypted in `.rodata`. Three pieces:

1. **Encrypted string table** — `0x109A30` to `0x11EF44` (91,284 bytes). Set in stone for this binary.
2. **100 explicit decoder functions** — `ace_decrypt_xor00 .. ace_decrypt_xor63`. Each takes a `uint16_t offset` argument and returns a `const char*`. Each uses a unique `(XOR_CONST, ADD_CONST)` pair derived from its ordinal.
3. **One generic decoder** — `ace_decrypt_string` (0x36D764). Routes through the same 100-decoder family using a fixed `XOR=0x40, ADD=6` (this IS decoder 0x40). Takes the table offset, looks up the encrypted bytes, and writes the plaintext into the **decrypted string cache** at a parallel offset.

## Per-entry layout

Each encrypted string entry in the table:

```
[key_byte][encrypted_length_byte][encrypted_data ... length bytes][integrity_byte]
```

**Decryption (per-decoder ordinal `N`):**
```python
XOR_CONST = N
ADD_CONST = 7 - (N % 7) or 7 if N%7 == 0
key       = table[offset]                  # first byte, must be != 0
length    = table[offset + 1] ^ key & 0xFF
output    = []
checksum  = 0xFF
k         = key
for i in range(length):
    b = table[offset + 2 + i] ^ (k & 0xFF)
    output.append(b)
    checksum ^= b
    k = ((k + i) ^ XOR_CONST) + ADD_CONST   # k stays uint32
integrity = table[offset + 2 + length]
assert integrity ^ checksum ^ key == 0xFF   # validation
```

## Key-storage / cache layout

- `ace_get_encrypted_string_table_base()` → `0x109A30` (the encrypted bytes).
- `ace_get_decrypted_string_cache_base()` → another big chunk that **mirrors** the table in size. After a string is decrypted once, its plaintext is written here so subsequent calls return the cached plaintext directly.
- `g_string_integrity_failed` (`byte_58D290`) — set to 1 when integrity check fails (anti-tamper signal).

## The 100-decoder family

| Ordinal | Function | XOR_CONST | ADD_CONST | Notes |
|---|---|---|---|---|
| 0x00 | `ace_decrypt_xor00` | 0 | 7 | |
| 0x01 | `ace_decrypt_xor01` | 1 | 6 | |
| ... | ... | ... | ... | |
| 0x07 | `ace_decrypt_xor07` | 7 | 7 | (N%7==0) |
| 0x09 | `ace_decrypt_xor09` | 9 | 5 | |
| 0x17 | `ace_decrypt_xor17` | 23 | 5 | |
| 0x18 | `ace_decrypt_xor18` | 24 | 4 | |
| 0x1B | `ace_decrypt_xor1B` | 27 | 1 | |
| 0x1F | `ace_decrypt_xor1F` | 31 | 4 | |
| 0x28 | `ace_decrypt_xor28` | 40 | 1 | |
| 0x3D | `ace_decrypt_xor3D` | 61 | 4 | |
| 0x40 | `ace_decrypt_xor40` (≡ `ace_decrypt_string`) | 64 | 6 | **default for class names** |
| 0x46 | `ace_decrypt_xor46` | 70 | 7 | |
| 0x4D | `ace_decrypt_xor4D` | 77 | 7 | |
| 0x5B | `ace_decrypt_xor5B` | 91 | 7 | |
| 0x5D | `ace_decrypt_xor5D` | 93 | 5 | |
| 0x62 | `ace_decrypt_xor62` | 98 | 2 | (used in ace_custom_syscall_handler error msg) |
| 0x63 | `ace_decrypt_xor63` | 99 | 1 | last |

Full closed form: `ADD_CONST = ((-XOR_CONST) % 7) or 7 if it's 0`. Equivalently: `ADD = 7 - (XOR%7); if ADD==0 then 7`.

## The decoder dispatch table

Located at `0x57E4A4` — array of 100 function pointers (800 bytes). Indexed by `index % 100`.

The single-function generic decoder `ace_decrypt_string` does NOT dispatch through this; it hard-codes the 0x40 algorithm inline (as we verified at 0x36D7F0: `v15 = (v18 ^ 0x40) + 6`).

## Why use this scheme?

- Cheap at runtime (4 simple ops per byte, no real key material in code).
- Defeats `strings(1)` — the binary's `.rodata` shows only key bytes + ciphertext.
- Each decoder variant means a single static-analysis tool sees 100 *different* decryption routines, even though the algorithm is identical (only constants change).
- The integrity byte means tampered decrypted text is detected; ACE flags `g_string_integrity_failed` and proceeds to its anti-tamper response (which in libanort.so ends in `exit_group(7)` after 2 failures; in libanogs.so the failure is logged but not auto-killed).

## Anti-tamper notes

- libanogs decoders read the table without atomics (single-threaded init).
- libanort decoders go through `ACE_AtomicLoad/Store` for thread-safe access AND have a kill-on-failure-twice anti-tamper.
- The generic `ace_decrypt_string` caches the result (subsequent calls = O(1)).

## Verified strings

| Index | Decoder | Decrypted text | Used as |
|---|---|---|---|
| 2970 | 0x46 | `init` | JNI method name |
| 2977 | 0x4D | `setuserinfo` | JNI method name |
| 2991 | 0x5B | `setuserinfoex` | JNI method name |
| 3007 | 0x07 | `setgamestatus` | JNI method name |
| 3023 | 0x17 | `getsdkantidata` | JNI method name |
| 3040 | 0x28 | `setsenddatatosvrcb` | JNI method name |
| 3061 | 0x3D | `senddatatosdk` | JNI method name |
| 3077 | 0x4D | `senddatatosvr` | JNI method name |
| 3093 | 0x5D | `onruntimeinfo` | JNI method name |
| 3109 | 0x09 | `hasMatchRate` | JNI method name |
| 3124 | 0x18 | `(I)I` | JNI signature |
| 3131 | 0x1F | `([BI)V` | JNI signature |
| 3140 | 0x28 | `(Ljava/lang/Object;)V` | JNI signature |
| 3164 | 0x40 | `com/tss/gamedemo/Game` | First FindClass arg |
| 49827 | 0x1B | `gcloud` | Validate-and-dispatch ID |

## Bypass implications

- **Stubbing `ace_decrypt_string`** to always return an empty string `""` would crash ACE at first FindClass (NULL class lookup). Not viable.
- **Forcing `g_string_integrity_failed = 0`** disables the soft anti-tamper signal. But it's only one of many.
- **Replacing decoder bodies with NOPs** breaks every internal string lookup → hard crash.
- **For full emulation** we just need to reproduce the exact algorithm — which we have.

## Standalone-scanner caveat

The skill's "scan all 100 decoders, accept ones passing integrity check" approach produces FALSE POSITIVES for short strings (≤8 bytes) where multiple decoder constants happen to satisfy the 1-byte integrity check. Always use the **explicit decoder ordinal** from the disassembly when the string matters; only use the scanner for high-confidence long strings. See `decrypt_explicit.py` in this directory for the proper approach.
