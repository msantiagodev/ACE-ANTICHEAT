# `g_anort_config_flags` — All Known Bits

`g_anort_config_flags` (libanort+0x171118, alias `dword_171118`) is a 32-bit configuration mask that gates many ACE behaviors. Setting/clearing specific bits enables or disables detection paths.

This is referenced in 18 functions throughout libanort. We've now decoded **11 of 32 bits** by walking each xref.

## Verified bits — comprehensive table

| Bit | Mask | Set means | Found in |
|---|---|---|---|
| 1 | `0x02` | Enable MZ/PE buffer scanner | `ace_buffer_mz_pe_scanner` (libanort+0x3AF80) |
| 1 | `0x02` | Enable ZIP-content MZ/PE scanner | `ACE_ZipMzPeContentScanner` (libanort+0x86DFC) |
| 2 | `0x04` | Enable detection list orchestration | `ace_detection_orchestrator_main` (libanort+0xF6B98) |
| 3 | `0x08` | **DISABLES** composite hash computation (returns short-form) | `ACE_ComputeCompositeHash` (libanort+0x2CC18) |
| 3 | `0x08` | Enable JNI class validator report | `ACE_JniClassValidatorReport` (libanort+0x4E334) — uses `flags<<28>>31` (bit-3 sign-extend) |
| 3 | `0x08` | Enable XML-config / JNI-class report path | `ACE_XmlConfigJniClassReport` (libanort+0x532F8) |
| 3 | `0x08` | Enable ZIP archive integrity check | `ACE_ZipArchiveIntegrityCheck_Wrapper` (libanort+0x8DA60) |
| 4 | `0x10` | Enable JNI detection scan phase | `ACE_JniDetectionScanWrapper` (libanort+0x91600) |
| 5 | `0x20` | Enable detection reporting | `ACE_DetectionFlagChecker` (libanort+0x5DE94) |
| 5 | `0x20` | Enable directory-file boundary signature validator | `ACE_DirectoryBoundarySigValidator` (libanort+0x940F0) |
| 5 | `0x20` | Enable signal-handler signature validator | `ACE_SignalHandlerSigValidator` (libanort+0xA00F0) |
| 6 | `0x40` | Enable ZIP-extract / config-value-true scanner chain | `ACE_ZipExtractValidateWrapper` (libanort+0x96D5C) |
| 8 | `0x100` | **DISABLES** `ACE_ConfigUpdateFromServer` | `ACE_ConfigUpdateFromServer` (libanort+0x12CE98) |
| 13 | `0x2000` | Gate the string-comparison early validator | `ACE_StringConfigEarlyValidator` (libanort+0x120128) — fast-path required |
| 14 | `0x4000` | Enable dynamic symbol resolution path | `ACE_DynamicSymbolResolver` (libanort+0x45CE8) |
| 16 | `0x10000` | Enable conditional struct init (mutex-protected setup) | `ACE_ConditionalStructInit` (libanort+0x2A734) |
| 16 | `0x10000` | Enable hash-chain aggregator full path | `ACE_HashChainAggregator` (libanort+0x9E9B0) |
| 16 | `0x10000` | Enable indexed event signal aggregator | `ACE_IndexedEventSignalAggregator` (libanort+0x9EFF8) |
| 17 | `0x20000` | INVERTED — when SET, the early validator passes false to `ACE_ValidateConfig`. Compliance-mode gate | `ACE_StringConfigEarlyValidator` (libanort+0x120128) |

## Detailed behaviors

### Bit 1 (`0x02`) — MZ/PE scanners
Two scanners gated by this bit. The `ace_buffer_mz_pe_scanner` checks raw memory buffers for PE signatures (catches Mono-style .NET assemblies); `ACE_ZipMzPeContentScanner` checks ZIP entries for the same.

### Bit 3 (`0x08`) — JNI / hash / ZIP integrity master switch
This is the most-checked single bit (4 different use sites). Likely the "JNI/Java-side validation" master switch in the ACE config schema.

In `ACE_ComputeCompositeHash`: when **set**, the function takes a short-circuit path returning `v17` (XOR of partial state). When **clear**, it falls through to `sub_43DAC(v16)`-based long form. So bit 3 SET = abbreviated hash mode; CLEAR = full hash mode.

### Bit 4 (`0x10`) — JNI detection scan
Gates `ace_jni_detection_scan_phase` from running. Without this bit set, the JNI bridge scan doesn't fire.

### Bit 5 (`0x20`) — Detection reporting / signature validation umbrella
Gates 3 functions:
- `ACE_DetectionFlagChecker` — actual report-build trunk
- `ACE_DirectoryBoundarySigValidator` — directory file boundary scan with signature
- `ACE_SignalHandlerSigValidator` — signal handler scan with signature validation

So clearing bit 5 disables ALL signature-based validation reporting.

### Bit 6 (`0x40`) — ZIP extract & validate
Gates the `ACE_ZipExtractAndValidate` → `ACE_ConfigValueTrueCheck` → `UE_esu__s_98110` chain. Used for in-memory ZIP archive scanning of obstub modules.

### Bit 8 (`0x100`) — config update kill switch (Tier 5)

In `ACE_ConfigUpdateFromServer`:
```c
if ((dword_171118 & 0x100) != 0 || *(_BYTE*)(a1 + 24) != 0)
    return 0;  // Skip the entire config update flow
```

When bit 0x100 is set, the function exits immediately, never reading the local config file or rebuilding the report packet. **Tier 5** of our bypass.

### Bit 13 (`0x2000`) — string config early validator gate

In `ACE_StringConfigEarlyValidator`:
```c
if ((g_anort_config_flags & 0x2000) != 0) {
    // do guarded one-time string compare against decrypted constant
    // if matches, run ACE_ValidateConfig
}
return 0;  // bit clear = always returns false
```

Bit 13 SET = run the string compare and config validation; CLEAR = skip entirely. This bit appears to be a "compliance mode" enabler — when set, ACE matches a specific string against the config and runs validation.

### Bit 14 (`0x4000`) — dynamic symbol resolution

In `ACE_DynamicSymbolResolver`:
```c
if ((dword_171118 & 0x4000) == 0)
    take_alternate_path();  // skip dynamic resolution
else
    proceed_with_dlopen_dlsym_chain();
```

When CLEAR (default), ACE skips dynamic dlsym chains and uses pre-resolved offsets. This is normally what we want.

### Bit 16 (`0x10000`) — hash-chain master switch

Three functions gated by this bit. In `ACE_HashChainAggregator`:
```c
if ((g_anort_config_flags & 0x10000) != 0) {
    // run full hash chain: walk dword_16A400[] -> aUINFLTF[80*i]
    // compute MD5, build event signals
}
return signal_or_zero;
```

When CLEAR, hash chain is bypassed entirely. When SET, ACE walks an indexed table at `dword_16A400` (libanort+0x16A400) and computes hash chains over `aUINFLTF[80*idx]` entries.

### Bit 17 (`0x20000`) — config validation strict-mode invert

In `ACE_StringConfigEarlyValidator`:
```c
v14 = (v8 & 0x20000) == 0;   // INVERTED!
ACE_ValidateConfig(ConfigObj, ..., v14);
```

When bit 17 is **clear** (`v14 = true`), validation runs in strict mode.
When bit 17 is **set** (`v14 = false`), validation runs in lenient mode.

Pairs with bit 13 — bit 13 enables the validator at all, bit 17 toggles its strictness.

## Behavior of bit 0x20 (detection reporting)

In `ACE_DetectionFlagChecker`:
```c
v21 = g_anort_config_flags & 0x20;
if (v21 == 0)
    return 0;  // No detection report this round
// else build and send report
```

When bit 0x20 is set, ACE actively builds detection reports. Clearing it would prevent report submission.

## What we still don't know (21 bits)

The other 21 bits are not referenced by any direct AND-mask in libanort's decompiled code. Possible explanations:
- They live in a different config field (the `+24` offset check in `ACE_ConfigUpdateFromServer` suggests a separate `cfg_byte` global).
- They're checked via the obfuscated-VM pathway and don't appear as plain `&0x...` constants.
- They're indirectly accessed through `ACE_GetField48` and friends.

## How to enumerate bits programmatically

```python
# IDA script to find all bits checked
import ida_xref
xrefs = list_xrefs_to(g_anort_config_flags_addr)
for xref in xrefs:
    fn = get_function(xref)
    # Find AND with constants in fn
    for instr in fn.instructions:
        if instr.op == "AND" and instr.operands[1].is_constant:
            print(f"{fn.name}: bit 0x{instr.operands[1].value:x}")
```

## Setting flag bits

There are several ways to flip bits in this global:

**At runtime (our Tier 5 approach):**
```cpp
uint32_t* cfg = (uint32_t*)(libanort_base + 0x171118);
*cfg |= 0x100;  // Disable config update
```

**Via mprotect + write:**
```cpp
DobbyCodePatch(cfg, &(uint32_t){*cfg | 0x100}, 4);
```

**Via the obfuscated config setter** (we haven't fully traced this):
The flags can also be set via a config-validation chain (`ACE_ValidateConfig`). Server-pushed config can flip these bits dynamically. By blocking config updates (Tier 5), we prevent server from changing flags.

## Bypass implications — composite mask

For our bypass, we want to **clear** every bit that gates a detection scanner and **set** every bit that disables ACE behavior. The optimal mask:

```cpp
// Clear (disable scanners)
*cfg &= ~0x02;       // disable MZ/PE buffer + ZIP-MZ/PE
*cfg &= ~0x04;       // disable detection list orchestration
*cfg &= ~0x08;       // disable JNI/ZIP integrity master
*cfg &= ~0x10;       // disable JNI detection scan
*cfg &= ~0x20;       // disable signature validator umbrella
*cfg &= ~0x40;       // disable ZIP extract+validate
*cfg &= ~0x2000;     // disable string config early validator
*cfg &= ~0x4000;     // (default clear; alternate path active)
*cfg &= ~0x10000;    // disable hash chain aggregator

// Set (disable ACE behavior)
*cfg |= 0x100;       // disable config update from server (Tier 5)
*cfg |= 0x20000;     // force lenient config validation (paired with bit 13)
```

**However** — bits 1, 5, 16 (etc.) being clear may trip ACE's own self-check (it expects certain bits set under normal operation). Setting only bit 0x100 is the proven-safe minimum.

We've validated **only `*cfg |= 0x100`** in production. The rest are theoretical and would need REPL-bridge testing.

## CONFIRMED: g_anort_config_flags has NO writers in libanort

A complete xref-walk of `g_anort_config_flags` (libanort+0x171118) shows **all 18 references are reads** (`& mask` patterns only). There are **zero writes** anywhere in libanort.so.

This means:
1. **The variable starts as 0** (BSS-default-zero), and stays 0 for the entire process lifetime in the un-hooked binary.
2. **All flag-gated code paths take the "default" branch** — for some this means scanner DISABLED (e.g., bit 16 hash chain), for others it means "alternate path" (e.g., bit 14 dynamic dlsym).
3. **Our Tier 5 bypass write (`*flags |= 0x100`) is the only known writer** anywhere in the runtime.

Why does ACE leave the flag at 0? Probable explanations:
- The flag exists for **future expansion** — bits to be set by future updates that flip behaviors.
- Some bits are checked for "force on" semantics in non-default builds (debug/test).
- The shipped binary uses a baseline detection set without the flag-gated extras.

This means the bypass surface is simpler than feared: the only flag manipulation we need is Tier 5 (`|= 0x100`), and we don't need to worry about dynamic flag changes from server config.

## To-do

- Test in REPL bridge: clear each bit individually and observe scanner activity changes
- Trace what server-pushed config SETS each bit (which CDN bytes correspond to which bits?)
- Find the "flag mask check" that ACE itself uses to validate flag integrity (probably catches our tampering)
- Look for additional flag globals: `dword_171158`, `dword_171160` (referenced by `ACE_StringConfigEarlyValidator`)
