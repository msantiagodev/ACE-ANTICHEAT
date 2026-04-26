# ACE Expression DSL and Scanner API Surface

ACE has a small **expression DSL** for conditional rules (run rule X only on certain devices/Android versions) and a **scanner API** with named on/off switches. This document catalogs both.

## The Expression DSL

ACE rules can be conditional using these primitive predicates:

| Primitive | Purpose |
|---|---|
| `sys_ver_eq("X")` | Android version equals X |
| `sys_ver_bt("X")` | Android version BIGGER THAN X (>= X) |
| `sys_ver_lt("X")` | Android version LESS THAN X (< X) |
| `brand_contains("X")` | `Build.BRAND` contains substring X |
| `model_contains("X")` | `Build.MODEL` contains substring X |
| `cpu_model_contains("X")` | `/proc/cpuinfo` Hardware field contains X |

These compose with `&&` (AND) and `||` (OR). Examples from the decoded strings:

```
sys_ver_bt("11") && sys_ver_lt("19") && brand_contains("oppo")
sys_ver_bt("11") && sys_ver_lt("19") && brand_contains("oneplus")
```

These rules fire **only on** Oppo or OnePlus devices running Android 11-18 (the actual Android API levels). They likely target known-vulnerable device firmware where additional detection is needed.

## Why the DSL exists

Different Android OEMs ship different system properties, kernel patches, and security policies. A detection that works on a Pixel may false-positive on Xiaomi. ACE uses the DSL to:
1. Apply OEM-specific detections only on those OEMs
2. Suppress detections on devices known to false-positive
3. Run extra checks on devices known to be commonly rooted/exploited

## DSL evaluation

The expression strings are compiled to AST nodes (we documented the AST evaluator at `ace_vm_eval_node` in `13_expression_engine.md`). Each primitive has a corresponding evaluator that reads from cached device info and returns a bool.

## Scanner API — Named on/off switches

ACE has a "scanner manager" with named scanners that can be toggled:

| Open API | Close API | Purpose |
|---|---|---|
| (always on) | `CloseUserTagScan` | User-tag (account) scanner |
| (always on) | `CloseEmulatorScan` | Emulator detection |
| (always on) | `CloseCloudPhoneScan` | Cloud-phone detection |
| (always on) | `CloseAntiProfiler` | Anti-profiler (debugger detection) |
| (always on) | `CloseAntiBlackModule` | Anti-blackmodule (rootkit-like detection) |
| (always on) | `CloseDevInfoCollect:` | Device info collection |
| (always on) | `CloseDevInfoCollectEx:` | Extended device info |
| `OpenMrpcsBridge` | `CloseMrpcsBridge` | Java↔native IPC bridge |
| `OpenVerificationLog` | (always on) | Logging / verification |

Each is selectively callable via the JNI command path. The server can disable specific scans for specific devices.

## Force-scan API

These force-fire scanners that would normally be throttled or disabled:

| String ID | Force-scan name |
|---|---|
| (43729) | `force_usertag_scan` |
| (43751) | `force_emu_scan` |
| (43788) | `force_cp_scan` |
| (43798) | `force_cp2_scan` |
| (43844) | `force_cp3_scan` |
| (43936) | `force_scan_live` |

**`force_emu_scan`**: ignores throttling, scans for emulator immediately. Used when ACE is suspicious.
**`force_cp_scan`**: same for cloud-phone (multiple variants — cp/cp2/cp3 are different scan strategies).

## High-level Scanner API (registered in JNI bridge)

Native methods registered in the JNI table, callable from Java:

| Method | Purpose |
|---|---|
| `ScanRoot` | Run root detection |
| `ScanEmulator` | Run emulator detection |
| `ScanVirApp` | Run virtual-app detection (the 21 signatures) |
| `ScanOpcode` | Run opcode-anomaly scan |
| `ScanCert` | Run certificate scan |
| `ScanTablet` | Run tablet-specific scan |
| `StartSecScan` | Start security scan |
| `MrpcsBridgeCmd` | Send command via IPC bridge |
| `OpenMrpcsBridge` / `CloseMrpcsBridge` | Bridge management |

These are Java-callable APIs. The game's Java code can trigger any scan on demand.

## Setter API (parameter pushing)

| API | Purpose |
|---|---|
| `setuserinfo` | Set user info |
| `setuserinfoex` | Extended user info |
| `setgamestatus` | Set game state |
| `setsenddatatosvrcb` | Set send-to-server callback |
| `SetSecToken:` | Set security token |
| `SetLocaleId:` | Set locale |
| `SetHWDevice` | Set hardware device info |
| `EnableGameReport` | Enable game-side reporting |

The game can push contextual info to ACE — user identity, locale, device fingerprint, etc.

## Sub-modules ACE checks for / depends on

| Name | Purpose |
|---|---|
| `sst_engine_module_name` | SST (Server Side Trust?) engine |
| `anoscan` | ANO scanner namespace |
| `module_exists` | Generic "is module loaded?" check |
| `ModuleBase` | Base for module objects |
| `module_crash` | Module crash handler |
| `zygisk_module` | Zygisk root hider detection |
| `zygisk_module_entry` | Zygisk entry-point inspection |
| `ts2_modules` | TS2 modules registry |
| `anti_blackmodule` | Anti-blackmodule scanner |
| `vos_chk` | VOS (Virtual OS) check |

## Cross-reference: scan strings → bypass tiers

Given our existing 8-tier bypass:

| Scan string | Bypass strategy |
|---|---|
| `frida_scan` | Tier 1 (kill detection scanners that look for Frida paths) |
| `opcode_scan` | Tier 4 (drop scan rule results) |
| `force_emu_scan` | NOT BYPASSED — emulator detected, but game allows it |
| `force_cp_scan` | NOT BYPASSED — but we're not on cloud phone |
| `ScanRoot` | NOT BYPASSED at this level — we don't have root tools installed |
| `ScanCert` | Mitigated by signing with original keystore |
| `MrpcsBridgeCmd` | NOT BYPASSED — could be hardened (Tier 11+) |

## Conditional rule example

A rule with the DSL `sys_ver_bt("11") && brand_contains("oppo")`:
1. ACE evaluates Build.VERSION.SDK_INT >= 11 (always true on modern Android)
2. ACE evaluates Build.BRAND.toLowerCase().contains("oppo")
3. AND combines results
4. If true, run rule's body (e.g., `force_emu_scan`)
5. Else, skip

This means ACE can ship a single ruleset that runs different detection logic per device type.

## To-do

- Find all DSL-using rules in the runtime decoder
- Document the AST node types (likely: AND, OR, NOT, EQ, LT, BT, primitive)
- Test in REPL: hook the DSL evaluator to log every (rule_dsl, device_match_result) tuple
- Map `MrpcsBridgeCmd` IPC protocol — what commands does it accept?
- Cross-reference scan API names with native function pointers in the registry
