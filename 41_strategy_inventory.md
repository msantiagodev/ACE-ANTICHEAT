# ACE Detection Strategies — The "_strategy" Keys

ACE has a **strategy system** where each scan capability is gated by a named string. The strings live in the encrypted string table and are referenced at scan time to look up which strategies are active.

## All known _strategy keys

Decoded from libanogs string table (ace_decrypted_strings.txt):

| String | What it gates |
|---|---|
| `strategy_manager` | The strategy manager root. Singleton that holds all the active strategy keys |
| `root_strategy` | All root-detection scanning |
| `virapp_strategy` | Virtual app / sandbox detection (VirtualXposed, Parallel Space, etc.) |
| `ptrace_strategy` | ptrace-based debugger detection |
| `jdb_strategy` | Java debugger (JDB) detection via `isDebuggerConnected` |
| `frida_strategy` | Generic Frida detection (all variants) |
| `frida_server_strategy` | Specifically frida-server process detection |
| `cc_strategy` | "Cheat client" generic detection |
| `opcode_strategy` | Bytecode opcode anomaly detection (catches modified .text) |
| `mem_watch_strategy` | Memory region watcher (catches breakpoints/inline patches) |
| `mem_trap_strategy` | Memory trap (catches ROP-style attacks?) |
| `mem_inotify_strategy` | inotify-watcher on memory regions (catches RW changes) |
| `xposed_strategy` | Xposed framework detection |
| `substrate_strategy` | iOS Substrate detection |

## All known _scan strings

| String | What it does |
|---|---|
| `cps_light_scan` | Lightweight CPS (Continuous Process Scan) variant |
| `opcode_scan` / `opcode_scan2` / `opcode_scan3` | Opcode integrity scans (3 levels of strictness) |
| `frida_scan` | Run frida detection scan |
| `trusted_scanner` | Run trusted-app scanner (whitelist check) |
| `elf_hook_scan` | ELF .text hook detection (catches Dobby) |
| `shell_checker` | Shell-protector integrity scan |
| `scan_by_detect` | Trigger scan from detection event |
| `axml_scanner` / `axml_scan` | Android XML manifest scanner (looks for tampered AndroidManifest) |
| `x86_sys_scan` | x86 system scanner (emulator detection) |
| `attest_scan_objvm` | Attestation scan via VM (ObjVM = Object VM, the libanogs expression-tree VM) |
| `cert_scaner_ohos` | Certificate scan for OHOS (Huawei) |
| `force_usertag_scan` | Force user-tag scan (verify user tag matches account) |
| `force_emu_scan` | Force emulator scan (always run, skip throttle) |
| `force_cp_scan` / `force_cp2_scan` / `force_cp3_scan` | Force cloud-phone scans (3 variants) |
| `force_scan_live` | Force live scan (don't use cached result) |

## All known _check strings

| String | What it does |
|---|---|
| `device_check_module` | Device integrity check module |
| `env_chk` | Environment check module |
| `cert_content_chk` | Certificate content (modulus) check |
| `vos_chk` | VOS (Virtual OS) check |
| `__tss_test` | TSS test marker (development holdover?) |
| `sensor_detect` | Sensor-based detection (Mobile Magic check via accelerometer) |

## Detection-related globals

| String | Use |
|---|---|
| `is_root` | Reports whether device is rooted |
| `gp3_no_root` | Gameplay 3 mode without root |
| `gp4_no_root` | Gameplay 4 mode without root |
| `unlock_root` | Unlock root scanner |
| `mem_trap_no_root` | Memory trap (no-root variant) |
| `dual_app_files` | Dual-app filesystem scanner |
| `dual_app_uid` | Dual-app UID scanner |
| `dual_uid_not_same` | Dual-UID mismatch flag |
| `dual_uid_cnt` | Dual-app UID count |
| `dual_uid_%d` | Per-UID format |
| `root_process_exists` | Root process detection result |
| `emulator_name` | Detected emulator name |
| `NotEmulator` | "Not an emulator" result |
| `antiemulator` | Anti-emulator master strategy |
| `anti_debugger` | Anti-debugger master strategy |
| `force_anti_debugger` | Force anti-debugger always-on |

## Boolean strategy results

Each strategy has a result bit. ACE writes 1/0 to a corresponding state byte to indicate detected/not.

The result bytes live in the registry struct at known offsets. By patching these to always-zero, we could simulate "all strategies clear" but ACE's integrity scanner would catch the mismatch.

## How strategies are checked at runtime

```c
// Pseudocode from ACE_HashCompute path
strategy_str = ACE_DecryptString(ID);  // e.g., "frida_strategy"
result = ace_strategy_lookup(strategy_singleton, strategy_str);
if (result.enabled) {
    if (run_scan(result.scanner_callback)) {
        ACE_SetDetectionFlag(detection_ctx, FLAG_BIT, ...);
    }
}
```

So ACE essentially has a hash table from strategy name → enabled/scanner callback.

## Bypass implications

Three approaches:

1. **Hook the strategy lookup** to always return "disabled". ACE thinks strategies are off, doesn't run them.
2. **Hook the scanner callbacks** individually. We've already done this (Tier 1).
3. **Patch the `gen_vm_handler.img` opcode mapping** (advanced). This would require runtime VM module manipulation.

The cleanest option is the existing Tier 1 (drop scanners by name). All these strategies are eventually fed to one of the 28 active scanners, which we already filter.

## The `gen_vm_handler.img` filename (libanogs string 45823)

Discovered: the `.img` modules within `ob_*.zip` are named systematically. We've found `gen_vm_handler.img` referenced in libanogs strings. Other likely module names:
- `gen_*.img` — various code generators
- `ts2_modules` — strings reference this as a list
- `device_check_module` — the device check module
- `zygisk_module` — Zygisk (Magisk for processes)
- `zygisk_module_entry` — Zygisk entry point reference
- `main_module` / `main_module_path` — main native module reference
- `x86_module_cnt` — x86 emulator module count

So ACE has detection specifically for **Zygisk** (a Magisk-based root hider). Important for our user (uses MuMu emulator which doesn't have Zygisk).

## To-do

- For each strategy, find which scanner(s) it gates
- For each scanner, find which detection bit(s) it sets
- For each detection bit, find the kill threshold (how many fires = ban)
