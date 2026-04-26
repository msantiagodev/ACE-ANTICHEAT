# The 7 Conditionally-Disabled Scanners

## The mechanism

`ace_register_all_scanner_modules` (libanogs+0x28B8A8) registers 37 scanner modules. The 4th argument to `ace_register_scanner_module` is the `enabled` flag (bool). Some calls pass `(v3 & 1) == 0` as enabled, where `v3 = ace_check_v3_flag()`.

Since `ace_check_v3_flag` (libanogs+0x245494) → `sub_1DA214()` (libanogs+0x1DA214) **always returns 1**:

```c
ace_check_v3_flag() returns true → v3 = 1 → (v3 & 1) == 0 is FALSE → enabled = 0
```

So those scanners get registered with `enabled=0` and never run. **They are dead code in this build.**

## The 7 disabled-by-v3-flag scanners

| # | Decoded name (from xor decoder) | vtable | Purpose |
|---|---|---|---|
| 1 | (id 16743 via xor2B) | unknown | unnamed conditional scanner |
| 2 | (id 5760 via xor3C) | `vtable_module_anti_virapp` | Anti-virtualized-app detection |
| 3 | (id 31704 via xor04) | `vtable_module_black_app` | Blacklisted app detection |
| 4 | (id 31667 via xor43) | `vtable_module_trusted_scanner` | Trust check |
| 5 | (id 49952 via xor34) | `vtable_module_anti_cheat_open_id` | Account ID anti-cheat |
| 6 | (id 31651 via xor33) | (elf_hook_scan) | **ELF section hook detection** — would catch our Dobby hooks! |
| 7 | (id 54769 via xor45) | `vtable_module_cps_new3` | CPS variant 3 |

The most important one for us: **#6 = `elf_hook_scan`**. It's specifically designed to detect inline hooks in `.text` sections. Because v3 returns 1, this scanner is currently disabled, which is why our Dobby hooks survive.

**WARNING:** If a future server config update changes `sub_1DA214` to return 0 (e.g., via a downloaded VM module that patches the function), these scanners will activate.

## Other gating flags

| Function | Address | Returns | Used for |
|---|---|---|---|
| `ace_check_v3_flag` | 0x245494 | always 1 | gate the 7 above |
| `ace_check_v4_flag` | 0x245264 | 3 if ctx+128==2005 else 1 | gate FakeToken/PE-rep scanners |
| `ace_check_v_flag_3` | 0x245328 | 0 if ctx+128==2005 else 4 | gate anoscan |
| `ace_check_token_enable` | 0x245440 | true if ctx+128 is in dword_EB630 list (size=15) or ==2005 | gate user_tag scanner |

The `ctx+128` field is the **platform ID**. Value 2005 means "current build's platform". The flag checks gate scanners based on which platform the SDK was built for.

## How to verify on a real device

Read these locations after game start:
- `libanogs.so + 0x245494` — should resolve to `ace_check_v3_flag`
- Call it (or simulate via `*(uint32_t*)(libanogs+0x1DA260) = ?` — the byte that says `MOV W0, #1; RET`)

To **re-enable** the 7 scanners, patch `sub_1DA214` to return 0:

```c
const uint8_t MOV_X0_0_RET[] = { 0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6 };
DobbyCodePatch(libanogs_base + 0x1DA214, MOV_X0_0_RET, 8);
```

But why would we want them ON? Only if testing detection capabilities or doing red-team work.

To **keep them disabled** (which we want for survival), don't touch this. The default state is fine.

## What the active 28 scanners include (summary)

From `ace_register_all_scanner_modules` (37 total - 7 disabled = 30; minus 2 hard-disabled like tablet/anti_clicker = 28 active):

| Function | Module name (decoded) |
|---|---|
| `ace_init_anti_virapp_module` | anti_virapp (DISABLED via v3) |
| `ace_init_black_app_module` | black_app (DISABLED via v3) |
| `ace_init_cps_new_module` | cps_new |
| `ace_init_anoscan_module` | anoscan |
| `ace_init_module2_module` | module2 |
| `ace_init_process_module` | process |
| `ace_init_anti_root_module` | anti_root |
| `ace_init_elf_hook_scan_module` | elf_hook_scan (DISABLED via v3) |
| `ace_init_collect_apk_module` | collect_apk |
| `ace_init_pe_rep_module` | pe_rep |
| `ace_init_env_chk_module` | env_chk |
| `ace_init_cc2_module` | cc2 |
| `ace_init_info_publisher_module` | info_publisher |
| `ace_init_live_module` | live |
| `ace_init_anti_clicker_module` | anti_clicker |
| `ace_get_singleton_frida_scan` | frida_scan |
| `ace_get_singleton_cps_new` | cps_new |
| `ace_get_singleton_cert3` | cert3 |
| (many more) | various |

So the build has these v3-disabled: `anti_virapp`, `black_app`, `trusted_scanner`, `anti_cheat_open_id`, `elf_hook_scan`, `cps_new3`, plus 1 unnamed.

## Bypass implications

Already covered by Tier 1 (`ace_register_scanner_module` filter). Even if v3 flag flips, our filter drops the named scanners by name (cert3, module2, various_opcode, anti_root, process, anoscan, FakeToken, shell_checker, auto_defence3, anti_clicker2).

Adding `elf_hook_scan` to the blocklist is wise as a safety net:

```cpp
static const char* kBlockedScanners[] = {
    "various_opcode", "module2", "cert3", "anti_root", "process",
    "anoscan", "FakeToken", "shell_checker", "auto_defence3",
    "anti_clicker2",
    "elf_hook_scan",   // ← NEW: in case server flips v3 flag
    "anti_virapp",     // ← NEW: defense in depth
    "black_app",       // ← NEW
    "trusted_scanner", // ← NEW
    "anti_cheat_open_id", // ← NEW
    "cps_new3",        // ← NEW
};
```

Would add 6 more block entries to defend against server-side flag flips.
