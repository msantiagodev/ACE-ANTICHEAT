# ACE Scanner Module Registry — VERIFIED INVENTORY

`ace_register_all_scanner_modules` (`0x28B8A8`, 2,152 bytes) registers all 37 scanner modules into the global scan registry by calling `ace_register_scanner_module` (sub_22D428) once per module.

Signature (effective):
```c
__int64 ace_register_scanner_module(
    registry_t  *registry,    // a1 — the global registry passed through
    void        *prev_module, // chain pointer
    const char  *name,        // decrypted module name
    int          enabled,     // 1=on, 0=off, or runtime flag
    int          flag2        // module-specific flag (mostly 0)
);
```

The function returns the new module pointer that becomes the next call's `prev_module`. So registrations are chained.

---

## Complete scanner inventory (registration order)

| # | Name | enabled | Notes |
|---|---|---|---|
| 1 | `auto_defence3` | `1` | "Automatic defense" v3 — generic defensive bundle |
| 2 | `antiemulator` | `1` | Emulator detection (TencentX86, virtpipe-*, etc.) |
| 3 | `tablet` | `0` | **HARD-DISABLED** — tablet detection unused |
| 4 | `user_tag` | `(v3 & 1) == 0` | Conditional — when v3 flag clear |
| 5 | `info` | `1` | Generic info gatherer |
| 6 | `anti_virapp` | `1` (with flag2=1) | Anti virtual-app detection (VMOS, DualSpace) |
| 7 | `ob_normal` | `1` | "Observation normal" — generic observer |
| 8 | `anoscan` | `1` | Generic ano-scan |
| 9 | `FakeToken` | `v33 & 1` | Conditional — when token-feature enabled |
| 10 | `ksat` | `1` | Unknown abbreviation (likely "Kernel Security Audit Toolkit") |
| 11 | `file` | `(v3 & 1) == 0` | File scanner — conditional |
| 12 | `black_app` | `1` | Blacklisted-app detection (the 30+ cheat-app package list) |
| 13 | `wb_new_sync` | `(v3 & 1) == 0` | Whitelist/blacklist new-sync |
| 14 | `anti_clicker` | `0` | **HARD-DISABLED** — auto-tap detection unused |
| 15 | `anti_clicker2` | `1` | Anti-clicker v2 |
| 16 | `anti_cheat_open_id` | `(v3 & 1) == 0` | Conditional — anti-cheat OpenID check |
| 17 | `trusted_scanner` | `1` | Trusted-build verifier |
| 18 | `HistoryOpenID` | `(v3 & 1) == 0` | History tracking for OpenIDs |
| 19 | `frida_scan` | `1` | **The Frida detector** |
| 20 | `various_opcode` | `1` | **The opcode integrity scanner (the famous opcode_scan)** |
| 21 | `cs_vm` | `1` | "Code-section VM" check |
| 22 | `process` | `1` | Process enumeration scanner |
| 23 | `module2` | `1` | Module integrity v2 (libanogs's own .so checksum) |
| 24 | `anti_root` | `1` | Root detection |
| 25 | `elf_hook_scan` | `(v3 & 1) == 0` | **ELF hook detector** — only runs when v3 flag clear |
| 26 | `shell_checker` | `1` | Shell-injection / exploit checker |
| 27 | `cert3` | `1` | APK certificate v3 verifier |
| 28 | `live` | `1` | Live-broadcast detection (TikTok / streaming apps) |
| 29 | `cps_new` | `1` | "CPS" scanner v1 (TBD what CPS = ) |
| 30 | `cps_new3` | `(v3 & 1) == 0` | "CPS" v3 — conditional |
| 31 | `collect_apk` | `v4 & 1` | APK collector — conditional on v4 |
| 32 | `pe_rep` | `1` | "PE report" — possibly performance / probabilistic-event |
| 33 | `env_chk` | `1` | Environment check (LD_PRELOAD, env vars) |
| 34 | `cc2` | `1` | Unknown abbreviation |
| 35 | `gp5` | `1` | "Generation 5" protection (the latest) |
| 36 | `info_publisher` | `1` | Internal info-publishing channel |
| 37 | `wb_daemon` | `1` | Whitelist/blacklist daemon |

(Plus `cs_dl`, `scan1`, `mrpcs1`, `gp3_ext`, `gp4_2`, `tcj`, `cs_license`, `screenshot` from earlier in the same function — total approx 45 modules; 37 here are after the `(v3 & 1) == 0` checkpoint.)

---

## How modules link

Each `vXX = sub_NAMED(prev)` call returns a wrapper around the previous module struct. The chain looks like:

```
registry
   │
   ▼
[auto_defence3] → [antiemulator] → [tablet] → ... → [wb_daemon]
```

Each module is a heap-allocated struct (`ace_calloc_wrapper(N)` is called for many) with:
- A vtable pointer at offset 0 (e.g. `*v37 = &off_52AA98;`)
- Some module-specific state
- Linked list `next` pointer
- The module's name field
- The module's `enabled` flag

The vtable defines methods like:
- `init()`
- `scan()`
- `cleanup()`
- `report_violation(scan_result)`

---

## Conditional flags

The decompile shows three "config-flag" reads that gate certain scanners:

```c
v3 = sub_245494();      // → ace_check_v3_flag (renamed)
v4 = sub_245264(v2);    // → ace_check_v4_flag (renamed)
v33 = sub_245440(v2);   // → ace_check_token_enable (renamed)
v56 = sub_245328(v55);  // → ace_check_v_flag_3 (renamed)
```

These read from the same config object that `ace_string_util_core()` returns. The exact bits are TBD next iteration — but pattern recognition shows:

| Flag | Likely meaning | Affected scanners |
|---|---|---|
| `v3 & 1 == 0` | Production-build flag (fail-safe scanners run when not in dev mode) | `user_tag`, `file`, `wb_new_sync`, `anti_cheat_open_id`, `HistoryOpenID`, `elf_hook_scan`, `cps_new3` |
| `v33 & 1` | Token feature enabled | `FakeToken` |
| `v4 & 1` | Server-side toggle | `collect_apk` |
| `v56 & 1` | Region/locale flag | (unrelated registration) |

**Implication:** if we can flip `v3` to make `(v3 & 1) != 0` (i.e. set the production flag), we disable **`elf_hook_scan` and 6 other scanners** including the one that detects our hook trampolines. This is the MOST LIKELY CODM-style bypass route.

---

## Bypass implications

There are three clean attack surfaces here:

### 1. Hook `ace_register_scanner_module` (sub_22D428)

If we hook this and silently drop calls where `name == "frida_scan"` or `name == "various_opcode"` or `name == "elf_hook_scan"`, those modules are NEVER added to the registry, so they NEVER run. The rest of init proceeds normally — ACE won't notice the missing modules because they're queried by name later.

```c
// Hook body
__int64 my_register_scanner_module(reg_t *r, void *prev, const char *name, int enabled, int flag2) {
    static const char *blocked[] = {"frida_scan", "various_opcode", "elf_hook_scan",
                                    "anti_root", "anoscan", "module2", "shell_checker"};
    for (auto *b : blocked) {
        if (strcmp(name, b) == 0) {
            return (__int64)prev;  // skip — return prev as if nothing was added
        }
    }
    return real_ace_register_scanner_module(r, prev, name, enabled, flag2);
}
```

This is **vastly cleaner than NOPing kill instructions**. No detection ⇒ no kill chain ⇒ no need to defeat the kill chain.

### 2. Force `(v3 & 1) != 0`

Patch `sub_245494` (`ace_check_v3_flag`) to always return 1. Disables `elf_hook_scan` + 6 other scanners. Less surgical than option 1, but a single-instruction patch.

### 3. Hook `ace_register_all_scanner_modules` (sub_28B8A8)

Replace the entire function with `RET`. Registers NO scanners. Total kill of the scan engine. Riskier: ACE init may detect "no modules registered" and react.

---

## Next sub-iteration target

Find the **scan dispatch function** that walks this registry and calls each module's `scan()` method. That function's caller is the SCAN THREAD. From there we know:
- How often each scan runs (period from sleep call)
- How module results aggregate
- Where the "should we kill?" decision is made

Likely candidate: a function that takes the registry as input and iterates the linked list. Search for callers of `ace_register_all_scanner_modules` (`sub_28B8A8`) to see who builds the registry, then trace the registry pointer.

Per iteration we should pick 5 module-specific scanners and decompile their actual scan() methods. Start with `frida_scan`, `elf_hook_scan`, `various_opcode`, `anti_root`, `module2`.

The `(v3 & 1) == 0` condition gating elf_hook_scan is the **single biggest insight of iteration 3**.
