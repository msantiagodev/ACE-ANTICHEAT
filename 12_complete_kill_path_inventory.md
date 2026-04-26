# Complete ACE Kill-Path Inventory

This is the **definitive list** of every code path in libanort.so + libanogs.so that can terminate the game process. Defeating ALL of these = the game survives indefinitely.

---

## libanogs.so kill paths

### Path 1 — Scanner-detection telemetry chain
```
scan thread → detection found → ace_create_tdm_report → ace_submit_corereport
              → ace_log_sdk_lifecycle_call (or peer)
              → ace_custom_syscall_handler → kill(getpid(), 9)
```

**Kill site:** `BL .kill` at `0x1CEEB0` (PLT call). Goes through libc.

**Defeat:** Tier 1 hook on `ace_register_scanner_module` (drop scanners) OR existing 5-leaf NOPs.

### Path 2 — Various inline kill spots

The 5 leaf-NOPs we've already deployed (`crash_handler_kill`, `assert_kill`, `raw_svc_exit`, etc.) cover this cluster.

---

## libanort.so kill paths

### Path 3 — String decoder integrity trap (×100)

Every one of the 100 string decoder functions in libanort has a kill-on-failure-twice trap:
```c
if (integrity_check_failed) {
    if (already_failed_once)
        linux_eabi_syscall(__NR_exit_group, &byte_7);  // exit code 7
    set_already_failed_flag = 1;
}
```

**Sites:** 100 instances at `0x109F3C`, `0x10A068`, ..., `0x111470` (every ~300 bytes).

**Defeat:** **DO NOT TAMPER WITH THE ENCRYPTED STRING TABLE.** Integrity passes naturally.

### Path 4 — `gp7ioctl("stop")` Java-command kill

When Java GP7Service sends `"stop"`:
```c
if (ACE_ValidateConfig(cfg, "enable_gp7_exit_group", 1))
    linux_eabi_syscall(__NR_exit_group, NULL);
```

**Site:** `0x25F28` (raw SVC #0).

**Defeat:** hook `JNI_ACE_CommandDispatch` (libanort + 0x25D94) to drop "stop", OR hook `ACE_ValidateConfig` to return false for `enable_gp7_exit_group`.

### Path 5 — `thread_cracked` 5-second timing trap

In `ace_formatted_path_scanner` (libanort + 0x71DE0):
```c
start = clock_gettime();
sub_11C644(ACE_DetectionPoller, 0, 0x80000);  // pthread_create
end = clock_gettime();
if ((end - start) > 5,000,000 us)  // > 5 seconds
    set_state(31);  // "thread_cracked:%ld"
```

The thread_cracked state propagates through `ACE_DetectionPoller` and eventually triggers a kill via the BST detection-flag path.

**Defeat:** hook `ACE_SyscallClockGettime` (libanort + 0x122448) to freeze time. Or NOP the comparison.

### Path 6 — `ACE_TimeBoundsValidator` anti-time-warp

Independently of path 5:
```c
if (current_time - stored_start_time >= 31 || stored_state != 52)
    exit_group(6);
```

**Sites:** kills at `0x3A018` (in `vfunc_3_39fb8`).

**Defeat:** hook `ACE_GetTime` to lie OR ensure stored_state field at offset +96/+81 stays correct.

### Path 7 — Function pointer init-failure traps (×3)

Triggered when ACE's lazy-resolved function pointers are NULL (resolver failed):
- `0x132720`: `if (!off_1A49C8) exit_group(3);`
- `0x39FE8`: `if (!off_1A4958) exit_group(2);`
- `0x3B028`: `if (!g_aco_array) exit_group(2);`

**Defeat:** ensure these globals are initialized normally — don't break the resolver chain. If we hook ACE_DynamicLibraryLoader to fail, these will fire. So leave that loader alone.

### Path 8 — APK / MZ / Unity-Mono buffer scanner

`vfunc_1_3af80` (libanort + 0x3AF80):
- Looks at input buffer for `MZ` PE header (`a1[0]==77 && a1[1]==90`)
- Scans for `.apk`, `Assembly-CSharp`, `Assembly-CSharp-firstpass`, `Assembly-CSharp.dll`
- If pattern found, sets detection flag 8
- After 2 failures of `ACE_FileStatIntegrityChecker`: `exit_group(0x12)`

**Sites:** kills at `0x3B028`, `0x3B24C`, `0x3B3AC`.

**Relevance for us:** UE4 game, no Mono assemblies, no PE/MZ files. Should never fire. Safe.

### Path 9 — Other init-fail / config-fail traps

Decompiled but not yet enumerated — likely 3-5 more sites in the 0x39000-0x3D000 range based on the byte pattern search (we found 8 outside-decoder sites).

**Defeat:** check each by ensuring init succeeds.

---

## Summary table

| # | Path | Kill mechanism | Defeat |
|---|---|---|---|
| 1 | libanogs scanner detect | `kill()` PLT | Hook scanner registration |
| 2 | libanogs leaf instructions | Existing 5 NOPs | Already deployed |
| 3 | libanort decoder integrity ×100 | `exit_group(7)` SVC | Don't tamper with strings |
| 4 | gp7ioctl("stop") | `exit_group(?)` SVC | Hook gp7ioctl, drop "stop" |
| 5 | thread_cracked >5s | flag → BST → kill | Freeze clock_gettime |
| 6 | TimeBoundsValidator | `exit_group(6)` SVC | Don't pause execution |
| 7 | NULL fn-ptr inits | `exit_group(2/3)` SVC | Don't break resolver |
| 8 | MZ/Mono scanner | `exit_group(0x12)` SVC | (irrelevant for UE4) |
| 9 | Misc init-fail | `exit_group(?)` SVC | Don't break init |

---

## Integrated bypass spec

Combining everything we know, the COMPLETE bypass for our UE4 use case requires:

1. **Tier 1:** hook `ace_register_scanner_module` (libanogs + 0x22D428) to drop named scanners
2. **Tier 2:** flip TDM telemetry kill switch (libanogs + 0x57E31C/D = 0/1)
3. **Tier 3:** hook `JNI_ACE_CommandDispatch` (libanort + 0x25D94) to drop "stop" commands
4. **Tier 4:** hook `ACE_SyscallClockGettime` (libanort + 0x122448) to freeze time → defeats `thread_cracked`
5. **Optional:** disable config update via `dword_171118 |= 0x100`
6. **Don't break:** the encrypted-string-table integrity, the function-pointer resolver chain, time-bounds validator's stored fields

Path 1+2 stop libanogs from killing.
Path 3+4 stop libanort from killing via gp7ioctl and timing traps.
Path 5+6+7+8+9 don't fire if we don't actively break init or tamper with strings.

This is the **MINIMAL VIABLE BYPASS** — 4 hooks + 2 byte writes + abstinence from tampering with strings.

---

## Hot offsets reference

```
libanogs.so:
  0x22D428  ace_register_scanner_module        Tier 1 hook
  0x57E31C  g_tdm_report_enabled                Tier 2 byte
  0x57E31D  g_tdm_report_checked                Tier 2 byte
  0x3ECFF8  ace_run_scan_rules                  Tier 6 hook (kill all rule eval)
  0x3F9CFC  ace_arm64_instruction_relocator     Tier 7 hook (no new hooks installed)

libanort.so:
  0x25D94   JNI_ACE_CommandDispatch             Tier 3 hook
  0x122448  ACE_SyscallClockGettime             Tier 4 hook (clock freeze)
  0x171118  dword_171118 |= 0x100               Tier 5: disable config update
  0x137804  ACE_VMExecutionDriver               Tier 8 hook (kill bytecode VM)
  0x3860C   ACE_InstallApiHooks                 (do not interfere)
  0x11149C  ACE_DecryptString                   (do not tamper, kill-on-failure-twice)
  0x71DE0   ace_formatted_path_scanner          (timing trap source)
  0x71484   ACE_DetectionPoller                 (the scan thread)
```

---

## ITERATION 22-23 KILL PATH UPDATES

Additional kill paths discovered:

### Path 10 — `mprotect_check_1/2` direct SIGKILL

**Sites:** libanort+0x120C88 (`mprotect_check_1`) and libanort+0x120D80 (`mprotect_check_2`)

```c
mmap(NULL, 0x1000, PROT_RW, MAP_PRIVATE|MAP_ANONYMOUS);
decrypted = byte_170631[i] ^ 0x1D;  // 56 bytes
if (ACE_EventSignal(decrypted, 0x80) != -993659912) {
    kill(getpid(), SIGKILL);  // Signal 9 — instant kill
}
mprotect(buf, 0x1000, PROT_RX);
```

If our hook breaks the integrity check, **immediate** `kill(getpid(), 9)`. No telemetry, no rule eval — just kill.

**Defeat:** ANORT_PATCHES patch #5 (replace with `MOV X0, #1; RET`). Already deployed.

### Path 11 — Library Integrity Scanner submission

**Site:** `ACE_LibraryIntegrityScanner` (libanort+0xCE64C)

Walks loaded libraries, hashes pages vs disk image. Whitelists `libanogs.so` but flags everything else if it doesn't match. On flag: submits a TDM report (Path 1 chain). Doesn't directly kill but eventually triggers it.

**Defeat:** ANORT_PATCHES patch #7. Or hook `vfn[40]` of COREREPORT channel.

### Path 12 — Memory Region Validator (90% threshold)

**Site:** `ACE_MemoryRegionValidator` (libanort+0xA7E7C)

Computes `(matched_pages * 100) / total_pages`. If <90%, increments severity counter. After threshold: TDM report.

Our trampolines push deviation past 10% if we hook many libUE4.so functions.

**Defeat:** ANORT_PATCHES patch #8. Or use GOT/PLT hooks instead of inline (no trampoline).

### Path 13 — Bytecode VM downloaded modules

**Site:** Anywhere inside `ACE_VMExecuteLoop` (libanort+0x137984)

Downloaded `ob_*.zip` modules can do anything — including emit ARM64 instructions that compute a target address and execute it. The B/BL handler at `ace_vm_op_branch_imm26` (libanort+0x142314) bridges from emulated to native via opcode 0x48D958.

If a downloaded module contains a kill check (e.g., "verify libUE4.so + integrity hashes"), it would emit a B instruction calling `kill()` natively.

**Defeat:** Tier 8 (`ACE_VMExecutionDriver`) deployed. Or block server fetch (Tier 5 + DNS block).

---

## Updated COMPLETE bypass spec (v2)

| Tier | Target | Address | Mechanism | Status |
|---|---|---|---|---|
| 1 | `ace_register_scanner_module` | libanogs+0x22D428 | DobbyHook (filter scanners) | DEPLOYED |
| 2 | `g_tdm_report_enabled/checked` | libanogs+0x57E31C-D | DobbyCodePatch (0/1) | DEPLOYED |
| 3 | `JNI_ACE_CommandDispatch` | libanort+0x25D94 | DobbyHook (filter "stop") | DEPLOYED |
| 4 | `ACE_SyscallClockGettime` | libanort+0x122448 | DobbyHook (cache 6s) | DEPLOYED |
| 5 | `g_anort_config_flags` | libanort+0x171118 | OR 0x100 | DEPLOYED |
| 6 | `ace_run_scan_rules` | libanogs+0x3ECFF8 | DobbyHook (return 1) | DEPLOYED |
| 7 | `ace_arm64_instruction_relocator` | libanogs+0x3F9CFC | DobbyHook (return true) | DEPLOYED |
| 8 | `ACE_VMExecutionDriver` | libanort+0x137804 | DobbyHook (return 0) | DEPLOYED |
| ANORT 1-11 | 11 detection sensors in libanort | various | `MOV X0, #0; RET` | DEPLOYED |

**Coverage:** Paths 1-13 all defeated by some combination of these tiers.

---

## What we still don't have full coverage on

1. **Server-side rule push during gameplay** — even with Tier 5, if the game has internet access during play, future server pushes might bypass our filter via a new code path we haven't mapped. Mitigation: DNS sinkhole `*.anticheatexpert.com`.

2. **JVM-level checks via JNI** — ACE could trigger Java code to do detection (read `/data/data/<pkg>/...` via Java APIs). Our native hooks don't see Java code. Mitigation: hook Java side via a separate framework (Xposed, etc.).

3. **Kernel-level signals** — if ACE somehow triggers signals via a kernel module or eBPF, we can't see those. (But this is exotic; ACE is userspace-only.)

4. **Cumulative time-based kills** — some paths integrate signal counts over minutes/hours. We need the bypass to survive 8+ hour play sessions to verify.
