# Heartbeat Integrity Check — Yet Another Kill Path

`ACE_HeartbeatIntegrityCheckOrKill` (libanort+0x1087F0) is the **5th kill path** we've found in ACE. It runs on every heartbeat and can trigger process termination if integrity violations are detected.

## The check

Called every heartbeat with parameters:
- `a2` = previous heartbeat timestamp
- `a3` = current timestamp
- `a4` = some flag (low bit)
- `a5` = pointer to a counter

The function:

```c
__int64 ACE_HeartbeatIntegrityCheckOrKill(...) {
    bool counter_threshold_hit = false;
    
    // Step 1: Check timestamp delta
    if (current_ts - prev_ts > 60) {
        counter_threshold_hit = true;
        // The HB has been missing for >60s — anomalous
    }
    
    // Step 2: Increment failure counter
    if (counter_threshold_hit) {
        ACE_StoreXorEncodedTimestamp(...);   // Log to BST with XOR-encoded time
        *counter += 1;
    }
    
    // Step 3: If 2+ consecutive failures, check kill condition
    if (*counter > 1) {
        // Check if "alert only" mode is active
        config = ACE_GetConfigSingleton();
        bool alert_only = ACE_ValidateConfigOrKill(config, "sdkhb_alert_only", 1);
        
        if (!alert_only) {
            // Not in alert-only mode — proceed to kill check
            sigverify = ACE_GetSingleton_SigVerify();
            if (!ACE_CheckSDKVersionMinimum_7_7_2(sigverify)) {
                return 1;   // Version check failed → kill
            }
        }
        // Continue to VM context validation
        vm_ctx = ACE_GetSingleton_VMContext();
        sub_13827C(vm_ctx, ...);
        if (!sub_1382D8(vm_ctx)) {
            return 0;   // VM context invalid → kill
        }
    }
    
    return 1;
}
```

## Kill condition summary

ACE kills the process if **ALL** of these are true:
1. Multiple (≥2) consecutive heartbeats missed (timestamp delta > 60s twice)
2. Config flag `sdkhb_alert_only` (string 12067) is **NOT set** (default = unset)
3. SDK version is below 7.7.2 OR VM context is invalid

This is **fail-closed** like other ACE validators: the default behavior on integrity failure is termination.

## Kill paths total inventory (updated)

| # | Kill path | Triggered by | Killable via |
|---|---|---|---|
| 1 | SVC syscall (`ace_vm_op_svc_syscall`) | Emulator code calls `syscall(__NR_exit_group)` | Tier 1 patch |
| 2 | JNI exit_group (`ACE_ValidateConfigOrKill`) | Server sends "stop" command | Tier 11 (not deployed) |
| 3 | Probabilistic deep audit (`ACE_ScheduledTimerProbabilisticDetect`) | 0.1%/day random fire | Tier 12 (not deployed) |
| 4 | Server-side bans | Accumulated detection reports | Server-side, can't bypass client |
| 5 | **Heartbeat integrity (`ACE_HeartbeatIntegrityCheckOrKill`)** | Missed HBs + version/VM mismatch | Tier 13 (not deployed) |

## What `ACE_StoreXorEncodedTimestamp` does

Writes the integrity-failure timestamp (XOR'd with date-magic 0x20230726 = July 26 2023) to the BST under key `XTask_HB_Time`. This is an **anti-forensic** measure: even if an attacker dumps the BST contents, the timestamps are obfuscated.

XOR with a fixed magic is a weak obfuscation, but it does prevent simple timestamp pattern matching.

## ACE_CheckSDKVersionMinimum_7_7_2

Validates the **Tencent Protect SDK** version. Hardcoded minimum: `7.7.2`. If the SDK in the host APK is older, the version check fails and contributes to the kill condition.

This means ACE refuses to run inside an old TP SDK wrapper. Tencent's policy is that game devs must use TP SDK >= 7.7.2 to ship games. Older games would trigger the version-check kill (but those games would also have older ACE).

## Bypass implications

For our deployed bypass:
- **Tier 5** doesn't cover this path (different config flag than Tier 5's `bit 0x100`)
- **Tier 8** (VM driver kill) DOES help — the VM context check (`sub_13827C`/`sub_1382D8`) probably involves the VM, and our hook may make `sub_1382D8` return success
- We don't currently fail HBs — the periodic scan thread (Tier 4 dropped its results) doesn't generate timestamps that would trigger a 60-second delta

If the scenario arose where HBs DID fail:
- Tier 13 candidate: hook `ACE_HeartbeatIntegrityCheckOrKill` to always return 1 (success)

## To-do

- Decompile `sub_13827C` (VM context update) and `sub_1382D8` (VM context validate)
- Test if our Tier 8 (VMExecutionDriver kill) impacts VM context state — could make this validator fail
- Confirm `*a5` counter persistence across calls
- Look for the periodic timer that calls this — likely from the Tier-4 scan thread or one of the GP layers
