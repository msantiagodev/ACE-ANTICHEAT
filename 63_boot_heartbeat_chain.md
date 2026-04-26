# Boot Heartbeat Validation Chain

ACE's boot module isn't just "load + run" — it implements a **synchronous request/response** protocol where the host code (libanort) asks the loaded VM module a question, and waits 5 seconds for the answer.

## The function

`vfunc_3_138344` (libanort+0x138344) — vtable[3] of the boot module singleton.

```c
__int64 vfunc_3_boot_driver(__int64 self) {
    // Step 1: Build "ask key" packet
    char packet1[64];
    char* fmt = decrypt(11373);   // "ObjVM_HBv2_%d"
    sprintf(packet1, fmt, *(byte*)(self + 62));   // self+62 = HB sequence number
    
    // Step 2: Insert into BST under key "G_HB_ASK_K" (12385)
    ACE_BSTEncodedUpsert(hash_state, decrypt(12385), packet1);
    
    // Step 3: Build "ask data" packet
    char packet2[128];
    char* fmt2 = decrypt(11389);  // "ObjVM_HBv2_%d_%lx_%lx_%lx"
    time_t cached_ts = ACE_GetCachedTimestamp(...);
    sprintf(packet2, fmt2, *(byte*)(self + 62), 
            *(uint64_t*)(self + 80),    // some hash 1
            *(uint64_t*)(self + 88),    // some hash 2  
            cached_ts);                 // current time
    
    // Step 4: Insert into BST under key "G_HB_ASK_D" (12398)
    ACE_BSTEncodedUpsert(hash_state, decrypt(12398), packet2);
    
    // Step 5: Run the boot module (loads vm_hb.img + a64.dat)
    ace_boot_extract_and_run_modules(self, 2);  // mode=2 = include HB
    
    // Step 6: Poll 50 times (every 100ms = 5s total) for response
    char response[32] = {0};
    for (int i = 50; i > 0; --i) {
        char* expected_key = decrypt(12411);   // "G_HB_K_RESP"
        if (ACE_BSTStringLookup(hash_state, expected_key, response, 32))
            break;
        usleep(100000);   // 100 ms
    }
    
    // Step 7: Validate response
    if (response[0] != 0) {
        if (response[0] == '1') {
            // Compare rest of response to global string at &a1[1]
            char* expected_suffix = &g_libanort_str[1];
            if (memcmp(&response[1], expected_suffix, ...) == 0) {
                *(byte*)(self + 61) = 1;   // SUCCESS — set boot flag
            }
        }
        *(time_t*)(self + 72) = ACE_GetTime();   // record boot time
    }
}
```

## The protocol on the wire

ACE writes:
- BST key `G_HB_ASK_K` = string like `"ObjVM_HBv2_42"` (sequence #42)
- BST key `G_HB_ASK_D` = string like `"ObjVM_HBv2_42_<hash1>_<hash2>_<timestamp>"`

Then it runs `vm_hb.img` (the heartbeat module). The module:
1. Reads `G_HB_ASK_K` and `G_HB_ASK_D` from the BST
2. Computes some answer based on the hashes and timestamp
3. Writes the answer to BST key `G_HB_K_RESP`

Host then polls until response arrives, and validates response[0] is '1' followed by an expected suffix.

## What the answer represents

The answer is the **proof that the VM module ran successfully**. The hashes in the question prevent replay attacks (if attacker captured a previous answer, the new question's hash makes it invalid).

This is **mutual authentication between libanort and the VM module**:
- libanort → VM: "prove you can answer my hash question"
- VM → libanort: "yes, my answer is `1<suffix>`"

If the VM module is missing, broken, or hooked → no answer arrives → boot fails (flag at +61 stays 0).

## Why this matters for our bypass

We have Tier 8 hooked: `ACE_VMExecutionDriver` returns 0 immediately. This means:
- The VM module never executes
- The HB response never arrives
- After 5 seconds, the boot driver gives up
- `*(self + 61) = 0` (boot failed)

**This is observable!** ACE knows its boot didn't complete.

But — ACE may not actually fail-closed on this. The boot could continue with degraded detection capability. Our bypass works because the rest of ACE (post-boot scanners, heartbeats) is also neutralized via Tier 4 (drop scan rules).

If ACE ever adds a check like:
```c
if (*(byte*)(self + 61) == 0) {
    log_to_server("VM_HB_FAILED");
    sleep(60); retry;
    if (still_failed) exit_group(0);
}
```

Then our bypass would be detectable. We don't currently see this in the decompilation — but it could be added in future versions.

## Hardening our bypass

To survive a future "VM HB required" check, we'd need to:
1. NOT kill `ACE_VMExecutionDriver` — let the VM run
2. Hook the result-evaluation OR poison the input
3. Or write our own answer to `G_HB_K_RESP` BEFORE the host polls

Option 3 is interesting: if we can hash the question and produce a valid answer ourselves, we satisfy ACE without running the actual detection module. That's the elegant solution. Need to reverse the hash function.

## Decoded strings

| ID | Decrypted |
|---|---|
| 11373 | `ObjVM_HBv2_%d` |
| 11389 | `ObjVM_HBv2_%d_%lx_%lx_%lx` |
| 12385 | `G_HB_ASK_K` (Global Heartbeat Ask Key) |
| 12398 | `G_HB_ASK_D` (Global Heartbeat Ask Data) |
| 12411 | `G_HB_K_RESP` (Global Heartbeat K Response) |

## To-do

- Reverse the hash function inside `vm_hb.img` to compute legitimate HB answers
- Check if other vfuncs in this vtable (138224, 138230, 1384C4) participate in HB
- Find the watchdog (if any) that fails on missing HB response
- Trace the response suffix expected — it's compared to `&g_libanort_str[1]`, what's that string?
