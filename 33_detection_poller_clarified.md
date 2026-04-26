# ACE_DetectionPoller — Misleadingly Named Timing Trap

## Misnomer alert

`ACE_DetectionPoller` (libanort+0x71484) is **NOT** a periodic detection poller despite its name. It's a **one-shot thread** spawned solely to enable the **thread_cracked timing trap**.

## The real architecture

```
                       Java side calls AnoSDKMethodInit
                                 │
                                 ▼
                  JNI_ACE_Initialize → ace_init_core
                                 │
                                 ▼
                  ace_thread_cracked_timing_check
                  ┌──────────────────────────────┐
                  │  start = clock_gettime()     │
                  │  pthread_create(POLLER, det) │  ← ACE_DetectionPoller spawned here
                  │  end = clock_gettime()       │
                  │  if (end-start > 5s)         │
                  │      ctx.+48 = 31  ← FLAG    │  ← KILL PATH 5 origin
                  └──────────────────────────────┘
                                 │
                                 ▼
              ACE_DetectionPoller runs ONCE, mostly idle
                                 │
                                 ▼
              (Periodic detection happens elsewhere via
               libanogs's ace_rule_run_caller_5 — 50ms throttle)
```

## What ACE_DetectionPoller actually does

The function is heavily CFG-flattened (956 bytes, ~80 state values). What we can verify:

```c
ACE_DetectionPoller() {
    state = 484457182;  // initial state (encoded as int)
    
    while (state >= 341112965) {  // some loop condition
        // Inside: calls ACE_SyscallClockGettime
        // Counter v44 increments
        // When v44 == 10, special-case branch
        // Various opaque arithmetic checks (state machine dispatch)
    }
    
    return 0;
}
```

The function:
- Does **NOT** call any scanner / rule interpreter
- Does **NOT** do detection work
- Does **NOT** loop forever

It just does some clock_gettime calls and counter increments. The actual purpose? **It exists so pthread_create has something to call**. The thread_cracked trap doesn't care what runs in the spawned thread — it cares about how long pthread_create takes to spawn it.

This is a clever design: ACE measures pthread_create timing as a debugger detector. If a debugger has paused our process between the two clock_gettime calls, the elapsed time will be huge (>5 seconds), and the thread_cracked flag fires.

## Why we mistakenly thought it was the poller

Earlier docs (PROGRESS.md iterations 1-8) labeled it as the periodic poller because:
1. The name "DetectionPoller" suggested it
2. The function size (956 bytes) suggested complexity
3. We didn't verify what it actually does inside

The CFG flattening hid the truth: the function is a **decoy**. It does almost nothing useful. Its mere existence makes the trap work.

## Where periodic detection ACTUALLY happens

In **libanogs.so**, not libanort.so:

| Function | Address | Role |
|---|---|---|
| `ace_rule_run_caller_5` | libanogs+0x4B4288 | THE periodic poller (50ms throttle, tier checks, rule dispatch) |
| `ace_dispatch_rule_run` | libanogs+0x3ECB40 | Entry to interpreter |
| `ace_run_scan_rules` | libanogs+0x3ECFF8 | The interpreter itself |

These are called by **9 different scan triggers** (ace_rule_run_caller_1..9), not by ACE_DetectionPoller. ACE_DetectionPoller never enters libanogs.

## Bypass implications

**This is HUGE for our bypass:**
1. **Tier 4 (clock_gettime cache)** is the perfect counter to thread_cracked. Setting elapsed to ~0 makes the trap never fire.
2. **Hooking ACE_DetectionPoller** to return immediately is SAFE — the function does nothing important. We could even hook it to return immediately without breaking anything.
3. **Tier 6 (ace_run_scan_rules) hooks the actual periodic detection**, not ACE_DetectionPoller.

## Verification

To verify ACE_DetectionPoller really does nothing:
```bash
# Hook it to return 0 immediately
DobbyHook(libanort_base + 0x71484, &noop_returns_0, &orig_poller);
# Game should still work normally because the function is decoy
```

## How thread_cracked propagates

If the timing trap fires (`ctx.+48 = 31`), the next time the periodic poller (libanogs+0x4B4288) runs, it sees state 31 and:
1. Builds a TDM report with detection code 31
2. Submits via the ace_submit_corereport chain
3. Server eventually decides to kill the player (or rate-limits etc.)

So the kill is delayed and indirect. But it's a real kill mechanism — KILL PATH 5 in our inventory.

**Tier 4 prevents the trap from firing in the first place.**

## To-do (next iteration)

- Decompile `ace_pthread_create_detached` to understand what stack size 0x80000 does
- Find where ctx.+48 == 31 is read (the consumers of the thread_cracked flag)
- Check if there are similar "decoy thread" timing traps elsewhere
