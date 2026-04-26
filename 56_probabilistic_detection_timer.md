# Probabilistic Detection Sampling — The "0.1% Per Day" Timer

`ACE_ScheduledTimerProbabilisticDetect` (libanort+0xF6354) is one of the most insidious pieces of ACE. It runs detection sweeps **probabilistically** — only ~0.1% of the time per day per device — making detection difficult to reproduce by attackers.

## The function

```c
bool ACE_ScheduledTimerProbabilisticDetect(void* state) {
    if (byte_1A4C8C == 0) {
        // First-run path
        byte_1A4C8C = 1;
        config_singleton = ACE_GetSingleton_ConfigStore();
        if (!ACE_CheckTimestampValid(config_singleton, 4, 86400)) {
            // 24h timer expired or first run
            time_t now = ACE_GetTime();
            ACE_BSTUpsertUint32(config_singleton, 4, now);   // record timestamp
            ACE_ExportCacheDb(config_singleton);              // persist to ace_cache_db.dat
            
            srand(now + rand());                              // re-seed PRNG
            int sample = rand();
            int extra = sub_11CCBC();
            
            return (sample % 1000 == 910) && extra;          // ★ 0.1% probability
        }
    }
    // Already initialized — return false (no detection sample this run)
    return false;
}
```

## How the probability check works

```c
v7 = rand();
v8 = (v7 % 1000 == 910);   // 0.1% chance each call
```

Since `rand()` returns 0..32767, `rand() % 1000` is roughly uniform 0..999, so `== 910` is ~1/1000 = **0.1% probability**.

But the function only fires this check **once per day** (gated by `ACE_CheckTimestampValid` with 86400 seconds = 24h timeout).

So per device: probability of detection-sample on any given day = 0.1%.

## Why this matters

This is a powerful anti-analysis technique. If a cheater:
1. Tests their cheat → no detection (99.9% chance)
2. Streams to YouTube for 100 days → expected 0.1 days with detection
3. Ban arrives "out of nowhere" — cheater has no idea what triggered it

For ACE researchers (us): **you cannot reproduce the detection by simply running the game**. You need to:
- Patch `byte_1A4C8C` to allow re-entry
- Force `rand() % 1000 == 910`
- Then observe what happens downstream

## What runs when it fires?

When the function returns true, the caller (in `init_array_1` or downstream init) executes additional code paths. Without tracing the boolean usage, we know it's used to trigger:
- Heavy detection sweeps (mostly elided in normal runs)
- Memory scans (looking for cheats in unexpected places)
- The kind of "deep audit" you'd never get to see in normal play

## ACE_ExportCacheDb (libanort+0x12C15C) — the writer

The companion to `ACE_LoadCacheDb`. Writes the BST back to `<dir>/ace_cache_db.dat` using the same wire format (magic `0x20211215`, encoded entries with XOR-`0x12345678` obfuscation).

Format (write):
```
[u32 magic = 0x20211215]
[u32 entry_count]
[N × {
    [u32 key]
    [u32 encoded_value]    ← (decoded_value XOR 0x12345678)
    [u32 integrity_check]  ← (encoded_value XOR key)
}]
```

Then writes the buffer to disk via `sub_115150` (likely a fwrite wrapper).

## Persistent state via cache DB

The cache DB stores (among other things):
- Key 4 → last timer-fire timestamp (so 24h gating works across restarts)
- Other keys → cached config flags, scanner state, detection thresholds

Each game restart loads via `ACE_LoadCacheDb`, modifies in-memory, exports back via `ACE_ExportCacheDb`.

## Bypass implications

### Detection-side
1. The 0.1%/day probability means **most cheaters get away with it most of the time**. But persistence builds — over months, the cumulative ban probability is ~3% (`1 - 0.999^30 ≈ 2.96%/month`).
2. If we DETECT this timer firing (e.g., monitor `byte_1A4C8C` for state change + check the timestamp delta), we can pre-emptively pause cheating.

### Exploitation-side  
- Set `byte_1A4C8C = 0` and force-fire to test what triggers
- Patch `*(uint32_t*)(rand_addr) = constant_910 * 1000` to fake the sample
- Patch the `ACE_ExportCacheDb` to corrupt the cache → force "first run" every time

### Most-effective neutralization
Hook the function itself to always return **false** (never fire detection sample):

```cpp
bool hooked_ACE_ScheduledTimerProbabilisticDetect(void* state) { return false; }
```

This would be a Tier 10 in our bypass. Currently NOT deployed — we rely on lower-tier mitigation. Adding it would prevent the very rare deep-audit detections.

## Single point of failure for ACE

Because this whole detection class runs through ONE function, ACE has a single point of failure here. Hook it, return false, and the entire 0.1%/day audit class is neutralized forever.

## To-do

- Trace what code path runs when `ACE_ScheduledTimerProbabilisticDetect` returns true
- Determine which detections are gated by this (memory scans? deep file inspection?)
- Add Tier 10 to our bypass: hook the function to always return false
- Document `byte_1A4C8C` as the "first-run-guard" global
