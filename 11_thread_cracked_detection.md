# `thread_cracked` — The 4-Second Detection Window

## What kills us

The function `ace_formatted_path_scanner` (libanort + 0x71DE0) is what we've been calling "the 4-second crash." The exact mechanism:

```c
__int64 ace_formatted_path_scanner(__int64 a1) {
    // 1. Record start time
    int64x2_t v25 = ACE_SyscallClockGettime(0);  // (sec, nsec)
    
    // 2. Spawn ACE_DetectionPoller as a detached pthread with 512KB stack
    sub_11C644(ACE_DetectionPoller, 0, 0x80000);
    
    // 3. Record end time
    int64x2_t v26 = ACE_SyscallClockGettime(0);
    
    // 4. Compute elapsed in MICROSECONDS
    int64x2_t v16 = vsubq_s64(v26, v25);
    long elapsed_us = v16[1] + 1000000 * v16[0];  // sec*1M + us  (actually nsec scaled? need to verify)
    
    // 5. **THE TIMING TRAP**
    if (elapsed_us > 5000000) {  // > 5 seconds
        // Take alternate code path:
        // - decrypt "thread_cracked:%ld"
        // - format "thread_cracked:<elapsed>"
        // - copy into a 128-byte buffer at a1+56
        // - set state field at a1+48 = 31
        v11 = ACE_DecryptString(5184);  // "thread_cracked:%ld"
        ACE_Memcpy_Checked(...);
        *(_DWORD *)(a1 + 48) = 31;
        // Continue to subsequent paths that check this state.
    }
    // Otherwise return success early.
}
```

**The 5-second window is hard-coded.** If `pthread_create + ACE_DetectionPoller startup` takes longer than 5 seconds, ACE marks the process as "thread_cracked" and the eventual scan path triggers a kill.

## Why our hooks trigger this

When we install Dobby hooks on libc functions (`kill`, `_exit`, `dlclose`, etc.), the hook installation itself takes time — and our hooks add overhead to every libc call. The `pthread_create` call inside `sub_11C644` goes through libc's `pthread_create` which may now be slower (because our process is heavier) AND `ACE_DetectionPoller` startup probably touches several libc functions before its first sleep.

If our hooks add even a few hundred milliseconds of slowdown — combined with the natural variance of phone CPU scheduling — we exceed 5 seconds.

This is **NOT** a sophisticated detection — it's a CRUDE timing trap. But effective.

## Bypass options

### Option 1 — Patch the threshold

Find the constant `5000000` (= 0x4C4B40) loaded into a register before the comparison. NOP the comparison or change the constant to `INT64_MAX`.

In the disasm: `CMP X29, X28; B.LE branch_to_normal_path`
Patch the CMP to always-greater (i.e., always take normal path).

### Option 2 — NOP the entire function

`ace_formatted_path_scanner` (0x71DE0, size 0x480 bytes) — replace with `MOV X0, #0; RET`. Effect: scanner thread never spawned, no detection, but ALSO no scan thread runs at all. Risky — other code may expect it.

### Option 3 — Hook `ACE_SyscallClockGettime` to lie

Always return the same time. Then `elapsed_us = 0` always. Threshold never tripped.

```c
typedef int (*clock_gettime_t)(void *unused, struct timespec *t);
clock_gettime_t real;
int my_clock_gettime(void *unused, struct timespec *t) {
    static struct timespec frozen = {0, 0};
    if (frozen.tv_sec == 0) real(unused, &frozen);
    *t = frozen;  // always return the SAME time
    return 0;
}
DobbyHook(libanort_base + 0x122448, my_clock_gettime, &real);
```

But this might break other timing-sensitive things in ACE.

### Option 4 — Speed up our hook setup

If we install hooks BEFORE libanort runs (e.g., during our own `JNI_OnLoad`, before libanogs/libanort are loaded), the timing measurement happens with our hooks already in place. The overhead is constant, and our hooks should add < 1 second.

## Recommended fix

**Option 3** (clock_gettime spoof) is the cleanest because:
1. It's a single function hook
2. Our hook returns instantly  
3. The frozen-time pattern means any future timing checks ACE adds also become no-op detections
4. Other ACE timing (heartbeats, periodic scans) doesn't depend on perceived elapsed time — they sleep for fixed durations

Implementation in `Main.cpp`:

```cpp
#include <time.h>

static int (*real_ace_clock_gettime)(void*, struct timespec*) = nullptr;
static struct timespec g_frozen_ts = {0, 0};

static int hooked_ace_clock_gettime(void *unused, struct timespec *t) {
    if (g_frozen_ts.tv_sec == 0 && real_ace_clock_gettime) {
        real_ace_clock_gettime(unused, &g_frozen_ts);
    }
    if (t) *t = g_frozen_ts;
    return 0;
}

void install_anort_clock_freeze() {
    uintptr_t base = getLibraryAddress(OBFUSCATE("libanort.so"));
    if (!base) return;
    void *target = (void*)(base + 0x122448);  // ACE_SyscallClockGettime
    DobbyHook(target, (void*)hooked_ace_clock_gettime, (void**)&real_ace_clock_gettime);
}
```

## Combined with Tier 1+2+3

Our integrated bypass needs ALL of:
1. Hook libanogs scanner registration → drop scanners
2. Disarm libanogs TDM telemetry → silence reports
3. Hook libanort gp7ioctl → drop "stop" command
4. **Freeze libanort clock_gettime → defeat thread_cracked timing trap**

With all four, all known kill paths are neutralized. Path 2 (string-decoder integrity trap) is naturally avoided by NOT tampering with the encrypted string tables.

## Verification once deployed

After deploy, watch logcat:
- `kill hook BLOCKED` — Tier 2 PLT kill caught (path 1)
- `gp7ioctl(stop) BLOCKED` — Tier 3 caught (path 3)
- No `thread_cracked` formatting → Option 3 worked

If game survives 5+ minutes consistently, all three kill paths are neutralized.
