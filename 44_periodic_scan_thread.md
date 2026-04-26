# Periodic Detection Timer — The 30-Second Polling Thread

ACE has a dedicated background thread that polls hook descriptors every 30 seconds. This is the core "tick" that keeps detection running after init.

## The class

There's a singleton C++ class at libanogs+0x4B3F70..0x4B4910 that *is* the periodic scanner. Its layout:

| Offset | Type | Purpose |
|---|---|---|
| +0 | `void**` | vtable → `g_ace_periodic_scan_thread_vtable` (0x52E050) |
| +8 | `uint16_t` | tick counter — `++` once per loop iteration |
| +10 | `uint8_t` | (unused/reserved) |
| +11 | `uint8_t` | thread-started flag (1 = spawned) |
| +12 | `uint8_t` | descriptor block 0 running flag |
| +13 | `uint8_t` | descriptor block 1 running flag |
| +14 | `uint8_t` | descriptor block 2 running flag |
| +16 | sync (40 bytes) | mutex/cond for descriptor block 0 |
| +56 | sync (40 bytes) | mutex/cond for descriptor block 1 |
| +96 | sync (40 bytes) | mutex/cond for descriptor block 2 |
| +136 (0x88) | end | total class size |

## The vtable (g_ace_periodic_scan_thread_vtable @ libanogs+0x52E050)

| Index | Offset from base | Function | Purpose |
|---|---|---|---|
| -2 | -0x10 | 0 (offset_to_top, multi-inh) | |
| -1 | -0x08 | 0 (typeinfo, RTTI disabled) | |
| 0 | +0x00 | `ace_periodic_scan_thread_dtor` | destructor |
| 1 | +0x08 | `ace_periodic_scan_thread_dtor_delete` | deleting destructor |
| **2** | **+0x10** | **`ace_periodic_scan_thread_main`** | **the poll loop** |

Vtable[2] is the polymorphic "thread main" entry point that the C trampoline calls.

## The boot chain — how the timer starts

```
ace_init_core_v4_9_30_24277_oversea           (libanort+0xC3A6C, ELF SO ctor chain)
         |
         | (downstream, via runtime config + rule registration)
         v
ace_rule_run_caller_1                         (libanogs+0x3BD140, runs init rule)
         |
         | (when rule descriptor 1 fires for first time, calls)
         v
sub_3BB5BC                                    (libanogs+0x3BB5BC, rule-runner for descriptor 1)
         |
         | report_builder = ace_get_periodic_scan_singleton()
         |   (lazy double-checked-locking singleton; allocates 0x88 bytes, runs ctor)
         |
         v
ace_periodic_scan_start_thread_once            (libanogs+0x4B41A8)
         |
         | if singleton[+11] flag is 0 (thread not yet spawned):
         v
ace_thread_class_spawn                         (libanogs+0x4B1FD4)
         |
         | pthread_attr_init, then
         v
pthread_create(_, _, ace_thread_c_trampoline_vtable16, this)
         |
         v
ace_thread_c_trampoline_vtable16              (libanogs+0x4B207C)
         |
         | calls (*this->vtable)[2](this) — i.e., vtable+0x10
         v
ace_periodic_scan_thread_main                 (libanogs+0x4B4910)  ← THE THREAD
```

## What the thread does (libanogs+0x4B4910)

```c
void ace_periodic_scan_thread_main(this) {
    this[+11] = 1;                                    // mark "running"
    while (1) {
        // 1. Drain any pending stop request
        while ((registry->vtable[7](registry)) & 1)
            sleep(3);

        ++this->tick_counter;                         // +8

        // 2. Run descriptor block 0 (registry +456) if state allows
        if (registry->vtable[11](registry) != 2 &&
            try_lock(this+16) & 1)
        {
            if (!try_lock_global(registry+456)) {
                this[+12] = 1;
                ace_rule_run_caller_5(this, registry+456, 0);
                this[+12] = 0;
            }
            unlock(this+16);
        }

        // 3. Run descriptor block 1 (registry +504) — same pattern
        // 4. Run descriptor block 2 (registry +552) — same pattern

        // 5. Run any one-shot descriptors
        int n = registry_impl[1488];
        if (n > 0) {
            if (registry_is_busy()) {
                ace_periodic_scan_drain_descriptor_list(this, n);
            } else {
                lock(registry+1532);
                for (i=0; i<n; i++) {
                    desc = registry_impl[688 + 8*i];
                    ace_per_descriptor_run_rule(this, desc);
                }
                unlock(registry+1532);
            }
        }

        // 6. Sleep 30 seconds
        sleep(30);
    }
}
```

## Sleep mechanism — `ace_thread_sleep_seconds` (libanogs+0x493C60)

```c
__int64 ace_thread_sleep_seconds(void *thread_ctx, unsigned int seconds) {
    if (thread_ctx[80] /* wait_fnptr */)
        return ((wait_fn)(thread_ctx[80]))(seconds);   // hookable wait
    else
        return sleep(seconds);                         // direct
}
```

Two paths:
1. **Hooked wait**: thread context has a function pointer at offset +80 (likely set when ACE wants thread-coordinated wait/notify, e.g., for graceful shutdown).
2. **Plain sleep**: falls through to libc `sleep(N)`.

The 30-second poll cycle is hardcoded as the second arg.

## Bypass implications

### Tier-N options (none currently used; the bypass already kills detections higher up)

1. **Patch the sleep duration** to `INT_MAX` — makes the thread never re-fire. Ineffective: ACE notices "too few reports" via separate health check.
2. **Patch the loop body to `mov w0, #0; ret`** — thread immediately exits. ACE notices the thread death (TIDs are tracked in the registry).
3. **Patch ace_per_descriptor_run_rule to no-op** — descriptors run, returns 0 each time. This is the cleanest but already covered by Tier 4 (we kill `ace_run_scan_rules`).
4. **Patch `ace_periodic_scan_start_thread_once` to never spawn** — thread is never created, but rule descriptor 1 won't be marked as running, which trips a watchdog.

The current bypass tier 4 (`ace_run_scan_rules` kill) drops scan rule execution at the rule-runner level, which means every descriptor block returns 0 detections. Tier 4 sees the thread fire but always reports clean.

### Why we don't kill the thread itself

ACE has a "thread present" check that fires if the periodic scanner thread (TID stored in the singleton's pthread_t) is missing or stopped. So **let the thread run** and just neutralize what it does. That's what our existing 8-tier bypass already accomplishes.

## Other important call sites

- **`sub_3BB5BC` (libanogs+0x3BB5BC)** — rule-runner for descriptor 1. This is also where `ace_get_report_builder()` is called (we renamed to `ace_get_periodic_scan_singleton`), incrementing field +9, calling `ace_rule_run_caller_1` for sub-rules at offset +168, and doing protobuf-style serialization at +608.
- **`sub_3BB8C8`, `sub_3BBB1C`** — rule-runners for descriptors 2 and 3 (similar shape).
- **`sub_4C53E8` (libanogs+0x4C53E8)** — also calls `ace_periodic_scan_start_thread_once`. This is a separate spawn site, likely for a forced-restart path.

## To-do

- Trace the wait_fnptr at offset +80 — set by what?
- Confirm the registry offset +456/+504/+552 layout matches the descriptor blocks we documented in `24_hook_descriptor_registry.md`.
- Find the watchdog that monitors the thread is alive (probably in libanort, fires kill path if the report is older than N seconds).
