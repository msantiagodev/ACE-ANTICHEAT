# Kill-Path Watchdog Hunt — Negative Result

This doc records what we searched for and **didn't find**: a client-side thread-alive watchdog or time-based heartbeat staleness check.

## What we hunted

- `pthread_kill(thread, 0)` calls — none in libanort
- `clock_gettime` calls — symbol not present (uses `time(NULL)` instead)
- String matches for "heartbeat", "watchdog", "alive", "stale", "too_old", "last_report", "tick_age" — zero hits in encrypted/decrypted string tables

## What we found instead

### `time()` is used in 13 places in libanort
| Caller | Use |
|---|---|
| `ace_symlink_path_resolver` (libanort+0x83BFC) | timestamp-based filesystem entry mtime check |
| `ACE_FileSystemScanner` (libanort+0x85094) | scan-event timestamp |
| `vfunc_2_8eb08` (libanort+0x8EB08) | timestamp embedded in scan vfunc |
| `ACE_PathObfuscator` (libanort+0xB0C94) | random salt seed |
| `vfunc_3_c01b8` (2 sites, libanort+0xC01B8) | scan-event timestamps |
| `ACE_GetDetectionContext_Singleton` (libanort+0xECBAC) | **+84 = ctx creation time** |
| `ACE_AllocTimestampedObject` (libanort+0xED354) | pthread_once one-shot init of context |
| `vfunc_1_11cb34` (libanort+0x11CB34) | event signal timestamp |
| `ACE_GetTime` (libanort+0x1224D8) | wrapper, used by `ACE_GetTimestamp` |
| `sub_1304A8` (libanort+0x1304A8) | unknown helper |
| `ace_apply_elf_fixups` (libanort+0x131E6C) | randomization seed for ELF fixups |
| `ACE_NetworkSendHeartbeat` (libanort+0x147C98) | embeds `time(NULL)` in TLS handshake heartbeat packet |

None of these reads `g_ace_detection_context_singleton[+84]` and compares against a threshold. There's **no `if (time() - ctx[+84] > N) trigger_kill_path()` pattern**.

### Detection context layout
`g_ace_detection_context_singleton` (libanort+0x1A4C80) holds a pointer to a 0x78-byte struct:

| Offset | Type | Purpose |
|---|---|---|
| +0 | vtable* | `g_ace_detection_context_vtable` (0x163438) |
| +56 | list_head | linked list (allocated entries) |
| +80 | byte | `initialized = 1` |
| +81 | byte | `0` (reserved) |
| +84 | dword | **creation `time(NULL)`** |
| +88..+0x78 | extra | second linked list head + flags |

Created via `pthread_once(&dword_1A4C88, ACE_AllocTimestampedObject)` so it's truly one-shot.

## Conclusion: client-side watchdog doesn't exist (in the form we expected)

ACE's anti-tamper for the periodic-scan thread is delegated to the **server** via TLS handshake heartbeats. The client side simply:

1. Spins up the periodic scan thread on rule descriptor 1 firing.
2. Records `time(NULL)` in the detection context at creation.
3. Sends `ACE_NetworkSendHeartbeat` packets type-7 with `time(NULL)` over TLS handshake.

If the heartbeat stops arriving server-side, the server denies further connections. There is no client-side `kill_self_if_thread_dead` logic that we can find.

This makes our bypass simpler: **as long as we don't kill the thread itself, we're safe**. Our existing Tier 4 (`ace_run_scan_rules` no-op) lets the thread fire normally but produces no detections.

## What this means for our bypass

- **Tier 4 (drop scan results)** — keeps thread alive but neutralizes detection. ✓ Safe.
- **Hypothetical "kill the thread"** — bad idea; even though no client-side watchdog fires, the server eventually times out the heartbeat and we're banned at next login.
- **Hypothetical "block heartbeats"** — also bad; explicit server timeout.

The bypass strategy of "let everything run, just falsify the results" remains correct.

## Outstanding questions

1. The `ACE_TLSHandshake` (libanort+0x147B9C) sends only **one** heartbeat at handshake-time. Where's the **periodic** heartbeat? Possibly in libanogs via `ace_periodic_scan_thread_main` → some downstream packet builder we haven't fully traced.
2. Does the server-side response carry a "kill in N seconds" command? We've seen `ace_run_scan_rules` evaluate response packets but haven't decoded the response header format.

## To-do

- Trace `ACE_TLSHandshake` callers — is it called periodically or only at session start?
- Decompile `sub_15E084` — the actual network send. May reveal heartbeat cadence config.
- Look at libanogs for periodic packet build.
- Decode response packet handler — server kill commands.
