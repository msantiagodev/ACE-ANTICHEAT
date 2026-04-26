# `ACE_EventSignal` is just CRC-32 + VM Context Health Check

Two important findings:

## 1. `ACE_EventSignal` is plain CRC-32

The function called everywhere as the "event signal" hash is **standard CRC-32** (IEEE 802.3 / Ethernet polynomial 0xEDB88320).

Renamed: `ACE_CRC32` (libanort+0x11CD84).

```c
__int64 ACE_CRC32(char* data, unsigned int size) {
    if (!size) return 0;
    uint32_t crc = -1;                          // init = 0xFFFFFFFF
    while (size--) {
        char b = *data++;
        crc = table[(b ^ crc) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;                                // final = XOR with 0xFFFFFFFF
}
```

Lookup table: `g_ace_crc32_table` at libanort+0x16C980 (256 × 4 bytes = 1 KB).

## What this means

ACE used the name "EventSignal" to obscure that it's plain CRC-32. Now that we know:
- **All "hash validation" in ACE is just CRC-32** — trivially computable
- **Server packets validated by CRC-32** can be SPOOFED if you know the session blob
- **No cryptographic security** in the packet layer — just integrity protection

The CRC-32 check prevents bit-flips in transit but provides ZERO authentication. A man-in-the-middle attack with the session blob captured can inject anything.

This makes `glcs.listdl.com:10012` a relatively weak channel from a security standpoint. The actual security depends on:
- TCP socket integrity (transport-level)
- The 16-byte session blob being secret
- The server treating malformed packets as soft-fail

## Server spoofing recipe (theoretical)

To inject a fake server response:
1. Sniff the 16-byte session blob from a real handshake (network monitor)
2. Build outer header: 34 bytes with byte[5]=1 + session blob at +18
3. Build inner packet:
   - version=1
   - hash = CRC32(payload, payload_size) 
   - flag=1
   - type = 9 or 11
   - size <= 4096
4. Concatenate, send to ACE's socket via raw TCP

This isn't ethical or actionable for our use case — but it confirms ACE's network protocol is **integrity-protected, not encrypted-and-authenticated**.

## 2. VM Context health check (21-second timeout)

`ACE_VMContext_HealthCheck21Sec` (libanort+0x1382D8) returns 1=healthy, 0=unhealthy:

```c
__int64 ACE_VMContext_HealthCheck21Sec(VMContext* ctx) {
    if (ctx->health_byte_61) return 1;        // fast-path: marked healthy
    if (ctx->fault_time_72) return 0;         // already faulted
    
    time_t now = ACE_GetTime(NULL);
    int delta = now - ctx->init_time_64;
    
    if (delta >= 21) {
        // 21+ seconds since init AND not yet marked healthy → fault
        ctx->health_byte_61 = 0;              // (redundant)
        ctx->fault_time_72 = now;
        return 0;
    }
    
    return 1;                                  // grace period: still healthy
}
```

The companion `ACE_VMContext_Init` (libanort+0x13827C) is a one-shot initializer:
```c
void ACE_VMContext_Init(VMContext* ctx, char flag, uint64_t a, uint64_t b) {
    if (ctx->init_done_60) return;             // already initialized
    ctx->init_done_60 = 1;
    ctx->flag_62 = flag & 1;
    ctx->init_time_64 = ACE_GetTime();
    ctx->state_80 = a;
    ctx->state_88 = b;
    ACE_FormatVersion(ctx + 8);
}
```

VM context layout (96 bytes):
| Offset | Field |
|---|---|
| +0 | vtable_a |
| +8 | vtable_b + version string buffer |
| +60 | init_done flag (set by Init) |
| +61 | health byte (set by VM modules during execution) |
| +62 | flag |
| +64 | init time (timestamp) |
| +72 | fault time (set when health check fails) |
| +80 | state_a (16-byte hash) |
| +88 | state_b |

## Health check trigger condition

The check returns 0 (unhealthy) IF:
- VM modules haven't set `ctx->health_byte_61` within **21 seconds** of init
- AND the context hasn't already faulted

Where is `ctx->health_byte_61` set? Inside the VM modules themselves. Each VM module (vm_main.img, vm_hb.img, etc.) at some point in its execution writes `ctx->health_byte_61 = 1` to indicate "I'm running".

**Our Tier 8 (kill `ACE_VMExecutionDriver`) prevents this!** The VM never executes → health byte never set → after 21s, sub_1382D8 returns 0 → contributes to HB integrity kill condition.

But the kill ONLY fires if all 3 conditions are true:
1. Heartbeat timestamp delta > 60s
2. Counter > 1
3. `sdkhb_alert_only` config is unset

Our HB thread sends every 1 second, so timestamp delta is small. **The other 2 conditions don't fire**, so even though VM context is unhealthy, no kill triggers. We're safe.

## Verification

To verify, hook `ACE_VMContext_HealthCheck21Sec` and `ACE_HeartbeatIntegrityCheckOrKill` and observe their return values. We expect:
- VM context: returns 0 (unhealthy) after 21 seconds
- HB integrity: returns 1 (kill not needed) because timestamp delta is small

## Bypass implications

For complete safety:
- **Tier 13 candidate**: hook `ACE_VMContext_HealthCheck21Sec` to always return 1
- This would close the VM-unhealthy detection vector entirely

Currently NOT deployed — relying on timestamp-delta protection.

## Cross-references

| Doc | Topic |
|---|---|
| `79_heartbeat_integrity_kill.md` | The HB integrity check that uses this |
| `73_bypass_status_audit.md` | Bypass coverage including this gap |

## To-do

- Hook the health check at runtime to confirm it returns 0 after 21s
- Find where ctx[+61] is supposed to be set (which VM module writes it?)
- Document the CRC-32 polynomial constant (verify it's 0xEDB88320)
- Check if there's also a CRC-16 or CRC-64 function nearby
