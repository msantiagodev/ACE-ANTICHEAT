# TLV Records and PacketCompose Variants

ACE has 4 distinct packet formats (each via a different `PacketCompose` variant) and uses TLV (Type-Length-Value) records inside payloads for extensibility.

## TLV record structure

`ACE_PacketTLVDeserialize` (libanort+0x14AD10) parses each TLV record:

```
Offset | Size | Field
-------+------+---------------------------------
+0     | 2    | tag (2 bytes — note: read with bytes swapped)
+2     | 4    | length (u32 BE)
+6     | N    | value (up to 0x1000 bytes, validated)
```

**Output struct:**
```c
struct TLV {
    uint8_t  tag[2];   // bytes swapped on read: a1[0]=byte+1, a1[1]=byte+0
    uint32_t length;   // big-endian
    char     value[N]; // max 4096 bytes
};
```

If length > 0x1000 → return -7 (error).
If buffer underflow → return -2.

The "swapped tag bytes" suggests ACE uses a 2-byte tag encoded in a non-obvious order, possibly for extra obfuscation. A naive byte-by-byte parser would get wrong tags.

## The 4 PacketCompose variants

ACE uses 4 different packet formats, each selected by which compose function is called:

| Variant | Address | Outer Header | Payload Serializer | Used For |
|---|---|---|---|---|
| `ACE_PacketCompose` | 0x148028 | sub_14917C | sub_149674 | General data via `ACE_PacketBuildAndSend` |
| `ACE_PacketCompose_2` | 0x1485E0 | sub_14A6F4 | sub_14AEDC | Chunked data via `ACE_PacketChunkAndSend` |
| `ACE_PacketCompose_3` | 0x148698 | sub_14A6F4 | sub_14A948 | Heartbeat via `ACE_NetworkSendHeartbeat` |
| `ACE_PacketCompose_4` | 0x148848 | sub_14A6F4 | sub_14AA50 | (Unknown — possibly response or signed packets) |

All four follow the same 3-step pattern:
1. Serialize header (placeholder size)
2. Serialize payload
3. Patch header with final size, re-serialize header

The differing payload serializers (sub_149674 vs 14AEDC vs 14A948 vs 14AA50) handle different inner formats:
- General: TLV-encoded
- Chunked: chunk index + total + data
- Heartbeat: minimal (just timestamp/seq)
- Variant 4: ?

## ACE_GetSingleton_VMContext (libanort+0x13813C)

The VM execution context — referenced by the heartbeat integrity check.

```c
__int64 ACE_GetSingleton_VMContext(void) {
    if (!g_ace_vm_context_singleton) {
        pthread_once(&dword_1A84B8, sub_1381C0);   // one-shot init
        if (!g_ace_vm_context_singleton) {
            // Lazy init
            void* obj = operator new(0x60);
            obj->vtable_a = &vtable_163e78;
            obj->vtable_b = &vtable_163ea8;       // multi-inheritance
            // (initialize other fields)
            g_ace_vm_context_singleton = obj;
        }
    }
    return g_ace_vm_context_singleton;
}
```

96-byte struct holds VM execution state. If corrupted/missing → heartbeat integrity check fails.

This singleton tracks:
- Which VM modules are loaded
- Current execution state per module
- Hash of the active modules
- Update sequence

## Bypass implications

### Server can extend protocol via TLV
ACE's TLV records mean Tencent can add new field types (new TLV tags) without breaking older clients. So even if we statically analyze the binary today, a future ACE update could introduce new tags we don't recognize.

To future-proof: hook the TLV deserializer to log every (tag, length, value) tuple ACE encounters. Build a corpus over time.

### VM context dependency
Our Tier 8 (kill `ACE_VMExecutionDriver`) prevents VM modules from running, but the **VM context singleton itself is still allocated**. It's just empty/invalid. The heartbeat integrity check could detect this:
- `sub_13827C` writes to VM context (likely updates state byte)
- `sub_1382D8` reads VM context (likely returns "is healthy")

If `sub_1382D8` returns false (no VM activity → not healthy), the kill condition fires — but only if all other conditions also true (timestamp delta + counter > 1 + alert_only flag unset).

For paranoid hardening: hook `sub_1382D8` to always return true.

## Renamed functions and globals

| Address | New name |
|---|---|
| 0x13813C | `ACE_GetSingleton_VMContext` |
| 0x1A84B0 | `g_ace_vm_context_singleton` |

## To-do

- Identify what TLV tag values ACE uses (capture at runtime via REPL bridge hook)
- Decompile `sub_13827C` (VM context update writer)
- Decompile `sub_1382D8` (VM context health checker)
- Determine which PacketCompose_4 channel is used for
- Cross-reference with `g_ace_boot_module_vtable` (used by VM context init)
