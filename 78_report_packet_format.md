# Report Packet Format — `ace_shell_di.dat`

ACE writes its persistent detection report to `<dir>/ace_shell_di.dat`. This file is the ON-DISK format that `ACE_ConfigUpdateFromServer` reads back at next boot to integrate prior detection state.

## Function chain

```
[Detection happens]
       ↓
ACE_BuildShellDiReport (libanort+0x12CD6C)
       │
       │ 1. Format target path: ACE_FormatShellDiPath = "<dir>/ace_shell_di.dat"
       │    (string ID 7153)
       │ 
       │ 2. Build packet via ACE_LinkedListNode_Init + ACE_CondWait sequence
       │
       │ 3. Write to disk via sub_115150 (atomic rename via .tmp)
       ↓
File on disk: <dir>/ace_shell_di.dat
```

## Wire format

```
[u32 magic = 0x20211111 (Nov 11, 2021 date-encoded)]
[u32 timestamp = time(NULL)]
[u32 size_placeholder = 0]   ← patched after payload built
[u32 hash_placeholder = 0]   ← patched after payload built
[<payload bytes from *v1>]   ← the actual detection state
```

After payload is built, the function:
1. Computes `payload_size` (offset_after_payload - offset_after_hash_placeholder)
2. Computes `ACE_EventSignal(payload_start, payload_size)` — a CRC-style hash
3. Patches `size_placeholder` slot with `payload_size`
4. Patches `hash_placeholder` slot with the computed hash
5. Writes the entire buffer to `<dir>/ace_shell_di.dat`

## The complete inventory of ACE magic numbers

| Magic | Decimal | Encoded date | Where used |
|---|---|---|---|
| `0x20211111` | 539037969 | **November 11, 2021** | `ace_shell_di.dat` first u32 |
| `0x20211215` | 539038229 | **December 15, 2021** | `ace_cache_db.dat` first u32 |
| `0x20218998` | 539099416 | (unknown year-month-day combo?) | Outer ZIP wrapper magic |
| `0x20218923` | 539100707 | (unknown) | Running module "active" marker |
| `0x12345678` | 305419896 | (placeholder) | Per-module `.img` magic |
| `0x464C457F` | 1179403647 | "\x7FELF" | Standard ELF magic (validated by ACE_ParseELFManually) |

The `0x2021_xxxx` pattern across multiple magics confirms ACE was finalized in 2021 with these specific dates baked into the wire format. Tencent uses date-encoding as a "version sentinel" — if Tencent ships a new wire format, they'd update the magic to the new release date.

## Why this matters

`ace_shell_di.dat` is the persistence layer. Its contents:
- Survive across game restarts
- Can be read by `ACE_ConfigUpdateFromServer` at next boot
- Allow ACE to remember detection state ("this user was suspicious yesterday")

For our bypass:
- **Tier 5** blocks `ACE_ConfigUpdateFromServer` from reading this file
- But `ACE_BuildShellDiReport` may still WRITE to it
- Stale detection state could accumulate across sessions

## Bypass: clean the file

To force a fresh state every session:
```bash
adb shell rm /data/data/<pkg>/files/ace_shell_di.dat
```

Or hook `ACE_BuildShellDiReport` to skip writing.

Currently we don't do this — but it's a hardening tier (Tier 12+) candidate.

## ACE_PacketCompose — the network protocol packet builder

`ACE_PacketCompose` (libanort+0x148028) builds outbound network packets:

```c
__int64 ACE_PacketCompose(packet, payload, buf, buf_size, total_size_out) {
    // Step 1: Serialize header (placeholder size)
    sub_14917C(packet, buf, buf_size, &hdr_size, 0);
    
    // Step 2: Serialize payload after header
    sub_149674(payload, buf + hdr_size, buf_size - hdr_size, &payload_size, 0);
    
    // Step 3: Patch header total_size = hdr_size + payload_size
    *(uint16_t*)(packet + 4) = payload_size + hdr_size;
    
    // Step 4: Re-serialize header with correct size
    sub_14917C(packet, buf, buf_size, &hdr_size, 0);
    
    if (total_size_out)
        *total_size_out = packet[+4];   // total bytes written
    return 0;
}
```

There are 4 versions: `ACE_PacketCompose`, `_2`, `_3`, `_4` — each with different header/payload serializers. Likely:
- `_1` = plain
- `_2` = encrypted variant
- `_3` = heartbeat variant
- `_4` = signed variant

## Network heartbeat send

`ACE_NetworkSendHeartbeat` (libanort+0x147C98) calls `ACE_PacketCompose_3` with a 1024-byte buffer. Heartbeats are type 7 packets (we documented this earlier). The TLS handshake delivers them.

## Cross-reference

| Doc | Topic |
|---|---|
| `25_network_protocol.md` | Full network protocol |
| `54_signed_cache_db_format.md` | Cache DB format |
| `42_format_strings_inventory.md` | All printf format strings |

## To-do

- Decompile `sub_14917C` (header serializer) and `sub_149674` (payload serializer)
- Determine the actual binary header layout (16 bytes)
- Trace the 4 PacketCompose variants to know which is for which channel
- Document `sub_11BAD0` (the buffer copy that builds the body)
