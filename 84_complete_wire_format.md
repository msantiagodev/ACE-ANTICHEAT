# Complete Wire Format — Outer + Inner Headers

After reverse-engineering both `ACE_OuterHeaderParse` and `ACE_InnerPacketParse`, we now have the exact byte-level wire format ACE uses for all network communication.

## OUTER PACKET (34 bytes header + variable payload)

```
Offset | Size | Field           | Description
-------+------+-----------------+----------------------------------
+0     | 1    | byte0           | message type indicator
+1     | 4    | field1 (u32 BE) | (purpose TBD - timestamp?)
+5     | 1    | flag_byte       | MUST == 1 for continuation/dispatch
+6     | 4    | field2 (u32 BE) | (purpose TBD)
+10    | 4    | field3 (u32 BE) | (purpose TBD)
+14    | 4    | field4 (u32 BE) | (purpose TBD)
+18    | 16   | session_blob    | session ID / hash blob
+34    | N    | inner_packet    | the actual payload (parsed below)
```

The `flag_byte` at +5 is checked by `ACE_PacketReceiveAndDispatch` — if non-1, the packet is dropped immediately.

The 16-byte session blob at +18 likely matches the `xmmword`-sized session state we saw in `ACE_PacketHeaderInit` (first arg).

## INNER PACKET (variable, ≤4KB)

After the 34-byte outer header, the inner packet starts. Layout:

```
Offset | Size | Field          | Description
-------+------+----------------+----------------------------------
+0     | 4    | u32 field0     | (purpose TBD)
+4     | 1    | byte4          |
+5     | 1    | byte5          |
+6     | 4    | u32 hash       | hash check field
+10    | 1    | form_selector  | (==1 → has u16 size at +11; else immediate TLV)
{if form_selector == 1:
+11    | 2    | u16 size_BE    | payload size hint
+13    | 2    | (padding?)
+15    | ?    | TLV payload    | Type-Length-Value encoded
}
{else:
+15    | ?    | TLV payload    | TLV starts immediately
}
```

## DISPATCH-TIME VALIDATION

`ACE_PacketDeserializeAndDispatch` reads specific offsets from the *parsed* inner packet (after the parser has filled the struct):

```
struct ParsedInnerPacket {
    char  v14[15];      // bytes 0-14: header fields
    u16   version;      // +15: MUST == 1
    u32   hash;         // +17: MUST match ACE_EventSignal(payload, payload_size)
    char  ...           // +21: padding
    u8    flag;         // +21? or +22: MUST == 1
    u16   type;         // +22: MUST be 9 or 11
    u8    pad[3];
    u32   payload_size; // +28: MUST be <= 0x1000 (4KB)
    char  payload[4096];// +32: actual payload bytes
};
```

(Offsets approximate based on decompilation context; exact alignment may differ.)

## TLV (Type-Length-Value) inner format

`ACE_PacketTLVDeserialize` (libanort+0x14AD10) reads TLV records from the payload section. Each TLV looks like:

```
[1-byte type] [variable-length size encoding] [<size> bytes value]
```

This allows extensible payloads where ACE can add new field types without breaking older clients.

## Helper functions

| Function | Purpose |
|---|---|
| `ACE_ReadUint32_BE` (libanort+0x14950C) | Read big-endian u32 from buffer + advance position |
| `ACE_ReadUint16BE_Plus2` (libanort+0x14AE30) | Read big-endian u16 + advance by 2 |
| `ACE_ReadBytes` (libanort+0x1495DC) | Copy N bytes from buffer + advance |
| `ACE_PacketTLVDeserialize` (libanort+0x14AD10) | Decode TLV records |

All readers use a `{ptr, pos, end}` cursor struct (3 qwords). They:
1. Check if `end - pos >= size_needed`
2. Read from `ptr + pos`
3. Advance `pos`
4. Return error if buffer exhausted

## Big-endian byte order

All multi-byte fields are **big-endian** (network byte order). This matches typical TCP protocols.

## Maximum sizes

| Limit | Value |
|---|---|
| Outer header | 34 bytes (fixed) |
| Inner packet payload | 4096 bytes (validated by ACE_PacketDeserializeAndDispatch) |
| Single chunk | 4096 bytes (validated by ACE_PacketChunkAndSend) |
| Total chunked message | 64 KB (16 chunks × 4 KB) |

## Receive validation gauntlet

For a server packet to be accepted:
1. **Outer header parses** (34 bytes consumed cleanly)
2. **Outer flag byte == 1** (checked at byte +5)
3. **Inner header parses** (variable bytes consumed cleanly)
4. **Inner version == 1**
5. **Inner hash matches `ACE_EventSignal(payload, size)`**
6. **Inner flag == 1**
7. **Inner size <= 4 KB**
8. **Inner type == 9 or 11**

Any failure → drop. Server can't lie about contents (hash check) or send malformed packets (parser bounds-checks every field).

## Bypass implications

To **inject a fake server response**:
- Need to know the per-session 16-byte session blob (set during handshake)
- Need to compute correct hash via ACE_EventSignal
- Then write to `glcs.listdl.com:10012` socket

This is hard but not impossible. ACE has no key authentication — just hash validation. Anyone with the session blob can spoof the server.

To **monitor inbound**:
- Hook `ACE_OuterHeaderParse` — log every received packet
- Hook `ACE_PacketDeserializeAndDispatch` — log decoded type + size

## Cross-references

| Doc | Topic |
|---|---|
| `82_packet_format_and_chunking.md` | Outer packet build (sender side) |
| `83_packet_dispatch_full.md` | Receive dispatch logic |
| `25_network_protocol.md` | Original network doc |
| `78_report_packet_format.md` | ace_shell_di.dat file format (different from network) |

## To-do

- Identify what each of the 4 outer-header u32 fields means (timestamp, sequence, hash, etc.)
- Map TLV record types — what types can be in the payload?
- Determine where the per-session 16-byte session blob comes from (handshake?)
- Test with REPL bridge: hook ACE_OuterHeaderParse to log inbound bytes
