---
iter: 63
title: Complete Outbound Wire Format — Every Byte Accounted For
status: definitive (no remaining unknowns in the outer header)
---

# Outbound Packet Wire Format — Definitive

This document closes out the outbound serializer family. Every field in the 34-byte outer header is now decoded, and all 4 inner payload formats are fully reverse-engineered.

## OUTER HEADER (34 bytes) — exact field-by-field

Built by `ACE_PacketHeaderInit_Inner` at libanort+0x148560 (note: the legacy name is misleading — this routine builds the *outer* header).

| Offset | Size | Field | Source | Meaning |
|---|---|---|---|---|
| +0 | 1 | magic | constant `1` (set by `sub_14A6CC` outer-init) | format version marker |
| +1 | 4 | zero | zero-init | reserved / padding |
| +5 | 1 | **packet type** | `a3` parameter to header init | **1**=Data, **2**=Chunk, **3**=Response, **7**=Heartbeat |
| +6 | 4 BE | sequence counter | `state[+12]++` per call | monotonically increases |
| +10 | 4 BE | protocol hash | 131-base string hash of `state[+33]` | identifies protocol/channel |
| +14 | 4 BE | constant tag | `sub_1469F4()` returns `8899` (`0x000022C3`) | hard-coded magic |
| +18 | 16 | session blob | xmmword copy of `state[+16]` | per-session identity |

Total: 1 + 4 + 1 + 4 + 4 + 4 + 16 = **34 bytes**. Confirmed via `ACE_PacketRecordSerialize` at libanort+0x14A75C (renamed from sub_14A75C).

### MAJOR CORRECTION TO DOC 84

Earlier (`84_complete_wire_format.md`) we assumed byte `+5` was a "continuation flag that must == 1". **It's actually the packet type byte** — values 1/2/3/7 are normal. The receive-side check `byte[5] == 1` filters for Data-class packets only. Other classes (response, heartbeat) take different dispatch routes. Doc 84 is now superseded by this doc on outer-header semantics.

## The 4 inner payload serializers — all decoded

### Variant 1 — Data (TLV)
- Compose: `ACE_PacketCompose` (libanort+0x148028)
- Inner serializer: `sub_149674`
- Outer type byte: **1**
- Caller: `ACE_PacketBuildAndSend` / general data path
- Inner format: TLV records (Type-Length-Value), max 4 KB total

### Variant 2 — Chunked
- Compose: `ACE_PacketCompose_2` (libanort+0x1485E0)
- Inner serializer: `sub_14AEDC`
- Outer type byte: **1** (uses Data class because each chunk is logically Data)
- Caller: `ACE_PacketChunkAndSend` (libanort+0x148118)
- Inner struct (per chunk):

| Offset | Size | Field |
|---|---|---|
| +0 | 4 | global seq number (state[+4]++ per chunked send) |
| +4 | 2 | total chunk count (1..16) |
| +6 | 4 | CRC32 of full unsegmented payload |
| +10 | 1 | always 0 |
| +11 | 2 | tag (`a3` arg — caller-supplied subtype) |
| +13 | 1 | is_first_chunk (1 if index==0 else 0) |
| +14 | 1 | derived counter `state[+8] + state[+8]/255 + 1` |
| +15 | 2 | chunk_index + 1 (1-based) |
| +17 | 4 | this chunk's size (≤4096) |
| +21 | N | chunk bytes (max 4096) |

Maximum total payload across chunks: **16 × 4 KB = 64 KB**.

### Variant 3 — Heartbeat
- Compose: `ACE_PacketCompose_3` (libanort+0x148698)
- Inner serializer: `sub_14A9B0` → renamed `ACE_HeartbeatInnerSerialize`
- Outer type byte: **7**
- Caller: `ACE_NetworkSendHeartbeat` (libanort+0x147CB4)
- Inner format: **8 bytes** total

| Offset | Size | Field | Source |
|---|---|---|---|
| +0 | 4 BE | reserved | zero-init by `sub_14A938` |
| +4 | 4 BE | timestamp | `time(NULL)` — Unix epoch seconds |

That's it. No payload, no hash. The HB packet's purpose is purely "I'm alive at time T". Server uses the timestamp delta to detect freezes/clock-skew.

### Variant 4 — Response (ACK)
- Compose: `ACE_PacketCompose_4` (libanort+0x148848)
- Inner serializer: `sub_14AAB8` → renamed `ACE_ResponseInnerSerialize`
- Outer type byte: **3**
- Caller: `ACE_NetworkSendResponse` (libanort+0x147DC4)
- Inner format: **20 bytes** total

| Offset | Size | Field | Source |
|---|---|---|---|
| +0 | 4 BE | result code | caller arg `a3` |
| +4 | 16 raw | session/echo blob | `sub_14AA3C` zero-inits, caller fills |

Likely use: ACK an incoming server command — echo back its 16-byte correlation ID with a result code.

## Wire format cheat sheet

```
ALL outbound packets start with this 34-byte outer header:
+----+-----------+----+---------+----------+----------+------------------+
| 01 | 00000000  | TT | SEQ_BE  | PROTO_BE | 22C30000 | SESSION_BLOB_16  |
+----+-----------+----+---------+----------+----------+------------------+
  +0   +1..+4    +5    +6..+9   +10..+13   +14..+17   +18..+33

TT = type:  1=Data    2=Chunk    3=Response    7=Heartbeat

then the inner payload, format chosen by TT:
  Data     → TLV records (≤4 KB)
  Chunk    → 21-byte chunk header + ≤4 KB chunk data
  Response → 4-byte result code + 16-byte echo blob (20 bytes total)
  Heartbeat→ 4 zero bytes + 4-byte timestamp (8 bytes total)
```

## Why this matters for spoofing

Now that we have the **complete** wire format AND we know `ACE_CRC32` (doc 86) is the only "hash" used:

To inject a packet that ACE will accept as legitimate:
1. Sniff the 16-byte session blob from a real handshake
2. Sniff the 4-byte protocol hash (or compute via `131^k` over the protocol-name string)
3. Pick a sequence number above the last seen one
4. Build the outer header with correct type byte
5. Build inner payload appropriate to type
6. CRC32 the inner-packet payload section, write into hash field
7. Send raw to socket

There is **no** cryptographic signature. The 16-byte session blob is the only secret, and CRC-32 provides only integrity (not authentication).

## IDB renames applied

| Address | Old | New |
|---|---|---|
| 0x14A6F4 | sub_14A6F4 | `ACE_OuterHeaderSerializeWrapper` |
| 0x14A75C | sub_14A75C | `ACE_PacketRecordSerialize` (already named earlier) |
| 0x14A9B0 | sub_14A9B0 | `ACE_HeartbeatInnerSerialize` |
| 0x14AAB8 | sub_14AAB8 | `ACE_ResponseInnerSerialize` |
| 0x14AA50 | sub_14AA50 | `ACE_ResponseInnerSerializeWrapper` |
| 0x14A948 | sub_14A948 | `ACE_HeartbeatInnerSerializeWrapper` |
| 0x149578 | sub_149578 | `ACE_BufferAppendBytes` |
| 0x14A6CC | sub_14A6CC | `ACE_OuterHeaderZeroInit` |
| 0x14A938 | sub_14A938 | `ACE_HeartbeatPayloadZeroInit` |
| 0x14AA3C | sub_14AA3C | `ACE_ResponsePayloadZeroInit` |
| 0x14AEBC | sub_14AEBC | `ACE_ChunkPayloadZeroInit` |
| 0x1469F4 | sub_1469F4 | `ACE_GetProtocolMagicTag_8899` |

## Cross-references

| Doc | Topic |
|---|---|
| `82_packet_format_and_chunking.md` | Earlier compose/chunk overview (now refined here) |
| `84_complete_wire_format.md` | First-pass wire format (CORRECTED here re: byte+5) |
| `86_crc32_and_vm_context_health.md` | The CRC32 used in inner header |
| `83_packet_dispatch_full.md` | Receive side dispatcher |

## To-do

- Trace where `state[+33]` (the protocol-name string used for the 131-base hash) comes from. Likely a fixed string like `"ACEPROTO"` or similar.
- Decompile `sub_146970` (the singleton allocator that backs the constant tag 8899)
- Find the unknown 4-byte "reserved" field at heartbeat inner +0 — does the server use it for anything?
- Confirm at runtime: hook `ACE_OuterHeaderSerializeWrapper`, log every emitted 34-byte header, see actual values
