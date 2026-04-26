# Packet Format and Chunking — The Full Wire Picture

ACE's network packets have a structured wire format with header magic, sequence numbers, session ID, type bytes, and payload chunks. Documented end-to-end.

## ACE_PacketBuildAndSend (libanort+0x1479D0)

The high-level packet builder:

```c
__int64 ACE_PacketBuildAndSend(state, fd, payload, payload_size, flags, optional_extra) {
    if (!payload) return -1;
    
    PacketHeader hdr;
    ACE_PacketHeaderInit(&hdr, 0x010A0023);   // magic = 17432611
    int seq = state->seq++;                    // increment sequence
    
    char inner[64+2+0x7FFF];   // 64-byte session + 2-byte size + payload
    
    sub_149648(inner);                          // init inner buffer
    ACE_SpinlockAcquire(inner, state+8, 64);   // copy 64-byte session ID
    __memcpy_chk(inner+0x51, payload, payload_size, 0x7FFF);
    *(uint16_t*)(inner+0x4F) = payload_size;
    
    // Allocate output buffer + serialize
    char* out = calloc(1, 0x1000);              // 4KB output
    list_append(&list, out);
    
    int total = 0;
    if (ACE_PacketCompose(&hdr, inner, out, 4096, &total) == 0)
        ACE_PacketChunkAndSend(state, fd, type=9, out, total);
    
    if (flags & 1)
        ACE_NetworkRecvWithTimeout(state, fd, optional_extra);
    
    return 0;
}
```

## Wire format (outer)

```
[u32 magic = 0x010A0023 (17432611)]    ← ACE_PacketBuildAndSend header
[u32 sequence_number]                  ← incremented per send
[64 bytes session ID/key]              ← copied from state+8
[u16 payload_size]                     ← max 0x7FFF (32767)
[<payload bytes>]
```

Plus the type byte (sent as part of the packet header by `ACE_PacketChunkAndSend`).

## Packet types we've identified

| Type | Purpose | Used by |
|---|---|---|
| 1 | Generic data chunk | `ACE_PacketChunkAndSend` (used internally for chunking) |
| 7 | Heartbeat | `ACE_NetworkSendHeartbeat` |
| 9 | Standard data | `ACE_PacketBuildAndSend` |

There are likely 2-6 between 7 and 9 we haven't identified, plus higher types.

## Chunking (`ACE_PacketChunkAndSend`)

If payload > 4KB, ACE chunks it into multiple network sends:

```c
ACE_PacketChunkAndSend(state, fd, type, data, total_size) {
    // Calculate chunk count: total_size / 4096 (round up)
    chunks = (total_size + 4095) / 4096;
    if (chunks > 16) return 0;   // max 16 chunks = 64KB total
    
    state->msg_seq++;            // increment message-sequence
    int hash = ACE_EventSignal(data, total_size);
    
    for (i = 0; i < chunks; i++) {
        ChunkHeader hdr;
        sub_148560(state, &hdr, type=1);   // type=1 inner header for chunks
        
        hdr.message_seq = state->msg_seq;
        hdr.chunk_count = chunks;
        hdr.message_hash = hash;
        hdr.is_first_chunk = (i == 0);
        hdr.chunk_index = i + 1;
        hdr.outer_type = original_type;    // 7, 9, etc.
        hdr.chunk_size = (i == last) ? remainder : 4096;
        
        memcpy(chunk_buf, data + i*4096, hdr.chunk_size);
        
        ACE_PacketCompose_2(&hdr, chunk_buf, send_buf, 10240);
        sub_15E084(fd, send_buf);    // actual TCP send
    }
}
```

So each chunk has its own header with: message-sequence, chunk-count, message-hash, chunk-index, outer-type, chunk-size, payload. Receiver reassembles by message-sequence.

## Maximum payload size

- `ACE_PacketBuildAndSend`: payload max 0x7FFF = 32,767 bytes (16-bit size field)
- `ACE_PacketChunkAndSend`: 16 chunks × 4096 = 65,536 bytes max
- So total max single message: ~32KB (limited by inner size field)

## ACE_NetworkRecvWithTimeout (libanort+0x1482D4)

Receives server response with select+recvfrom:
- Allocates 0x2800 (10KB) buffer
- 30-second timeout (was misread as encryption key — actually `struct timeval` with 30s)
- Calls `ACE_PacketReceiveAndDispatch` (libanort+0x1483DC) to parse and dispatch incoming packet
- Vtable+16 callback called on error

## Critical correction: `xmmword_16A3A0`

Earlier I mistakenly believed this was an encryption key. **It's actually a `struct timeval` constant** (16 bytes: tv_sec=30, tv_usec=0) used as the select() timeout. **There is NO hardcoded encryption key in libanort.**

The actual encryption (if any) happens in the inner-payload serializer or via the per-session session ID at `state+8`. We haven't fully traced this yet.

## Header magic encoding

`0x010A0023` doesn't match the date-encoding pattern of other ACE magics. Possibly:
- `0x01` = packet protocol version 1
- `0x0A` = sub-version 10
- `0x0023` = magic constant 0x23 (also used in S-box decryption!)

The `0x23` byte is the same XOR constant as `g_ace_module_sbox` decryption. This could be an intentional hint that 0x23 is ACE's "company magic byte".

## Bypass implications

The HB thread sends to `glcs.listdl.com:10012` every 1 second. To monitor:
- Hook `ACE_PacketBuildAndSend` to log every (type, size, payload_dump)
- Wireshark won't decode the custom protocol but we can read it from the application side

Currently we don't hook this — just let it run normally. With Tier 4 (drop scan rules), no detection findings end up in the queue, so only legitimate heartbeats flow.

## To-do

- Decompile `sub_15DD50` (the actual recv read loop)
- Decompile `sub_148560` (chunk header init) to see chunk header structure
- Determine if/how the inner payload is encrypted
- Trace the 64-byte session ID source (set during handshake?)
- Map `ACE_PacketReceiveAndDispatch` to see how server responses are processed
