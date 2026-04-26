# Packet Receive Dispatch — Server Command Surface

ACE's server can send back exactly **2 command types** (9 and 11) which are dispatched through a vtable. The receiver path is fully validated with version, hash, and size checks.

## Receive flow

```
Server sends bytes
    ↓
ACE_NetworkRecvWithTimeout (libanort+0x1482D4)
    ↓
ACE_PacketReceiveAndDispatch (libanort+0x1483DC)
    │
    ├─ Parse outer header via sub_14A824
    ├─ If header byte[5] == 1 (continuation flag):
    │     Forward to ACE_PacketDeserializeAndDispatch
    │
    ↓
ACE_PacketDeserializeAndDispatch (libanort+0x148464)
    │
    ├─ ACE_PacketBufferZero (4117-byte buffer init)
    ├─ sub_14B024: parse inner packet
    ├─ Validate:
    │   • size_consumed == data_size (no leftover bytes)
    │   • version == 1
    │   • ACE_EventSignal(payload, payload_size) == hash_in_packet
    │   • flag byte == 1
    │   • payload_size <= 0x1000 (4KB max)
    │
    ├─ Dispatch by packet type:
    │   • Type 9 → vtable[1](receiver_ctx, payload)
    │   • Type 11 → vtable[3](receiver_ctx, payload)
    │   • Other → reject (-1)
```

## Validation order (server can't spoof)

1. **Wire format**: outer header parses correctly
2. **Continuation flag**: byte[5] == 1
3. **Inner version**: == 1
4. **Hash matches**: server can't lie about contents
5. **Flag byte**: == 1
6. **Size limit**: <= 4KB

If any check fails → return -1 (drop packet). Server cannot inject malformed data to crash ACE.

## Packet type 9 (vtable[1])

Type 9 is the standard data type ACE uses for outbound — and apparently the server uses the same type for replies. Likely contains:
- Server acknowledgment of detection report
- Updated config bytes
- Force-scan triggers

vtable[1] is "process generic data" — exact handler depends on receiver context.

## Packet type 11 (vtable[3])

Less common. Likely for:
- Special server commands (force-update, force-disconnect)
- Out-of-band metadata

vtable[3] is "process control message" — handler index 3 in receiver's vtable.

## Maximum receive size: 4KB

ACE refuses any inbound payload > 4096 bytes. So the server's command set is constrained — no big binary blobs over this channel. Larger downloads (rules, modules) use the separate CDN path (`ob_*.zip` via `down.anticheatexpert.com`).

## TLS state primitives (clarified)

The "TLS" handshake is actually a custom protocol layered on a buffered socket:

| Function | Purpose |
|---|---|
| `ACE_SocketStateInit` (libanort+0x15DBEC) | Allocates 10KB recv buffer; sets vtable to `off_165070` |
| `ACE_SocketStateSetPort` (libanort+0x15DD38) | Sets port at +12, clears recv_offset at +24 |
| `ACE_SocketStateSetParams` (libanort+0x15DD44) | Sets (proto_family=1, sock_type=4, ssl_flag=1) at +32/+36/+40 |
| `ACE_SocketStateDestroy` (libanort+0x15DC3C) | Frees recv buffer, resets vtable |

`off_165070` is the buffered-socket vtable. It probably has slots for `read`, `write`, `flush`, etc.

## Inner packet header init

`ACE_PacketHeaderInit_Inner` (libanort+0x148560) populates a chunk header with:
- Sequence number (state seq counter, incremented)
- 131-base polynomial **string hash** of the string at state+33 (used as protocol identifier)
- A 16-byte field copied from state+16 to packet+18

The 131-base hash isn't standard djb2 (which uses 33). It's `hash = (131 * hash + byte)`. Possibly a Tencent custom hash for protocol versioning.

## ACE_EventSignal — the payload integrity hash

This function is used everywhere ACE needs a content hash. Used here as the receive-validation hash. We documented it earlier; appears to be a CRC-style computation.

## Bypass implications

For our deployed bypass:
- Server can't push commands we don't already handle (we're not running in that thread)
- The 2 server-side dispatch paths (vtable[1], vtable[3]) are NOT killed by our patches
- A malicious server could trigger detection-related callbacks

For complete server-side isolation:
- DNS-block `glcs.listdl.com` (per `80_network_endpoint_full.md`)
- Or hook `ACE_PacketReceiveAndDispatch` to drop everything

Currently NOT deployed — server-side commands aren't a vector our cheat creates.

## To-do

- Identify the receiver vtable (likely related to `g_libanogs_corereport_singleton` or HB thread context)
- Decompile `sub_14A824` (outer header parser) to know the wire format precisely
- Decompile `sub_14B024` (inner packet parser) for the body format
- Cross-reference with the ACE_PacketCompose family — is _2/_3/_4 for different packet types?
