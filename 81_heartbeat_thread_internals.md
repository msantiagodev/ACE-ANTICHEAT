# Heartbeat Thread — The 1-Second Send Loop

ACE has a dedicated background thread that wakes every second to send queued data to `glcs.listdl.com:10012`. Documented end-to-end.

## The thread function

`ACE_HeartbeatThreadLoop` (libanort+0x147788) is the thread main:

```c
void* ACE_HeartbeatThreadLoop(void* this) {
    while (1) {
        sleep(1);                                        // sub_1220F4(1) = sleep(1)
        
        LinkedList pending = {0, 0, 0};
        ACE_HBThread_CollectPending(this, &pending);     // sub_147670 — gather queued data
        
        if (pending.count > 0) {
            ACE_HBThread_DispatchPending(this, &pending);  // sub_1476D8 → ACE_NetworkBatchSend
        }
        
        // Free the linked list entries
        for (entry = pending.head; entry; ) {
            next = entry->next;
            ACE_Free(entry, 0x20u);
            entry = next;
        }
    }
}
```

## Cadence

ACE's network thread polls for outbound data **every 1 second** (`sleep(1)`). When data is ready:
1. Connect to `glcs.listdl.com:10012` via DNS (`ACE_NetworkConnectWithDNS`)
2. Iterate queued data entries (linked list)
3. For each entry: call `ACE_PacketBuildAndSend` to encode + send
4. Close socket
5. Free entries

## Per-message flow (a single send)

```
Detection happens (rule fires)
    ↓
Add (data, size) to ACE_HBThread queue (linked list)
    ↓
... (waits up to 1s for next thread tick) ...
    ↓
ACE_HeartbeatThreadLoop wakes up
    ↓
ACE_HBThread_CollectPending — drain the queue
    ↓
For each entry:
  ACE_NetworkBatchSend
    ↓
  ACE_NetworkConnectWithDNS — dial glcs.listdl.com:10012
    ↓
  ACE_PacketBuildAndSend — encode payload + send via TLS
    ↓
  Free entry, move to next
```

## Why every 1 second?

- **Latency**: 1-second ceiling on detection-to-server delay
- **Batching**: avoids 1 socket per detection (could DDOS the server)
- **Fast enough**: 1 second is faster than a human can react to "I should disconnect"

## TLS state init (`ACE_SocketStateInit`)

`ACE_SocketStateInit` (libanort+0x15DBEC) allocates a 0x2800 (10KB) buffer per socket and initializes the state struct:

```c
void* ACE_SocketStateInit(SocketState* state, int fd) {
    state->vtable = &g_socket_state_vtable;
    state->fd = fd;
    state->fd_dup = -1;
    state->magic = qword_16A238;        // some session-specific magic
    state->buf = malloc(0x2800);        // 10KB buffer
    state->buf_used = 0;
    state->state_byte = 0;
    return state->buf;
}
```

This is **NOT** standard SSL/TLS — it's a custom buffered socket wrapper with vtable-driven state machine. Likely supports:
- Custom TLS-like handshake (the 5-step process we documented)
- Encryption/decryption of payloads
- Buffered I/O for batched messages

## Where is the thread spawned?

`ACE_HeartbeatThreadLoop` is referenced from `0x165000` (data segment), suggesting it's a vtable entry. The thread is likely spawned via `pthread_create(_, _, c_trampoline, this)` similar to the `ace_periodic_scan_thread_main` we documented.

## Where messages come from

`ACE_HBThread_CollectPending` (libanort+0x147670) drains a queue. Producers:
- Detection scanners enqueue findings
- Heartbeat sender enqueues HBs
- Report builder enqueues serialized reports

The exact producer paths need more tracing, but our existing Tier 4 (drop scan rule results) prevents detection findings from reaching this queue.

## Bypass implications

To **completely silence** ACE's network channel:
1. Hook `ACE_HeartbeatThreadLoop` — return immediately, thread exits
2. Or hook `ACE_NetworkConnectWithDNS` — fail every connect
3. Or block DNS for `glcs.listdl.com`

For our deployed bypass:
- We don't kill this thread
- ACE's HB thread runs; sees no detections (Tier 4 dropped them); sends only normal heartbeats
- Server thinks we're a normal user

## Cross-references

| Doc | Topic |
|---|---|
| `25_network_protocol.md` | Full network protocol |
| `42_format_strings_inventory.md` | All printf format strings |
| `78_report_packet_format.md` | ace_shell_di.dat format |
| `80_network_endpoint_full.md` | Server endpoint and TLS handshake |

## To-do

- Trace caller chain that pushes messages into the HB queue
- Decompile `sub_120760` and `sub_120708` (per-send context setup/cleanup)
- Map the actual encryption used in ACE_PacketBuildAndSend
- Test what happens if we drop all `send()` calls — does ACE detect "i can't reach server"?
