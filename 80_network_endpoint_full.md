# ACE Network Endpoint — Confirmed: `glcs.listdl.com:10012`

After extensive tracing, we've confirmed ACE's **production network endpoint**: it connects to `glcs.listdl.com` on TCP port 10012 via a custom TLS-like protocol.

## Discovery chain

```
Heartbeat needed
    ↓
ACE_NetworkConnectWithDNS (libanort+0x147910)
    ↓
1. ACE_GetGlcsHostname (libanort+0x147B2C)
   └─ ACE_DecryptString(12469) = "glcs.listdl.com"
   
2. ACE_DNSResolve(hostname, &results)  (libanort+0x15DAC4)
   └─ getaddrinfo() to get list of IPs
   
3. For each IP:
   a. ACE_TLSHandshake(this, ip)  (libanort+0x147B9C)
      ├─ ACE_TcpConnect(ip, 0x271C = 10012)  (libanort+0x15E110)
      ├─ Set up TLS state via sub_15DBEC/DD38/DD44 (likely SSL_CTX_new + SSL_set_fd)
      ├─ ACE_NetworkSendHeartbeat(this, fd)  — Client Hello
      ├─ Read server params (sub_147D1C)
      ├─ ACE_NetworkSendResponse(this, fd, params)
      ├─ Send additional data (sub_147E4C)
      └─ ACE_NetworkReceiveData(buf=256 bytes)
   b. If success → return socket
   c. If fail → close socket + try next IP
   
4. If all IPs fail → return -1
```

## The network endpoint

| Property | Value |
|---|---|
| **Hostname** | `glcs.listdl.com` (string ID 12469) |
| **Port** | TCP **10012** (`0x271C`) |
| **Protocol** | Custom TLS-like (NOT standard HTTPS) |
| **Purpose** | Heartbeats, detection reports, server commands |

## Why this matters

`glcs.listdl.com:10012` is the **single point** for ACE-to-Tencent communication. Block this and ACE goes silent.

If a user adds to their `/etc/hosts` (or Android equivalent):
```
0.0.0.0 glcs.listdl.com
0.0.0.0 dl.listdl.com
0.0.0.0 glcs-r1.listdl.com
0.0.0.0 down.anticheatexpert.com
```
ACE cannot reach any server. **Effective DNS-level bypass.**

The TCP fail behavior in `ACE_NetworkConnectWithDNS`: tries all resolved IPs, returns -1 on total failure. ACE then operates in "offline" mode — local detection still runs, but no reports leave the device.

## Other Tencent domains we've seen

| Domain | Use |
|---|---|
| `glcs.listdl.com` | **Confirmed: production heartbeat/report channel** |
| `glcs-r1.listdl.com` | Region 1 mirror |
| `dl.listdl.com` | Generic download |
| `dl.tomjson.com` | Tomjson (Tencent serialization) downloads |
| `down.anticheatexpert.com` | CDN for `ob_*.zip` updates |
| `intl.acekeeper.anticheatexpert.com` | International ACE Keeper service |

For complete isolation, block all 6.

## Custom TLS protocol

ACE doesn't use standard HTTPS. Port 10012 + custom handshake = Tencent's proprietary game protocol. Likely related to their MMG (MultiMedia Gateway) or GS2 (Game Service 2) protocols.

Wireshark would see:
- TCP SYN/ACK to 10012
- Then opaque encrypted bytes (NOT TLS Client Hello pattern)
- Bidirectional data exchange
- TCP FIN

Decoding this protocol would require:
- Reverse-engineering `sub_15DBEC` / `sub_15DD38` (SSL state setup)
- Capturing handshake bytes via Frida-on-`send`
- Cryptanalysis of the opaque payloads

## Bypass strategy

### Network-level (cleanest)
Block DNS for `glcs.listdl.com`. ACE can't connect. Done.

### Application-level
Hook `ACE_NetworkConnectWithDNS` to return -1 immediately. Same effect, no DNS games.

### Client-side stealth
Hook `ACE_NetworkSendHeartbeat` to drop bytes. ACE thinks it sent, server hears nothing.

### Currently deployed
None of the above. We let the network fire normally. Our cheat doesn't generate detections, so reports are clean.

## Cross-references

| Doc | Topic |
|---|---|
| `25_network_protocol.md` | Original network doc |
| `42_format_strings_inventory.md` | Network endpoint URLs |
| `71_gcloud_remote_config.md` | GCloud SDK channel |

## To-do

- Capture actual packet bytes via REPL bridge or Frida on `send/recv`
- Decompile `sub_15DBEC` and friends to understand the TLS state machine
- Determine if the connection persists across heartbeats or reconnects each time
- Check if `glcs-r1.listdl.com` is the failover when `glcs.listdl.com` is unreachable
- Examine if the protocol uses standard SSL/TLS or fully custom
