# `WB_*` Command Protocol — Java↔Native Wire Format

ACE's primary IPC format between Java and native is **pipe-delimited key-value strings** with command name `WB_*` (Wire Bridge?). All discovered commands documented here.

## Format

```
func=<COMMAND_NAME>|<param1>=<value1>|<param2>=<value2>|...
```

Sent through:
- `JNI_ACE_ProcessCommand` (libanort)
- `senddatatosdk` / `senddatatosvr` (libanogs)
- TssIoCtl bridge

Native side parses with `ACE_ParseDelimited` (libanort+0x11C140).

## All known `WB_*` commands

| Command | Format | Purpose |
|---|---|---|
| `WB_SyncOpenID` | `func=WB_SyncOpenID\|open_id=%s\|game_id=%d\|locale=%d` | Push user's account ID to ACE |
| `WB_GetTPShellVersion` | `func=WB_GetTPShellVersion` | Query the TP shell version |
| `WB_GetReportStr` | `func=WB_GetReportStr` | Get formatted report string |
| `WB_HeartBeat` | `func=WB_HeartBeat\|index=%d\|md5=%s\|uid=%d` | Heartbeat to ACE with sequence + MD5 |
| `WB_SyncGs2Host` | `func=WB_SyncGs2Host\|game_id=%d\|cdn_host=%s\|cs_host=%s\|cs_ip=...` | Sync GS2 server config |
| (generic) | `func=%s\|game_id=%d\|open_id=%s\|pkg_name=%s\|uid=%d` | Generic command with user context |

## What's "TP shell"?

`TPShell` is Tencent Protection Shell — the binary protection wrapper. `WB_GetTPShellVersion` queries which version of TP Shell wraps the host APK. Used to:
1. Apply version-specific detection rules
2. Verify TP Shell is intact (anti-tamper)

## Heartbeat protocol details

`WB_HeartBeat`:
- `index` — sequence counter (increments per heartbeat)
- `md5` — MD5 hash of recent state (game state, detection state)
- `uid` — user ID

If heartbeats stop arriving on the server side, the user gets disconnected/banned. Each HB validates that:
1. ACE is alive
2. ACE has been running detections (md5 changes per session)
3. The user account is still the same (uid matches)

## SyncGs2Host

When the game starts, it pushes the GS2 server endpoints to ACE so ACE can validate connections. The `cs_ip=...` field is truncated in our string sample but likely contains an IP address comma-separated list.

## SyncOpenID

`WB_SyncOpenID` is called once per session at login. It tells ACE:
- The user's open_id (Tencent platform user ID)
- The game_id (numeric Tencent product code)
- The locale (region code)

ACE then includes this in every detection report sent to server.

## Generic command pattern

The format `func=%s|game_id=%d|open_id=%s|pkg_name=%s|uid=%d` shows that ACE supports arbitrary commands with **standardized user-context fields**. Any new command Tencent invents can fit this template.

## Bypass implications

To **lie about user identity**:
- Hook `JNI_ACE_ProcessCommand` to drop or modify `WB_SyncOpenID` — ACE doesn't know who you are
- This breaks per-user detection (no targeted bans)

To **block heartbeats**:
- Hook `WB_HeartBeat` send → server thinks you're disconnected
- Game may auto-disconnect you too
- More risky than just letting HBs run

To **kill all WB commands**:
- Hook `senddatatosvr` to drop all data
- Net effect: ACE collects detections but can't send them

For our deployed bypass: we don't currently hook any WB commands. ACE-side data collection runs but server-side decisions still happen normally. Our cheat (slomo) doesn't trigger detection so this is fine.

## To-do

- Find more WB_* commands (likely 20+ exist; we only found 6)
- Map the dispatcher that handles incoming WB commands (probably in JNI_ACE_ProcessCommand)
- Trace `WB_SyncGs2Host` to find the actual GS2 server URLs
- Document the relationship between "uid" in heartbeat and account ban policy
