# Complete `ob_*.zip` Inventory

ACE downloads **multiple tiers of `ob_*.zip` files** from the CDN. Each contains rule modules, scanner definitions, and detection logic. Tiers can be hot-swapped without app updates.

## Naming convention

`ob_` = "object bytecode" (educated guess). Each ZIP contains:
- `vm_main.img`, `vm_hb.img`, etc. (the .img modules we documented)
- Rule definitions for the rule interpreter
- Scanner registration data

## All known `ob_*.zip` variants (from libanogs strings)

| ZIP name | String ID | Purpose |
|---|---|---|
| `ob_normal.zip` | 44292 | Normal scanner package (32-bit baseline) |
| `ob_normal_ver.zip` | 44308 | Version metadata |
| `ob_normal_64.zip` | 44347 | 64-bit variant |
| `ob_builtin.zip` | 44461 | **Built-in** (embedded in libanogs, not downloaded) |
| `ob_x.zip` | 44478 | "X" variant — extension scanner |
| `ob_x_ver.zip` | 44489 | X version metadata |
| `ob_x_64.zip` | 44518 | X 64-bit variant |
| `ob_x_ace.zip` | 44532 | X with ACE-specific rules |
| `ob_x_ace_64.zip` | 44565 | X-ACE 64-bit |
| `ob_cdn1.zip` | 44662 | CDN tier 1 |
| `ob_cdn1_64.zip` | 44693 | CDN tier 1, 64-bit |
| `ob_cdn2.zip` | 44710 | CDN tier 2 (deeper detection) |
| `ob_cdn2_64.zip` | 44741 | CDN tier 2, 64-bit |
| `ob_cs1.zip` | 44758 | CS (Cheat Scanner) tier 1 |
| `ob_cs1_64.zip` | 44787 | CS tier 1, 64-bit |
| `ob_cs2.zip` | 44962 | CS tier 2 |
| `ob_cs2_64.zip` | 44991 | CS tier 2, 64-bit |
| `ob_gs1.zip` | 45007 | GS (Game Scanner?) tier 1 |
| `ob_gs2.zip` | 45020 | GS tier 2 |
| `ob_gs2_64.zip` | 45049 | GS tier 2, 64-bit |
| `ob_custom.zip` | 45215 | Custom (per-game) overrides |
| `ob_idle` | 45363 | Idle state marker (not a real ZIP) |
| `ob_abort` | 45382 | Abort state marker |

That's **22 distinct ZIP variants** (including 32/64-bit pairs).

## Tier hierarchy

ACE has a **3-tier scanner system**:

```
Tier 1 (CS1/CDN1/GS1) — basic detection (root, emulator)
    ↓
Tier 2 (CS2/CDN2/GS2) — deeper detection (anti-Frida, hooks)
    ↓
Custom (ob_custom.zip) — per-game/per-deployment rules
```

Higher tiers run more expensive checks. ACE escalates if lower tiers detect suspicious activity.

## CDN download URL

From string ID 40953 (libanogs):
```
https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me
```

The marker file `donot_delete_me` confirms this is reachable. The path format is:
- `/iedsafe/Client/<platform>/<port?>/<install_id>/<filename>`
- 8899 — port or version code
- 71C1E6D7 — install ID (per-device)

Other URLs we documented:
- `https://%s/gamesafe/mobile/%s/%08X` — production reporting
- `%s/%d/%08X/tpup.zip` — TP update
- `intl.acekeeper.anticheatexpert.com` — international keeper service
- `glcs.listdl.com` — Tencent Global Cloud Service
- `glcs-r1.listdl.com` — region 1
- `dl.tomjson.com` — Tomjson (Tencent serialization) downloads

## CDN preferences

String IDs 5682, 5720, 7807:
- `cdn_host` — preferred CDN host
- `ext_cdn_first` — try external CDN first
- `is_update_cdn_ok` — flag: did the CDN update succeed

These let ACE try multiple CDN endpoints (China-mainland vs international) and fall back if one fails.

## Bypass implications

**To completely sever ACE from server**:
1. Block DNS for: down.anticheatexpert.com, intl.acekeeper.anticheatexpert.com, glcs.listdl.com, glcs-r1.listdl.com, dl.tomjson.com
2. ACE cannot download new ob_*.zip files
3. ACE falls back to `ob_builtin.zip` (embedded in libanogs)
4. Built-in detection runs but no fresh rules/IOCs

This is **Tier 5 + DNS block**, the proven complete-isolation strategy.

**Currently deployed**:
- Tier 5: `g_anort_config_flags |= 0x100` blocks `ACE_ConfigUpdateFromServer`
- DNS block: at the user's discretion (we don't enforce; user responsible for hosts file)

The combined effect:
- ACE always uses `ob_builtin.zip` (cached from compile time)
- Server cannot push new detection rules
- Detection capability is frozen at app-build-time levels

## To-do

- Trace the download URL composition (which template + which params)
- Find the install_id source (71C1E6D7 in URL)
- Check if `tpup.zip` is yet another download (TP update package)
- Investigate `ob_x_ace.zip` — is "ACE" just branding or a separate scan tier?
