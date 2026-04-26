# ACE Format Strings — What ACE Logs/Reports

Format strings reveal what data ACE actually collects and reports. This is the complete inventory of format strings found in libanogs (ace_decrypted_strings.txt).

## Network endpoints

| Format string | Use |
|---|---|
| `https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me` | **CONFIG DOWNLOAD URL** (hardcoded, plain) |
| `https://%s/gamesafe/mobile/%s/%08X` | Production reporting URL (per-install) |
| `%s://%s/iedsafe/Client/%s` | Generic iedsafe URL template |
| `%s/%d/%08X/tpup.zip` | TP update package URL |
| `%s/%d/%08X/tpup64.zip` | TP update 64-bit |
| `intl.acekeeper.anticheatexpert.com` | International ACE keeper subdomain (referenced in user-facing detection messages) |
| `glcs.listdl.com` | Tencent Global Cloud Service download server |
| `glcs-r1.listdl.com` | GCS region 1 |
| `dl.tomjson.com` | Tomjson download (TomJson is a Tencent serialization format) |

## /proc paths queried

| Path | Purpose |
|---|---|
| `/proc/%u/cmdline` | Process command-line (catches frida-server etc.) |
| `/proc/%u/task` | Thread directory |
| `/proc/%u/status` | Process status (TracerPid, etc.) |
| `/proc/%u/stat` | Stat info |
| `/proc/%u` | Generic /proc/PID |
| `/proc/%u/task/%u` | Thread-specific status |
| `/proc/%u/maps` | Memory maps (catches Frida agent libraries) |
| `/proc/net/tcp` | TCP connections |
| `/proc/net/tcp6` | TCP6 connections |

## File paths probed

| Path | Purpose |
|---|---|
| `/data/data/%s` | App's private data dir |
| `/data/data/%s/files` | App's files dir |
| `/sdcard/Android/data/%s/files` | Scoped storage app dir |
| `/sdcard/Android/data/%s/files/%s` | Specific file in scoped dir |
| `/data/data/%s/files/tss.rwv.tmp` | TSS read/write/verify temp file |
| `/data/data/%s/files/virap2.tss.dat` | virap2 TSS data file |
| `/sdcard/sdk/cloudphone_test_no_such_file.txt` | Cloud-phone probe |
| `/sdcard/sdk/tssmub.dat` | TSS MUB data file |
| `/__aceinfo.dat` | ACE info file (in scoped storage root) |
| `/__acecfinfo.dat` | ACE config info file |

## Frida detection paths

| Path | Tool |
|---|---|
| `/data/local/tmp/android_server` | "Android server" tool |
| `/data/local/tmp/android_server64` | 64-bit variant |
| `/data/local/tmp/12re.34frida.56server78` | Renamed frida-server with junk prefix |
| `/data/local/tmp/re.frida.server` | re.frida.server variant |
| `/data/local/tmp/frida-server` | Standard frida-server |
| `/system/bin/frida-server` | System-installed |
| `/usr/sbin/frida-server` | iOS system frida-server |
| `/var/jb/usr/sbin/frida-server` | rootless iOS variant |
| `/Library/LaunchDaemons/re.frida.server.plist` | iOS LaunchDaemon |
| `/var/jb/Library/LaunchDaemons/re.frida.server.plist` | rootless variant |

ACE iterates these paths and `access()` checks each one. Found = detection.

## TP/TSS specific paths

| Path | Component |
|---|---|
| `/data/data/com.tencent.tp/files` | TP app's files (referenced from libanogs detection) |
| `com/tencent/tp/TssSdk` | Java SDK class |
| `com/tencent/tp/DisplayMgrListener` | Display manager Java class |
| `com/tencent/tp/ScreenRecordHelper` | Screen record helper Java class |
| `com/tencent/tp/MainThreadDispatcher2` | Main thread dispatcher v2 |
| `com/tencent/tp/TssJavaMethod` | TSS Java methods bridge |

## Detection report format strings

| Format string | What it reports |
|---|---|
| `apk_cnt:%d,sys_cnt:%d,adb:%d,cache_exists:%d` | APK/system installed app counts + ADB status |
| `history_adb:%d` | Whether ADB was historically enabled |
| `reason=%s\|root=%d\|cert=%s` | Detection reason with root flag and cert info |
| `is_unlock=%d\|reason=%s` | Bootloader unlock status |
| `IsRoot=%d\|RootReason=%s\|IsNeedReqApkList=%d\|` | Comprehensive root info |
| `binder:err1:%d,cnt1:%d;err2:%d,cnt2:%d` | Binder error counts |
| `appid:%s,detail:%s,err:%s,sysver:%s,time:%p` | Detailed error report |
| `so:%s,bss_prt_err:%d` | .so file BSS protection error |
| `err=%d\|all_wp=%d\|all_bp=%d\|used_wp=%d\|used_bp=%d` | Watchpoint/breakpoint counts |
| `inf_cl:1\|%d\|%d\|%d\|%08x` | "Information collection" report |
| `tss_main:%s,0x%lx` | TSS main module address |
| `data_%d` | Generic data field |
| `c:%d,s:%d` | Compact counter pair |

## Module/state format strings

| Format string | What it reports |
|---|---|
| `iAppMachUUID:%.2X%.2X%.2X%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X` | Mach-O UUID (iOS app identity) |
| `iAppMachOUUID:...` | Same, alt format |
| `iTssSDKUUID:%s` | TSS SDK UUID |
| `iAppMainModule:%s` | App's main module path |
| `iAppMainModuleGame:%s` | Same for game module |
| `iDevIDFV:%s` | iOS Identifier-for-Vendor |
| `iAppName:%s` | App name (iOS) |
| `iAppCryptInfo:%d(0x%X,0x%X)` | App crypt info (LC_ENCRYPTION_INFO) |
| `iAppCryptInfoGame:%d(0x%X,0x%X)` | Game module crypt info |
| `iAppFileCryptInfo:%d(0x%X,0x%X)` | App file crypt info |
| `iDevInfoException:iStep(%d)` | iOS device info collection error step |
| `SImei:%s` | IMEI (Android) |

## Hash/fingerprint format strings

| Format string | What |
|---|---|
| `%08X%08X%02X%02X%02X%02X%01X%01X%01X%01X%04X%04X%04X%04X%04X%04X%04X%08X` | Long composite fingerprint |
| `%08x%08x%08x` | 12-byte hex fingerprint |
| `%08X` | 32-bit hash |
| `%04X` | 16-bit hash |
| `%08x|%s` | Hash + string |
| `cpa_%d` | CPA index format |
| `ano_box_%08x` | ANO box (sandboxed channel) |
| `ano2_box_%08x` | ANO2 box (newer sandbox channel) |

## Time format strings

| Format string | What |
|---|---|
| `%04d%02d%02d.` | Date stamp YYYYMMDD |
| `%s/test/%d/%s` | Test endpoint format |

## I/O Control reports

| Format string | What |
|---|---|
| `TssIoCtl.emm:%d,n:%s,p:%s,b:%u` | TSS ioctl, emergency mode |
| `TssIoCtl.uts:%d,n:%s,p:%s,b:%u` | TSS ioctl, user-tag scan |
| `tbt:%d,n:%s,b:%u,p:%s` | TBT (Tencent Boundary Test?) report |
| `user_tag:%s%d` | User tag value |

## User-facing error messages

These are the messages shown to users when ACE blocks them:

```
"An emulator environment is detected. Start %s before running the game. 
 If %s isn't installed, visit intl.acekeeper.anticheatexpert.com on %s 
 to download and install it."
```

```
"An abnormal environment is detected. Start %s again before running the game.
 If %s isn't installed, visit intl.acekeeper.anticheatexpert.com on %s 
 to download and install it."
```

The `%s` placeholders fill in: the ACE Keeper app name, the app name again, the platform name. ACE has a companion app users are expected to install to "fix" detection issues.

## Bypass implications

These format strings tell us:

1. **Tier 5 + DNS block** is even more important than we thought. Multiple Tencent endpoints:
   - down.anticheatexpert.com
   - intl.acekeeper.anticheatexpert.com
   - glcs.listdl.com
   - glcs-r1.listdl.com
   - dl.tomjson.com

2. **ACE collects EXTENSIVE data**: iOS UUIDs, Android IMEI, app crypt info, device info, /proc state, file existence, ADB history, root info, even bootloader unlock status. The `%08X%08X%02X%02X...` long fingerprint is probably 80+ bytes encoding the entire device fingerprint.

3. **No root needed** for most data — much of this comes from Java APIs and accessible /proc paths.

4. **ACE Keeper app exists** — `intl.acekeeper.anticheatexpert.com` suggests Tencent has a separate companion app users can download. Maybe a way to get unbanned?

## To-do

- Cross-reference each format string with its caller to see WHEN ACE collects this data.
- Capture an actual report packet to see the ordering of fields.
- Look for `ro.com.cph.*` properties — these are CloudPhone (cph) related, suggests ACE has special handling for cloud Android instances.
