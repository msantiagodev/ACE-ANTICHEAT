# ACE Anti-Cheat — Full System TL;DR

> Single-file overview of everything we know. For deep dives, see numbered sub-docs.

---

## What is it?

**ACE = "Anti-Cheat Expert"** — Tencent's mobile anti-cheat. Used in PUBG Mobile, CODM, and Division Resurgence. Two Android shared libraries cooperate inside the game's process:

| Library | Job | Size |
|---|---|---|
| `libanort.so` | The detective. Watches everything; installs spies. | 1.7 MB |
| `libanogs.so` | The messenger. Bundles reports; sends them to a server. | 5.7 MB |

Project codename: **`huiwan`** (慧玩 = "smart-play"). libanort version: **`4.9.30.24277_oversea`**.

---

## The big picture

```
┌──────────────────────────────────────────────────────────┐
│  Android Game Process                                    │
│                                                          │
│  ┌──────────────┐         ┌──────────────────┐           │
│  │  Game's      │         │ libanort.so      │           │
│  │  Java Code   │ ───────►│  (detective)     │           │
│  │              │  JNI    │                  │           │
│  │ + GP7Service │         │  - Hooks libc    │           │
│  └──────────────┘         │  - Polls scans   │           │
│                           │  - String enc    │           │
│                           └────────┬─────────┘           │
│                                    │ shared globals       │
│                                    ▼                      │
│                           ┌──────────────────┐           │
│                           │ libanogs.so      │           │
│                           │  (messenger)     │           │
│                           │                  │           │
│                           │  - 37 scanners   │           │
│                           │  - TDM reports   │           │
│                           │  - HTTP send     │ ──────────┼──► down.anticheatexpert.com
│                           └──────────────────┘           │
└──────────────────────────────────────────────────────────┘
```

---

## What ACE actually does

### 1. At init (during dlopen of libanort/libanogs)

**libanort:**
- Runs `JNI_ACE_Initialize` (registered as Java native method `initialize`)
- Calls `UE_4_9_30_24277_oversea_c3a6c` which:
  - `ACE_ConfigUpdateFromServer` → fetches signed config from CDN
  - `ACE_LoadSignedConfig` → loads + verifies the config
  - `ACE_ProcessCmdlineCheck` → reads `/proc/self/cmdline` and verifies process name
  - `ACE_DynamicLibraryLoader` → dlopen()s helper libs
  - `ACE_ShellDetector` → injection scan
  - Returns 0 if all pass
- Spawns scanner threads via `ace_pthread_create_detached(fn, arg, 0x80000)` — 512KB stacks, detached
- Installs **inline hooks on 8 libc functions** via `ACE_InstallApiHooks`:
  - Calls `ACE_ELFSetSectionPerms(libc_text, RWX)`
  - Replaces first instructions of 8 functions with `B ACE_ObfuscatedDispatch_NNNN`
  - Saves originals in `qword_1A4808–1A4840`
  - Restores libc to RX

**libanogs:**
- 60 init_array constructors run (set up vtables, singletons, scanner registry)
- `init_ctor_02` builds the JNI native method table — 11 methods including `init`, `setuserinfo`, `senddatatosvr`, `setappobject`, etc.
- `JNI_OnLoad` registers 11 methods on `com/ace/gamesafe4/...` Java class
- Also registers 3 methods (`init`, `onPause`, `onResume`) on `com/tss/gamedemo/Game`
- ANY game call to `AnoSDKInit(game_id)` then runs `ace_core_init_obfuscated` which spawns the actual detection threads

### 2. While running

- Detection threads in libanort poll `ACE_DetectionPoller` continuously
- libanogs has 37 scanner modules registered. Active in this build: 28 (the rest are conditional or hard-disabled).
- Each scan uses singleton vtables (`ACE_GetSingleton_Hash`, `ACE_GetSingleton_Detection`, `ACE_GetSingleton_ConfigStore`)
- Detections are inserted into a per-singleton red-black tree by ID via `ACE_DetectionBSTInsert(singleton, detection_id)`
- Whenever the game calls one of the 21 `AnoSDKxxx` exports, libanogs logs the call via `ace_log_sdk_lifecycle_call` → `ace_create_tdm_report` → `ace_submit_corereport`

### 3. When something is detected

There are **THREE INDEPENDENT KILL PATHS:**

#### Path 1 — libanogs scanner-detection
`scanner_thread → ace_create_tdm_report → ace_submit_corereport → ace_custom_syscall_handler → kill(getpid(), SIGKILL)`

The "messenger" library kills via libc PLT.

#### Path 2 — libanort string-decoder integrity trap
If the encrypted string table in libanort has been modified, the decoder catches it on second read:
```c
if (integrity_check_failed_again)
    linux_eabi_syscall(__NR_exit_group, &byte_7);  // raw syscall, bypasses libc
```

#### Path 3 — Java GP7Service `gp7ioctl("stop")` command
Java service calls the JNI native method `gp7ioctl(String)` registered by libanort. If the command string is `"stop"` AND `ACE_ValidateConfig(cfg, "enable_gp7_exit_group", 1)` returns true:
```c
linux_eabi_syscall(__NR_exit_group, NULL);  // raw syscall, bypasses libc
```

**Defeating only path 1 (our previous attempts) leaves paths 2 and 3 free to kill us.**

---

## How to remove ACE — 3-tier blueprint

### Tier 1: Surgical scanner-disable (cleanest)

Hook **`ace_register_scanner_module`** at libanogs `+0x22D428`. Drop registrations by name. Effect: those scanners NEVER run, so they NEVER detect, so kill chain 1 NEVER fires.

```c
__int64 my_register(void *r, void *prev, const char *name, int en, int f2) {
    static const char *blocked[] = {
        "various_opcode", "module2", "cert3", "anti_root", "process",
        "anoscan", "FakeToken", "shell_checker", "auto_defence3"
    };
    for (auto *b : blocked) if (strcmp(name, b) == 0) return (__int64)prev;
    return real_register(r, prev, name, en, f2);
}
DobbyHook(libanogs_base + 0x22D428, my_register, &real_register);
```

### Tier 2: TDM telemetry kill switch

Set 2 bytes in libanogs:
```c
*(uint8_t*)(libanogs_base + 0x57E31C) = 0;  // g_tdm_report_enabled = false
*(uint8_t*)(libanogs_base + 0x57E31D) = 1;  // g_tdm_report_checked = true
```

Effect: every report submission silently returns 0. Server never sees us.

### Tier 3: libanort kill-path defenses

Hook **`JNI_ACE_CommandDispatch`** at libanort `+0x25D94` (the gp7ioctl handler):
```c
void hooked_gp7ioctl(JNIEnv *env, jobject thiz, jstring cmd) {
    const char *str = env->GetStringUTFChars(cmd, nullptr);
    if (str && strcmp(str, "stop") == 0) return;  // drop
    if (str) env->ReleaseStringUTFChars(cmd, str);
    return real_gp7ioctl(env, thiz, cmd);
}
```

Disable config update (avoid downloading new sig rules):
```c
*(uint32_t*)(libanort_base + 0x171118) |= 0x100;
```

### Tier 4: Full SDK emulation (bonus)

Replace libanogs.so + libanort.so with a stub library that exports all 21 + 6 = 27 functions, all returning success. The 14 JNI native methods all become no-ops. Game thinks ACE is fine.

---

## Key offsets / addresses (Division Resurgence build)

### libanogs.so
| Offset | Symbol | Purpose |
|---|---|---|
| `0x22D428` | `ace_register_scanner_module` | Tier 1 hook target |
| `0x57E31C` | `g_tdm_report_enabled` | Tier 2 byte |
| `0x57E31D` | `g_tdm_report_checked` | Tier 2 byte |
| `0x28B8A8` | `ace_register_all_scanner_modules` | Calls register 37 times |
| `0x346038` | `ace_log_sdk_lifecycle_call` | Reports SDK API usage |
| `0x345C54` | `ace_create_tdm_report` | Builds TDM report |
| `0x345E60` | `ace_submit_corereport` | Submits report |
| `0x1CE750` | `ace_custom_syscall_handler` | Kill chain dispatcher (path 1) |
| `0x1E2444` | `JNI_OnLoad` | Java→native entry |
| `0x1DA368` | `AnoSDKInit` | Public SDK init |
| `0x36D764` | `ace_decrypt_string` | The default decoder |
| `0x57E4A4` | `g_decoder_dispatch_table` | 100 decoder pointers |
| `0x109A30` | encrypted string table | 87,316 bytes |

### libanort.so
| Offset | Symbol | Purpose |
|---|---|---|
| `0x25D94` | `JNI_ACE_CommandDispatch` (gp7ioctl handler) | Tier 3 hook target |
| `0x12A308` | `ACE_ValidateConfig` | Tier 3 alt hook |
| `0x171118` | `dword_171118` | Tier 3 OR with 0x100 |
| `0xF42AC` | `ACE_DetectionScanOrchestrator` | Inserts scan IDs into BST |
| `0xEE60C` | `ACE_MasterDetectionLoop` | 14KB scan loop |
| `0x71484` | `ACE_DetectionPoller` | Scanner thread fn |
| `0x71DE0` | `ace_formatted_path_scanner` | Spawns the poller; 5-sec timing check |
| `0x11C644` | `ace_pthread_create_detached` | Thread spawn wrapper |
| `0x3860C` | `ACE_InstallApiHooks` | Installs hooks on 8 libc fns |
| `0x33A4C` | `ACE_ELFSetSectionPerms` | mprotect wrapper |
| `0x11149C` | `ACE_DecryptString` | Central decoder dispatcher |
| `0x1634C0` | `g_ace_decoder_dispatch_table` | 100 decoder pointers |
| `0x1716F2` | encrypted string table | ~202 KB |
| `0x1A3010` | `g_acf_array` | 53 exported ACE Core Functions |
| `0x1A4948` | `g_aco_array` | (TBD) — exported globals |
| `0x1A4808–0x1A4840` | hooked-libc-original-fn pointers | 8 saved originals |

---

## Java-callable surface (what the game can call)

**libanogs.so** registers via JNI_OnLoad:

Class `com/tss/gamedemo/Game` (3 methods):
| Java | Native handler |
|---|---|
| `init() -> int` | `ace_jni_class1_method1` (0x1E04E4) |
| `onPause() -> int` | `ace_jni_class1_method2` (0x1E07E0) |
| `onResume() -> int` | `ace_jni_class1_method3` (0x1E0B48) |

Class `com/ace/gamesafe4/...` (11 methods):
| Java | Native handler |
|---|---|
| `init` | ace_jni_init_chained |
| `setuserinfo` | ace_jni_setuserinfo_impl |
| `setuserinfoex` | ace_jni_setuserinfoex_impl |
| `setgamestatus` | ace_jni_setgamestatus_impl |
| `getsdkantidata` | ace_jni_getsdkantidata_impl |
| `setsenddatatosvrcb` | trampoline |
| `senddatatosdk` | ace_jni_senddatatosdk_impl |
| `senddatatosvr` | trampoline |
| `onruntimeinfo` | trampoline |
| `hasMatchRate` | trampoline |
| `setappobject` | trampoline |

**libanort.so** registers via init_array_0_268d0:

Class (TBD class name — likely `com.gamesafe.ano.AnoJavaMethod` or `com.tencent.tp.TssJavaMethod`):
| Java | Native handler | Sig |
|---|---|---|
| `initialize` | JNI_ACE_Initialize (0x259D0) | `(SSSS[S)I` |
| `handleLoad` | JNI_ACE_ProcessCommand (0x1362A0) | `([BII)Object` |
| `handleLoad` (alt) | JNI_ACE_GetByteArray (0x136054) | `(Object,I)Object` |
| `handleLoadV22` | JNI_ACE_QueryData (0x136574) | `([BII)long` |
| `ioctl` | JNI_ACE_FileOperation (0x136AD8) | `(I,String)I` |
| `gp7ioctl` | JNI_ACE_CommandDispatch (0x25D94) | `(String)V` |
| `gp6ioctl` | JNI_NativeMethod_6 (0x25F48) | shared |

**Total: 21 Java→Native bridge methods.** Stubbing all 21 = full Java-side neutralization.

---

## What ACE DETECTS

### Hooking frameworks
Frida (12+ unique strings/paths), Substrate (libsubstrate, anti_substrate), Xposed (anti_xposed), EdXposed (libsandhook.edxp.so), KernelSU (me.weishu.kernelsu), CloudInject, FuckSign, PmsHookApplication.

### Root managers
Magisk + 14 specific apps (KingRoot, KingoRoot, OneClickRoot, Framaroot, SuperSU, CWM, etc.) + binary paths (`/system/app/Superuser.apk`, `/system/xbin/daemonsu`, etc.) + Zygisk paths.

### Cheat / script / automation apps
30+ specific packages: `pj.ishuaji.cheat`, `com.saitesoft.gamecheater`, `com.cyjh.gundam`, Lucky Patcher, Titanium Backup, ScriptELF, Game CIH, Muzhiwan helper, Huluxia tools, etc.

### Streaming / recording (account-protection)
TikTok, Bilibili Live, Duowan, KuaiShou Live Partner, Streamlabs.

### Account trading
8+ packages including `com.daofeng.zuhaowan`, `com.bdkj.LightningGameRental`.

### VPN / proxy
ShadowSocks, ShadowSocksR, Transocks.

### Antivirus apps
Kingsoft Duba, LBE Security, Qihoo 360.

### Emulators
TencentX86, BlueStacks (`/dev/virtpipe-*`), Genymotion (`/dev/socket/genyd`), Android-x86, Exagear, Cloud Phone (CPH), Rockchip emulators, VMOS, KVM checks, ueventd-x86, Houdini, libnative-bridge.

### Process / memory inspection paths
7 distinct `/proc/self/*` paths used for tampering detection (`maps`, `status`, `fd`, `task`, `environ`, `map_files`, `ns/mnt`).

### Sensor / token spoofing
`fake_token_androidid`, `fake_token_sensor`, internal cache `HANYCJLZOEUS_TOKEN2.dat`.

### Anti-debug
`TracerPid` parsing, `debuggerd`, `libjdwp.so`, `linker64`, `linjector-`, `rtld_db_dlactivity`.

### Java sig-bypass
`PmsHookApplication`, `CloudInject`, `FuckSign`.

---

## Network endpoints

| URL | Purpose |
|---|---|
| `https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me` | Primary download endpoint |
| `https://%s/gamesafe/mobile/huiwan/android/%s/test/%s` | Test config endpoint |
| `https://%s/gamesafe/mobile/huiwan/android/%s/%08X/%s` | Production config endpoint |

Project ID `8899`, build hash `71C1E6D7`.

The packet body uses fields:
- `110100` = source ("TSS" prefix)
- `110101` = formatted payload
- `110102` = extra data
- `100100` = severity
- `40004` = type (always 5)

Channel name: `COREREPORT`. Category: `monitor` for SDK lifecycle calls.

Fingerprint format string sent on first contact:
```
root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d
```

---

## String encryption

100 decoders. Each ordinal `N` uses `XOR_CONST = N`, `ADD_CONST = 7-(N%7)` (or 7 if 0). Algorithm: rolling XOR with 32-bit key, byte-at-a-time, with 1-byte integrity check at the end. **Failure twice triggers `exit_group(7)` directly via raw syscall.**

libanogs uses 100 named decoders called directly: `ace_decrypt_xorNN(offset)`.
libanort uses single dispatcher `ACE_DecryptString(N)` where decoder = `N % 100` and offset = N.

Verified: 2,119 unique strings in libanogs and 558 unique strings in libanort.

---

## ACE Module Vtable Layouts

The base scanner module class has 12 virtual method slots (BASE vtable at libanogs `0x528BA0`):

| Slot | Offset | Base impl | Purpose (inferred) |
|---|---|---|---|
| 0 | 0 | nullsub | virtual destructor 0 |
| 1 | 8 | (sub_1E64D4) | virtual destructor 1 |
| 2 | 16 | (sub_504610) | base virtual method (clone?) |
| 3 | 24 | `ace_module_base_cleanup` | cleanup |
| 4 | 32 | NULL | (gap) |
| 5 | 40 | nullsub | overridable method 5 (init?) |
| 6 | 48 | nullsub | overridable method 6 |
| 7 | 56 | nullsub | **scan() — overridden by detection modules** |
| 8 | 64 | nullsub | overridable method 8 |
| 9 | 72 | nullsub | overridable method 9 |
| 10 | 80 | nullsub | overridable method 10 |
| 11 | 88 | nullsub | overridable method 11 |

**Verified scan() implementations:**
- `vtable_module_cert3` (`0x52ADE8`) slot 7 = `ace_cert3_scan_method` (`0x2BB2F8`)
- `vtable_module_elf_hook_scan` (`0x52A908`) slot 8 = `ace_elf_hook_scan_method` (`0x29A9B4`) (DISABLED in this build)

**Scanner module singletons** (lazy pthread_once init):
- `g_singleton_frida_scan` at `0x579F50`, vtable `vtable_module_frida_scan`
- `g_singleton_cert3` at `0x579F88`, vtable `vtable_module_cert3`
- `g_singleton_cps_new` at `0x579FB0`, vtable `vtable_module_cps_new_alt`

---

## Update Channel & Rule Files

`ace_init_ob_zip_filenames` (init_array slot 3) initializes 6 download filenames:

| Filename | Channel | Arch |
|---|---|---|
| `ob_cdn2.zip` | CDN | 32-bit |
| `ob_cs2.zip` | CS (Control Server) | 32-bit |
| `ob_gs2.zip` | GS (Game Server) | 32-bit |
| `ob_cdn2_64.zip` | CDN | 64-bit |
| `ob_cs2_64.zip` | CS | 64-bit |
| `ob_gs2_64.zip` | GS | 64-bit |

**Network blocking these filenames freezes ACE on baked-in rules** — no fresh detection signatures download.

---

## Report channel pipeline

ACE has multiple corereport channels routed via the `g_corereport_singleton`:

| Channel name | Purpose |
|---|---|
| `COREREPORT` | Main detection report channel |
| `REMOTECONFIG` | Remote config fetcher (only opened if SDK version ≥ 1.0.0.74) |
| `CONNECTOR` | gcloud_connector channel — fetches from server |

Init: `ace_init_remoteconfig_channel` checks SDK version via `sscanf("%d.%d.%d.%d", ...)` against `1000074` minimum.

---

## Init Marker reports

ACE submits TDM reports at lifecycle moments:
- `TSSInit:tss_sdk_init_start` — SDK init begin
- `TssSDKInit`, `TssSDKSetUserInfo`, `TssSDKOnPause`, `TssSDKOnResume`, `TssSDKGetReportData`, `TssSDKDelReportData`, `TssSDKOnRecvData` — lifecycle hooks (each via `ace_log_sdk_lifecycle_call`)

The `monitor` category (in COREREPORT) collects these. Field `100100` = severity, `40004` = type=5, payload at field `110101`.

---

## libanort init order (verified)

`JNI_ACE_Initialize` → `ace_init_core_v4_9_30_24277_oversea`:
1. `ACE_GetTime()` — record start time (for `ACE_TimeBoundsValidator`)
2. `ACE_DecryptString(12303)` — init message
3. `ACE_ConditionalLockAcquire` — lock
4. Store JNI env at `singleton+160`, args at `+184`
5. **`ACE_ConfigUpdateFromServer`** — fetch signed config from CDN (gated by `g_anort_config_flags & 0x100`)
6. **`ACE_LoadSignedConfig`** — verify + apply
7. **`ACE_ProcessCmdlineCheck`** — read `/proc/self/cmdline`, validate process name, set bit at `singleton+178`
8. **`ACE_DynamicLibraryLoader`** (×N) — dlopen helper libs (libart.so resolution etc.)
9. **`ACE_ShellDetector(ctx, 1)`** — runs the shell injection / hook detector
10. `ACE_FormatVersion` — formats version into output
11. `ACE_ConditionalTimingReporter` — submits timing report
12. Returns 0 if all pass

Total time spent in this chain is the timing window measured by `ace_thread_cracked_timing_check`. **If this chain takes >5s, `thread_cracked` fires.**

---

## Files in this directory

| File | Contents |
|---|---|
| `00_TLDR_FULL_SYSTEM.md` | This file — overall summary |
| `ACE_MASTER.md` | Top-level master reference |
| `01_string_decryption.md` | Encryption algo deep-dive |
| `02_init_flow.md` | dlopen → init_array → JNI_OnLoad |
| `03_detection_targets.md` | Inventory of detected things |
| `04_libc_hook_watch.md` | libc-watch list + dispatcher |
| `05_scanner_modules.md` | The 37 scanner modules |
| `06_removal_emulation_blueprint.md` | Bypass strategy code |
| `07_libanort_structure.md` | Sister-library survey |
| `08_gp7ioctl_protocol.md` | GP7Service IPC + stop kill |
| `09_ace_inline_hooks.md` | The 8 libc hooks ACE installs |
| `10_libanort_strings.md` | Decoded libanort strings |
| Engineering scripts | `decrypt_*.py`, `ida_extract_*.py`, `parse_*.py` |
| Decoded tables | `decoder_call_sites.txt`, `decoder_call_sites_libanort.txt`, `all_decoded_strings.txt` |
