# libanort.so Decoded String Inventory

**Source:** `decoder_call_sites_libanort.txt` (558 unique offsets, 526 successfully decoded).

**Encryption:** Same 100-decoder-variant scheme as libanogs, BUT instead of 100 named decoders called directly, libanort routes ALL string lookups through a single dispatcher `ACE_DecryptString(int N)` at `0x11149C`. The dispatcher does `g_ace_decoder_dispatch_table[N % 100]()` and the offset N also encodes the decoder ordinal. Strings are pre-placed at offsets where `(offset % 100) == correct decoder ordinal`. Encrypted table base: `0x1716F2`, size 202,850 bytes.

**Verified self-destruct:** if integrity check fails twice in a decoder, the decoder calls `exit_group(7)` directly via raw `linux_eabi_syscall(__NR_exit_group, &byte_7, ...)`. **DO NOT TAMPER WITH THE ENCRYPTED TABLE BYTES.**

---

## SDK identity strings (multi-naming)

ACE supports MULTIPLE branding identities — all dispatch to the same underlying logic. Each game build picks one identity via config:

| Family | Strings present in libanort.so |
|---|---|
| **TSS (Tencent Security Solution)** | `tss_sdk_init`, `tss_sdk_setuserinfo`, `tss_sdk_setuserinfo_ex`, `tss_sdk_setgamestatus`, `tss_sdk_ioctl`, `TssSDKInit`, `TssSDKSetUserInfo`, `TssSDKOnPause`, `TssSDKOnResume`, `TssSDKGetReportData2` |
| **TP2 (Tencent Protection v2)** | `tp2_sdk_init`, `tp2_sdk_init_ex`, `tp2_setuserinfo`, `tp2_setgamestatus`, `tp2_sdk_ioctl` |
| **ACE (Anti-Cheat Expert)** | `AceSDKMethodInit`, `AceSDKSetUserInfo`, `AceSDKGetReportData2` |
| **Ano (Anonymous)** | `AnoSDKMethodInit`, `AnoSDKSetUserInfo`, `AnoSDKGetReportData2` |

The Division Resurgence build picks the **Ano** identity (matches what we see in libanogs.so exports — all `AnoSDKxxx`).

---

## Project codename: `huiwan` (慧玩 = "smart-play")

Two URL templates discovered:
- **Test endpoint:** `https://%s/gamesafe/mobile/huiwan/android/%s/test/%s`
- **Production:** `https://%s/gamesafe/mobile/huiwan/android/%s/%08X/%s`

Combined with libanogs's `https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me` — we have two distinct CDN paths the SDK uses.

`shell_cdn_dom` (offset 10911) and `shell_cs_dom` (offset 10927) are decryption keys for the CDN domain and CS (control server?) domain. Combined with `shell_rom.zip` (the binary blob downloaded), we know there's a **shell rom file** that ACE downloads to update its detection rules.

---

## Detection target inventory (specific to libanort)

### Frida (multiple paths beyond libanogs)
- `frida`, `frida-agent`, `frida-gadget`
- `/data/local/tmp/frida-server`, `/data/local/tmp/re.frida.server`, `/system/bin/frida-server`
- `linjector-` — Linker injector (frida-related)

### Anti-debug
- `TracerPid` — parses `/proc/self/status` for tracer detection
- `debuggerd` — Android crash daemon
- `libjdwp.so` — Java Debug Wire Protocol library
- `android/os/Debug.isDebuggerConnected` — Java-level debugger check
- `linker64` — checking the Android linker
- `rtld_db_dlactivity` — gdb's runtime-link symbol

### Java sig-bypass / app cloning
- `cc/binmt/signature/PmsHookApplication` (PmsHook is a known sig bypass)
- `com/cloudinject/feature/App` (CloudInject)
- `np/manager/FuckSign` (FuckSign)
- `com.gamesafe.ano.AnoJavaMethod`
- `com.tencent.tp.TssJavaMethod`

### Emulator (x86 / Genymotion / Exagear)
- `/system/framework/x86` (x86 emulator marker)
- `ueventd.android_x86.rc` (Android-x86 init script)
- `/system/lib/ld-android.so.exagear` (Exagear ARM-translation layer)
- `/system/priv-app/TGPAServer/TGPAServer.apk.exagear`
- `/dev/socket/genyd` (Genymotion daemon)
- `/data/data/com.tencent.tgpa.server` (Tencent's GPA helper)
- `/data/data/com.tencent.tinput` (Tencent input method)

### Mono/Unity (so they don't false-positive Unity games)
- `Assembly-CSharp`, `Assembly-CSharp-firstpass`, `Assembly-CSharp.dll`
- `libmono.so`

### `/proc` paths
- `/proc/%d/cmdline`, `/proc/%u/status`
- `/proc/self/maps`, `/proc/self/fd`, `/proc/self/fd/%s`, `/proc/self/fd/%d`, `/proc/self/./fd/%d`
- `/proc/self/status`

### Filesystem paths
- `/data/data/`, `/data/data/%s`, `/data/data/%s/files`, `/data/app/`, `/data/user/0/`
- `/data/data/%s/files/virap2.s.dat` (some virtual app cache file)
- `/system`, `/system/bin/dex2oat`, `/system/framework/x86`

### Java reflection
- `getClass`, `getName`, `getSuperclass`, `getPackageName`, `getApplicationInfo`, `getFilesDir`, `getAbsolutePath`, `sourceDir`, `nativeLibraryDir`, `getContentResolver`
- `findClass`, `loadClass`, `getClassLoader`, `toString`, `dalvik.system.PathClassLoader`
- `base.apk`, `META-INF`, `AndroidManifest.xml`
- `getApkAssets`, `getAssets`, `getAssetPath`

### USB / ADB detection
- `android.hardware.usb.action.USB_STATE`
- `ADB_ENABLED`
- `IntentFilter`, `addAction`, `getExtras`, `getBoolean`, `connected`, `registerReceiver`

### ACE-internal / config strings
- `comm.dat`, `comm.zip` (downloaded data files)
- `config2.xml`, `DEFAULT`, `probability`, `assets/__acinfo.tsd` (ACE info file)
- `s_open_id`, `time_magic`, `AnoStamp`, `metaData`
- `apk_path`, `shell_ver`, `shell_%08x`, `shell_cast1`, `shell.vm.hb`
- `lib_dir`, `files_dir`
- `gp6ioctl`, `gp7ioctl` — **Generation 6/7 ioctl handler names** (this is where the `:GP7Service` process gets its name!)
- `func_state`, `check_state`, `unlink_cflag`
- `application`, `DetailSecurityCheck`, `getPackageManager`

### Java handle identifiers
- `handleLoad`, `handleLoadV22` (offset 110, 123 — likely the JNI-callable Java methods)

---

## How libanort relates to GP7Service process

The `:GP7Service` Android service that we observed dying alongside the main process — its name comes from **`gp7ioctl`** (offset 158 in libanort). Generation 7 of Tencent's protection introduces this auxiliary service. The split-process design means:
- Main process: runs the game
- :GP7Service: runs the ACE scanners + reports

When the main process dies, GP7Service typically also exits. When GP7Service detects something, it can signal main process to die.

---

## Bypass implications specific to libanort

1. **Don't tamper with the encrypted string table** — every decoder check has the kill-on-failure-twice trap.
2. **The shell.vm.hb (heartbeat) string** suggests there's a heartbeat mechanism between the host and the shell-VM. Identifying its function might let us spoof the heartbeat.
3. **`assets/__acinfo.tsd`** is a file ACE expects at a specific path — check the APK we packaged whether this file is present (it should be from the original; we shouldn't break it).
4. **`probability`** suggests ACE has probabilistic-detection — some scanners only fire X% of the time. Useful to know when correlating death timing.
5. **Multiple SDK identities** (TSS/TP2/Ace/Ano) means we can EMULATE the Ano API without worrying about TSS/TP2 — we only need 21 entry points.

---

## Next iteration

- Decompile `gp7ioctl` handler to understand the GP7Service IPC
- Decode more strings (the 32 FAIL entries — try other decoders)
- Find where `comm.zip` is downloaded from (likely the same network code that hits `down.anticheatexpert.com`)
- Map `assets/__acinfo.tsd` content (file format)
- Cross-correlate libanogs and libanort SDK names (which one is canonical?)
