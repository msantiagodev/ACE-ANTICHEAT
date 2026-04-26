# ACE Detection Inventory — Everything ACE Watches For

This is the complete catalog of strings and patterns ACE looks for, decoded from libanogs and libanort string tables.

## Purpose

Even without decoding each CFG-flattened scan() method, we can infer what each scanner detects by looking at the strings it references. ACE uses encrypted strings extensively — every detection target has a matching encrypted string in the binary's data segment.

## Tier 1: Reverse Engineering Tools

### Frida (multiple variants)

| String | Source | Detection |
|---|---|---|
| `/data/local/tmp/frida-server` | libanort | Standard frida-server install location |
| `/data/local/tmp/re.frida.server` | libanort | Renamed frida-server |
| `/system/bin/frida-server` | libanort | System-installed frida-server |
| `frida-agent` | libanort | Frida injection agent name |
| `frida-gadget` | libanort | Frida gadget library |
| `linjector-` | libanort | Linjector tool prefix |
| `frida_strategy` | libanogs | Active frida detection strategy |
| `frida_server_strategy` | libanogs | Frida-server-specific strategy |

ACE walks `/proc/[pid]/cmdline` for every running process and matches against these. Also scans `/proc/[pid]/maps` for the agent library names.

### Substrate / Tweak Injection (iOS variants)

| String | Detection |
|---|---|
| `/var/jb/Library/MobileSubstrate/` | rootless-jailbreak Substrate |
| `/var/jb/usr/lib/libsubstrate.dylib` | rootless Substrate dylib |
| `/usr/lib/libsubstrate.dylib` | Standard Substrate dylib |
| `MobileSubstrate.dylib` | Substrate base dylib |
| `SubstrateBootstrap.dylib` | Substrate bootstrap |
| `SubstrateLoader.dylib` | Substrate loader |
| `SubstrateInserter.dylib` | Substrate inserter |
| `/Library/MobileSubstrate/DynamicLibraries/` | Tweak directory |
| `/usr/lib/TweakInject/` | TweakInject directory |
| `TweakInject.dylib` | TweakInject lib |
| `libinjector.dylib` | Generic injector |

(Even though our target is Android, ACE shares iOS detection strings — same binary serves both platforms.)

### Other hooking tools

| String | Detection |
|---|---|
| `libsandhook.so` | SandHook framework |
| `libsandhook-native.so` | SandHook native variant |
| `libhookzz.so` | HookZz library |
| `hookzz.dylib` | HookZz iOS variant |
| `substrate_strategy` | Substrate-specific strategy |

## Tier 2: Game Cheating Tools

### Memory editors / cheating overlays

| String | Detection |
|---|---|
| `/Applications/iGameGuardian.app` | iGameGuardian (iOS) |
| `iGameGuardian` | iGameGuardian process name |
| `gamecheater.dylib` | Generic game cheater |
| `gamehack` / `gamehacker` | Lookup keywords |
| `pj.ishuaji.cheat` | Specific cheat package |
| `com.saitesoft.gamecheater` | GameCheater app |
| `com.xiongmaoxia.gameassistant` | XiongMaoXia game assistant |

### H5GG variants (memory editor)

| String | Detection |
|---|---|
| `/usr/lib/TweakInject/H5GG.dylib` | H5GG dylib (TweakInject) |
| `/Library/MobileSubstrate/DynamicLibraries/H5GG.dylib` | H5GG dylib (Substrate) |
| `/usr/lib/TweakInject/libH5GG.A.dylib` | H5GG A variant |
| `/usr/lib/TweakInject/libH5GG.B.dylib` | H5GG B variant |
| `/usr/lib/TweakInject/libH5GGApp.dylib` | H5GG app variant |
| `/Applications/h5ggapp.app` | H5GG app bundle |
| `/var/jb/Applications/h5ggapp.app` | H5GG rootless variant |

### Game tools (Chinese market)

ACE has a HUGE list of Chinese game-cheating apps and tools:

| Package | Detection |
|---|---|
| `com.huluxia.gametools` | HuLuXia GameTools |
| `com.flamingo.xxrgplugin` | Flamingo XXRG |
| `com.bdkj.LightningGameRental` | Lightning Game Rental |
| `cn.com.opda.gamemaster` | OPDA GameMaster |
| `com.muzhiwan.gamehelper` | MuZhiWan GameHelper |
| `com.www.gamespeeder` | GameSpeeder |
| `com.paojiao.youxia` | PaoJiao YouXia |
| `com.cyjh.gundam` | CYJH Gundam |
| `com.cyjh.mobileanjian` | MobileAnJian script tool |
| `com.jbbl.handjingling` | HandJingLing macro tool |
| `com.cyjh.gundam.service.ScriptService.p` | Script execution service |
| `com.kascend.chushou.lu` | Recording tool |
| `com.leifeng.gametools` | Leifeng game tools |
| `com.dimonvideo.luckypatcher` | LuckyPatcher |
| `com.keramidas.TitaniumBackup` | Titanium Backup |
| `com.dragon.android.pandaspace` | PandaSpace |
| `com.mf.guagua.ttfwks` | GuaGua TTFWKS |

### ROOT tools

| String | Detection |
|---|---|
| `is_root` / `gp3_no_root` / `gp4_no_root` | Strategy names |
| `unlock_root` / `mem_trap_no_root` | Active strategies |
| `root_strategy` | Master root scan |
| `root_process_exists` | Found a root process |
| `com.speedsoftware.rootexplorer` | Root Explorer app |

## Tier 3: Virtual Environment / Sandbox

### Android virtualization apps

These are apps that run other Android apps in a sandbox:

| Package | Provider |
|---|---|
| `com.lody.virtual.client.stub.StubActivity` | VirtualXposed (LBE Parallel base) |
| `com.lody.virtual.client.stub.ShadowActivity` | VirtualXposed shadow |
| `com.google.virtual.client.stub.ShadowActivity` | "Google" virtual stub |
| `com.lbe.parallel.ui.tour.SplashActivity` | LBE Parallel Space |
| `com.estrongs.vbox.main.splash.SplashActivity` | Estrongs VBox |
| `com.chaozhuo.gameassistant.SplashActivity` | ChaoZhuo Game Assistant |
| `com.yyhd.sandbox.c.proxy.ActivityProxy` | YYHD Sandbox |
| `com.polestar.clone.client.stub.StubActivity` | Polestar Clone |
| `com.depu.wxfs` | DePu WXFS |
| `com.excean.dualaid.b32` | Excean DualAid |
| `com.iplay.assistant` | iPlay Assistant |
| `info.red.virtual` | Red Virtual |
| `com.sellapk.goapp` | SellAPK GoApp |
| `com.kongge` | KongGe |
| `com.excelliance.dualaid` | DualAid |

ACE iterates these and checks if they're installed or if the current package matches them.

### Emulator detection

| Path | Detection |
|---|---|
| `/init.vbox86.rc` | VirtualBox-based emulators (Genymotion) |
| `/dev/socket/genyd` | Genymotion-specific socket |
| `init.android_x86.rc` | x86 Android emulators |
| `ueventd.android_x86.rc` | x86 ueventd |
| `/system/framework/x86` | x86 framework path |
| `/vendor/lib/libdrm.so.exagear` | Exagear (ARM-on-x86 translator) |
| `/system/lib/ld-android.so.exagear` | Exagear loader |
| `/system/priv-app/TGPAServer/TGPAServer.apk.exagear` | Exagear with TGPA |
| `pipe:qemud:sensors` | QEMU sensor pipe |
| `antiemulator` | Master emulator strategy |
| `is_x86` | x86 indicator (in payload) |
| `iscompatiblemode` | Compatibility mode flag |

## Tier 4: Debugger Detection

| String | Detection |
|---|---|
| `debugger` | "debugger" keyword |
| `debuggerd` | Android debug daemon |
| `tracer_cracked:%d:%s` | Format for "tracer cracked" report |
| `android/os/Debug` | Java debug class |
| `isDebuggerConnected` | Java debug query |
| `anti_debugger` | Master anti-debug strategy |
| `force_anti_debugger` | Force-on flag |
| `ro.debuggable` | System debuggable property |
| `android:debuggable` | App manifest debuggable flag |

## Tier 5: APK / Signature / Mod Detection

| String | Detection |
|---|---|
| `cc/binmt/signature/PmsHookApplication` | BinMT signature killer |
| `bin/mt/apksignaturekillerplus/HookApplication` | APK Signature Killer Plus |
| `com/cloudinject/feature/App` | CloudInject framework |
| `np/manager/FuckSign` | NP Manager (sig stripper) |
| `signatures` | Java getSignatures field |
| `[Landroid/content/pm/Signature;` | Java Signature class |
| `java/security/cert/CertificateFactory` | Cert factory class |
| `(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;` | Cert factory ctor sig |
| `generateCertificate` | Cert factory method |
| `(Ljava/io/InputStream;)Ljava/security/cert/Certificate;` | generateCertificate sig |
| `getModulus` | RSA modulus getter (cert hashing) |
| `isPatch` | Patch detection flag |

## Tier 6: Mono / Unity-specific

| String | Detection |
|---|---|
| `Assembly-CSharp` | Game's main C# assembly |
| `Assembly-CSharp-firstpass` | Unity firstpass assembly |
| `assets/bin/Data/Managed/Assembly-CSharp.dll` | Mono assembly path inside APK |
| `Assembly-CSharp.dll` | Assembly filename |

## Tier 7: ART/DEX VM Detection

ACE looks up specific Android Runtime symbols:

| Symbol | Variant |
|---|---|
| `_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_string...` | DexFile::OpenMemory (32-bit) |
| `_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_string...` | DexFile::OpenMemory (64-bit) |

These are mangled C++ symbols. ACE hooks them to monitor when DEX bytecode gets loaded — catches code injection attacks that load malicious classes.

## Tier 8: Streaming / Recording Apps (anti-cheat by stealth)

| Package | Type |
|---|---|
| `com.ss.android.ugc.aweme` | TikTok / Douyin |
| `com.ss.android.ugc.aweme.lite` | TikTok Lite |
| `com.ss.android.ugc.trill` | Trill |
| `com.bilibili.bilibililive` | Bilibili Live |
| `com.bilibili.studio` | Bilibili Studio |
| `com.duowan.live` | DuoWan Live |
| `com.duowan.kiwi` | Kiwi (Huya) |
| `com.duowan.mobile` | DuoWan Mobile |
| `com.yy.huyaassist4game` | YY HuYa Game Assistant |
| `com.kwai.livepartner` | Kwai Live Partner |
| `com.kuaishou.nebula` | Kuaishou Nebula |
| `com.tencent.weishi` | Tencent Weishi |
| `com.prism.live` | Prism Live |
| `com.scriptelf.oneclickplay` | ScriptELF OneClickPlay |

ACE detects when these are running so it can know the player is streaming/recording. Doesn't necessarily ban — just records the context.

## Tier 9: Tencent Internal / TGPA / TP

| String | Component |
|---|---|
| `com.tencent.tp.DisplayMgrListener` | Tencent TP display manager |
| `com.tencent.tp.ScreenRecordHelper` | TP screen recording helper |
| `/data/data/com.tencent.tgpa.server` | TGPA server data dir |
| `/system/priv-app/TGPAServer/TGPAServer.apk.exagear` | TGPA-on-Exagear |

These are Tencent's own internal modules ACE coordinates with.

## Tier 10: System Probe

| Path | Purpose |
|---|---|
| `/proc/self/root` | Symlink to root (catches container roots) |
| `/proc/self/root/%s` | Format for symlink probing |
| `/proc/self/root/proc/self/fd` | FD enumeration via symlink |
| `/proc/1/cgroup` | Cgroup info (init process) |
| `/system/bin/dex2oat` | DEX-to-OAT compiler binary |
| `dual_app_files` / `dual_app_uid` / `dual_uid_not_same` | Dual-app detection markers |

## Tier 11: Crash / Stability detection

| String | Purpose |
|---|---|
| `Not Killed` | Status string for non-killed processes |
| `use_new_kill` | Strategy flag |
| `tracer_cracked` | Detection result |
| `module_base=%u\|...` | Pipe-delimited module info report |
| `reason:%08x,module:%08x` | Detection reason format |

## How ACE uses these strings

1. **At decode time**: Each string is decrypted from the encrypted table only when needed (lazy decryption).
2. **At scan time**: Scanners walk `/proc/*/cmdline`, `/proc/*/maps`, loaded library names, etc., and `strstr()` against the decoded string.
3. **At report time**: Detection format strings are filled with offending values and submitted via the COREREPORT channel.

## Bypass implications

Three layers of defense:

1. **Don't have any of these tools/libraries loaded.** Use Dobby (which isn't on the list) instead of Frida/SandHook/HookZz.
2. **Patch the scanners (Tier 1 in our bypass).** Drop them at registration so they never run.
3. **Patch ACE_DecryptString (DON'T DO THIS — kill-on-failure-twice trap).** Better to leave the decoder alone.

The first two are sufficient for our use case. We use Dobby (not on ACE's blocklist), and we drop the scanners that would catch our trampolines.

## Strategic recommendation

Stay AWAY from these tools when modding Tencent games:
- ❌ Frida (any variant)
- ❌ HookZz / SandHook
- ❌ Substrate (iOS)
- ❌ TweakInject (iOS)
- ❌ Lucky Patcher
- ❌ Game Guardian (iOS)
- ❌ MT Manager / NP Manager / FuckSign / Cloud Inject

Use these instead:
- ✅ **Dobby** (not on the list)
- ✅ **Custom GOT/PLT hooks** (no trampoline pages to scan)
- ✅ **Inline assembly patches** (one-shot, no library footprint)
- ✅ **Memory mapping tricks** (rename VMA via prctl — ACE does this themselves!)

## To-do

- Decode the remaining ~3000 strings from the libanogs decryption table
- Cross-reference each string with the function that uses it (gives us scanner→target mapping)
- Find the kill triggers for each detection (some give warnings, some kill)
