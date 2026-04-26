# Virtual App Detection — 21 Signature Patterns

ACE actively scans for **21 distinct virtual-app frameworks** that allow Android apps to run other apps in sandboxed environments. These are very popular for cheating because they let users run multiple instances or run on rooted devices.

Each signature is a `(package_name, stub_activity_class)` pair, encoded in ACE's encrypted string table. Strings 21435..23000 in libanogs.so contain the entire registry.

## The 21 detected virtual-app frameworks

| # | Package name | Stub class | Friendly name |
|---|---|---|---|
| 1 | `com.bly.dkplat` | `com.bly.chaos.plugin.stub.StubActivity` | **DKPlat** (Chaos VM) |
| 2 | `com.depu.wxfs` | `com.lody.virtual.client.stub.StubActivity` | **WeChat Helper** (Lody VirtualApp) |
| 3 | `com.excean.dualaid.b32` | `com.f0qyh0j.ilz3em3z4jv4k.id7fa8.qypbb3.hkm7ssg88` | **DualAid B32** (obfuscated) |
| 4 | `com.excean.maid` | `com.hi0bd.etidz36.jcst5td.ztb0b4.qkirs` | **Excean Maid** (obfuscated) |
| 5 | `com.excean.masaid` | `com.mz4kd3.abm0cl.e9qvfud.q4u1rd.idluw` | **Excean Masaid** (obfuscated) |
| 6 | `com.iplay.assistant` | `com.yyhd.sandbox.c.proxy.ActivityProxy` | **iPlay Assistant** (yyhd sandbox) |
| 7 | `info.red.virtual` | `com.google.virtual.client.stub.ShadowActivity` | **Red Virtual** (lookalike pkg) |
| 8 | `com.qihoo.magicmutiple` | `com.morgoo.droidplugin.stub.ActivityProxy` | **360 Magic Multiple** |
| 9 | `com.qihoo.magic` | `com.morgoo.droidplugin.stub.ActivityProxy` | **360 Magic** |
| 10 | `com.lbe.parallel.intl` | `com.lbe.doubleagent.client.proxy.ActivityProxy` | **Parallel Space** (LBE) |
| 11 | `com.svm.proteinbox_multi` | `com.svm.mutiple.client.proxy.ActivityProxy` | **Protein Box Multi** |
| 12 | `com.sellapk.goapp` | `com.lody.virtual.client.stub.ShadowActivity` | **GoApp** (Lody VirtualApp) |
| 13 | `com.app.hider.master.pro.cn` | `com.prism.gaia.client.stub.GuestActivityStub` | **App Hider Master** (Prism Gaia) |
| 14 | `com.bfire.da.nui` | `com.excelliance.kxqp.platform.proxy.gameplugin.ActivityProxy` | **Excelliance KXQP** game platform |
| 15 | `com.xunrui.duokai_box` | `com.docker.app.component.NormalActivity` | **Xunrui Duokai Box** |
| 16 | `com.chaozhuo.gameassistant` | `com.chaozhuo.superme.client.sb.SupermeSbActivity` | **ChaoZhuo Game Assistant** (Superme) |
| 17 | `com.kongge` | `com.polestar.clone.client.stub.StubActivity` | **KongGe** (Polestar Clone) |
| 18 | `com.joke.chongya` | `cn.ly.shahe.stub.PitActivity` | **Joke Chongya** (LY Shahe) |
| 19 | `com.vmos.app` | `android.os.VmosForkAppManager` | **VMOS** |
| 20 | `com.vmos.pro` | `com.vmos.server.VmosManager` | **VMOS Pro** |
| 21 | `com.weifx.wfx` | `com.z2lt7.iir3smvyjak.q8qjf6y.eiywe.bhngl` | **WFX** (heavily obfuscated) |

## Underlying engines

These 21 signatures break down to ~7 distinct underlying VM engines (most apps just rebrand them):

| Engine | Used by |
|---|---|
| **Lody VirtualApp** | DKPlat, WeChat Helper, GoApp, GameAssistant clones |
| **DroidPlugin (Morgoo)** | 360 Magic, 360 Magic Multiple |
| **DoubleAgent (LBE)** | Parallel Space, similar |
| **Prism Gaia** | App Hider Master, others |
| **DroidPlugin** (Excelliance variant) | KXQP game platform |
| **VMOS** | VMOS, VMOS Pro |
| **VirtualXposed-style** | Several heavily-obfuscated clones |

## How ACE detects each

The detection is in `ACE_VirtualEnvDetector` (libanort+0xAB9A4) and related scanners. The general algorithm:

```c
for each signature in g_virtapp_table:
    if (strcmp(host_package, signature.pkg) == 0) {
        // We're running INSIDE this virtual app
        report_detection(VIRT_APP_DETECTED, signature.pkg);
    }
    // Check if any installed app matches
    if (package_manager_query(signature.pkg) != null) {
        report_detection(VIRT_APP_INSTALLED, signature.pkg);
    }
}
```

Some apps detect "running inside" via `cls_name` matching the activity stack (the running app's main activity matches the proxy class).

## Bypass implications

If the user is running on a real device or a clean emulator (MuMu Player without virtual-app installed), **none of these fire**. We're safe.

If the user runs the game via a virtual-app:
- ACE detects → reports → potentially bans
- Mitigations: hook `getPackageName()` to lie, or hook ACE's package iteration

For our deployed bypass on MuMu, **no virtual app is in use** so this detection doesn't fire. Skip mitigation.

## Note on obfuscated class names

Several apps (Excean DualAid, Excean Maid/Masaid, WFX) use heavily-obfuscated class names like `com.f0qyh0j.ilz3em3z4jv4k.id7fa8.qypbb3.hkm7ssg88`. These are likely auto-generated via a name-mangler to evade pattern matching. ACE has explicit signatures for them anyway.

## Lookalike package names

Note `info.red.virtual` masquerades as `com.google.virtual.client.stub.ShadowActivity` — pretending to be a legitimate Google package. ACE catches these too.

## To-do

- Decompile `ACE_VirtualEnvDetector` (libanort+0xAB9A4) to see the exact match logic
- Find the table of these 21 patterns in IDA — likely an array of (pkg_str_id, cls_str_id) tuples
- Cross-reference with libanogs detection orchestration
- Research which engines have SDK leaks (so attackers can identify the engine in compiled code)
