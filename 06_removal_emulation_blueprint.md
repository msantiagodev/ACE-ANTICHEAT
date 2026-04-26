# ACE Removal / Emulation Blueprint

This document distills the previous five docs into actionable strategies. Three tiers, ordered from least invasive (production-safe) to most invasive (emulation).

---

## Tier 1 — Surgical scanner-disable (recommended)

**Goal:** keep ACE present and apparently "working" from the game's perspective, but with all detection scanners silently neutered.

**Hook:** `ace_register_scanner_module` (`0x22D428`).

**Implementation:**
```c
static const char *kBlockedScanners[] = {
    "various_opcode",   // detects our Dobby trampolines (.text byte hash)
    "frida_scan",       // not currently a problem but block proactively
    "elf_hook_scan",    // already disabled in this build but block to be safe
    "module2",          // hashes our libinstantreload.so — would flag
    "anti_root",        // root detection (unrelated to our use, but harmless to block)
    "process",          // process scanner — could flag the mod menu overlay
    "cert3",            // re-signed APK has wrong certificate — would flag
    "anoscan",          // generic catch-all scanner
    "shell_checker",    // exploit checker
    "FakeToken",        // fake token detection
    "anti_clicker2",    // auto-tap detection (unused but block)
    "live",             // live-broadcast detection (unused for this use)
    "trusted_scanner",  // verifies trusted build
    "auto_defence3",    // generic defense bundle
};

static int (*real_register)(void *r, void *prev, const char *name, int en, int f2);

static __int64 my_register_scanner_module(void *r, void *prev, const char *name, int en, int f2) {
    for (auto *b : kBlockedScanners) {
        if (name && strcmp(name, b) == 0) {
            // Skip — return prev as the chain pointer so subsequent calls still link.
            return (__int64)prev;
        }
    }
    return real_register(r, prev, name, en, f2);
}

// Install with Dobby:
DobbyHook((void*)(libanogs_base + 0x22D428), (void*)my_register_scanner_module, (void**)&real_register);
```

**Trade-offs:**
- ✅ Tiny patch surface (one hook).
- ✅ Game's AnoSDK calls all return success (TDM reports keep flowing — server doesn't suspect).
- ✅ No detection results means no kill chain runs.
- ✅ No syscall hooks needed for ACE — we hook ACE *before* it sets up its own hooks.
- ⚠️ Must install BEFORE `ace_register_all_scanner_modules` runs. That function is called from a vtable entry inside one of the early init_array constructors (`ace_init_ctor_03..16`). Our hook must run during `JNI_OnLoad` time, which is BEFORE the init_array (init_array runs during dlopen, before JNI_OnLoad).
- ⚠️ Order: we need libanogs.so to be loaded but not yet have its init_array fully run. Tricky — the init_array runs SYNCHRONOUSLY during dlopen.

**Solution:** hook `dlopen` to detect `libanogs.so` being loaded, intercept BEFORE the linker calls init_array, install our hook, then let init_array run. This requires our library to be loaded BEFORE libanogs.so — which is fine since we get loaded first (we're loaded by the App's Activity onCreate, libanogs is loaded later by the gcloud SDK which calls System.loadLibrary("anogs")).

Better: do nothing fancy, hook `dlopen` to look for "libanogs.so" filename, and as soon as `dlopen` returns the handle, walk libanogs's symbols and patch its `ace_register_scanner_module`. The patch happens BEFORE the calling code can run init.

---

## Tier 2 — Full TDM kill switch (defense in depth)

Combine with Tier 1. Stop ALL telemetry from leaving the device.

**Patch:** Set `g_tdm_report_checked` (`byte_57E31D` at `libanogs_base + 0x57E31D`) to 1 and `g_tdm_report_enabled` (`byte_57E31C` at `libanogs_base + 0x57E31C`) to 0.

The first thing `ace_create_tdm_report` checks:
```c
if ((g_tdm_report_checked & 1) != 0) {
    if (!g_tdm_report_enabled)
        return 0;  // silently drop the report
}
```

With `(1, 0)`: every report is dropped. ACE's network code never fires. The server never gets notified that a device exists, much less a detection result. **Even if some scanner SLIPS THROUGH our Tier-1 hook**, the result becomes a no-op.

```c
*(uint8_t *)(libanogs_base + 0x57E31C) = 0;  // disabled
*(uint8_t *)(libanogs_base + 0x57E31D) = 1;  // already-checked
```

---

## Tier 3 — Full SDK emulation

Replace libanogs.so entirely with our own stub library. Provides all 21 AnoSDK exports plus the 14 JNI native methods. Each returns a "no detections" result.

**Stub layout:**

```c
// Exports
extern "C" int   AnoSDKInit(int game_id) { return 0; }
extern "C" int   AnoSDKInitEx(int game_id, void *cfg) { return 0; }
extern "C" int   AnoSDKSetUserInfo(...) { return 0; }
extern "C" int   AnoSDKSetUserInfoWithLicense(...) { return 0; }
extern "C" int   AnoSDKOnPause() { return 0; }
extern "C" int   AnoSDKOnResume() { return 0; }
extern "C" int   AnoSDKGetReportData(int *outLen, void **outData) {
    *outLen = 0; *outData = nullptr; return 0;
}
extern "C" int   AnoSDKGetReportData2/3/4(...) { return 0; }
extern "C" void  AnoSDKDelReportData/3/4(...) { /* free if allocated */ }
extern "C" int   AnoSDKOnRecvData(int len, const void *data) { return 0; }
extern "C" int   AnoSDKOnRecvSignature(...) { return 0; }
extern "C" int   AnoSDKIoctlOld(int cmd, ...) { return 0; }
extern "C" int   AnoSDKIoctl(int cmd, ...) { return 0; }
extern "C" void  AnoSDKFree(void *ptr) { free(ptr); }
extern "C" int   AnoSDKRegistInfoListener(...) { return 0; }
extern "C" int   AnoSDKForExport() { return 0; }

// JNI_OnLoad: register the 14 Java-callable methods as no-ops
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    
    // Class 1 (com/tss/gamedemo/Game)
    static const JNINativeMethod c1[] = {
        {"init",     "()I", (void*)+[]() -> jint { return 0; }},
        {"onPause",  "()I", (void*)+[]() -> jint { return 0; }},
        {"onResume", "()I", (void*)+[]() -> jint { return 0; }},
    };
    jclass cls1 = env->FindClass("com/tss/gamedemo/Game");
    if (cls1) env->RegisterNatives(cls1, c1, 3);
    
    // Class 2 (com/ace/gamesafe4/...)
    static const JNINativeMethod c2[] = {
        {"init",                  "(<runtime-built>)I", (void*)+[]() -> jint { return 0; }},
        {"setuserinfo",           "(...)I",  (void*)+[]() -> jint { return 0; }},
        {"setuserinfoex",         "(...)I",  (void*)+[]() -> jint { return 0; }},
        {"setgamestatus",         "(...)I",  (void*)+[]() -> jint { return 0; }},
        {"getsdkantidata",        "(...)I",  (void*)+[]() -> jint { return 0; }},
        {"setsenddatatosvrcb",    "(Ljava/lang/Object;)V", (void*)+[]() -> void {}},
        {"senddatatosdk",         "([BI)V",  (void*)+[](...) -> void {}},
        {"senddatatosvr",         "([BI)V",  (void*)+[](...) -> void {}},
        {"onruntimeinfo",         "([BI)V",  (void*)+[](...) -> void {}},
        {"hasMatchRate",          "(I)I",    (void*)+[](...) -> jint { return 0; }},
        {"setappobject",          "(ILjava/lang/Object;)I", (void*)+[](...) -> jint { return 0; }},
    };
    // The class name "com/ace/gamesafe4/..." — must build at runtime.
    // For now: use FindClass with the actual name we observe in the game's APK.
    // Override later.
    
    return JNI_VERSION_1_6;
}
```

**Distribution:** ship our stub libanogs.so in the APK at `lib/arm64-v8a/libanogs.so` so the linker loads OURS instead of Tencent's. Strip the original from the APK during integration.

**Trade-offs:**
- ✅ Smallest binary. ACE entirely absent. Zero runtime overhead.
- ✅ No bypass needed — there's no detection to bypass.
- ❌ The game's gcloud SDK might verify libanogs.so signature/hash. If so, we need to also patch the gcloud SDK to skip verification.
- ❌ The game may refuse to start without "real" ACE (server might require an attestation token).

---

## What we don't yet know

1. **Server attestation flow.** Does the game upload an ACE-generated token at login? If so, `AnoSDKGetReportData` returning empty might cause server-side login rejection.
2. **gcloud SDK verification.** What does the game's gcloud shell do at startup beyond loading libanogs? Does it validate the lib? (Answer in `libgcloud.so` — separate analysis pass.)
3. **The actual `IsEnable2` implementation.** It's registered in the lookup but returns NULL there. Where's the real one? Likely in the ace_log_dispatch or set up by an init_ctor.
4. **The decoder dispatch table at `0x57E4A4`.** Read 800 bytes (100 × 8-byte ptrs); confirm each maps to its decoder ordinal.
5. **The vtable layouts** for each scanner module class (cert3 at `off_52ADE8`, frida_scan at `off_52AC28`, etc.). This tells us which vtable slot is `scan()`.
6. **libanort.so structure.** The "runtime" library has its own scanners and is currently the only one we patch.
7. **Network protocol details.** What does the COREREPORT channel emit on the wire? Plain bytes? JSON? Tencent's protobuf?

---

## Recommended next step (Tier 1 implementation)

**File:** `Android-Mod-Menu/app/src/main/jni/Main.cpp`

Add an early hook in `hack_thread`:

```cpp
// Add after libanort.so patches, before any other ACE-related code

static int (*g_real_register_scanner)(void *r, void *prev, const char *name, int en, int f2) = nullptr;

static __int64 my_register_scanner_module(void *r, void *prev, const char *name, int en, int f2) {
    if (name && (
        strcmp(name, "various_opcode") == 0 ||
        strcmp(name, "module2") == 0 ||
        strcmp(name, "cert3") == 0 ||
        strcmp(name, "anti_root") == 0 ||
        strcmp(name, "process") == 0 ||
        strcmp(name, "anoscan") == 0 ||
        strcmp(name, "FakeToken") == 0 ||
        strcmp(name, "shell_checker") == 0 ||
        strcmp(name, "auto_defence3") == 0
    )) {
        LOGI("ace_register: BLOCKED scanner '%s'", name);
        return (__int64)prev;
    }
    LOGI("ace_register: allowing '%s' (en=%d)", name, en);
    return g_real_register_scanner(r, prev, name, en, f2);
}

static void install_ace_scanner_block() {
    uintptr_t base = getLibraryAddress(OBFUSCATE("libanogs.so"));
    if (!base) {
        LOGW("libanogs.so not loaded yet — defer");
        return;
    }
    void *target = (void *)(base + 0x22D428);  // ace_register_scanner_module
    if (DobbyHook(target, (void *)my_register_scanner_module,
                  (void **)&g_real_register_scanner) == 0) {
        LOGI("Hooked ace_register_scanner_module @ %p", target);
    } else {
        LOGE("Failed to hook ace_register_scanner_module");
    }
    
    // Also: zero out telemetry kill switch (Tier 2)
    uint8_t *tdm_enabled = (uint8_t *)(base + 0x57E31C);
    uint8_t *tdm_checked = (uint8_t *)(base + 0x57E31D);
    DobbyCodePatch(tdm_enabled, (uint8_t[]){0}, 1);
    DobbyCodePatch(tdm_checked, (uint8_t[]){1}, 1);
    LOGI("TDM telemetry kill switch armed");
}
```

**Timing:** call `install_ace_scanner_block()` from `hack_thread` AFTER detecting libanogs.so is loaded but BEFORE its init_array fully runs. Since init_array runs synchronously during dlopen of libanogs.so, the safest pattern is to hook `dlopen` and intercept the moment libanogs.so is requested.

The current Main.cpp already detects `libanogs.so` via `getLibraryAddress`. The waiting loop checks every X seconds. **We need to install this hook the very first instant libanogs is in memory.** Currently we wait too long.
