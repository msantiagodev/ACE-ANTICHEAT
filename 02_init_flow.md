# ACE libanogs.so Initialization Flow — VERIFIED

## Order of execution (dlopen-time)

When the dynamic linker maps `libanogs.so`, it runs these in order:

1. **`.init_array`** — 60 constructor function pointers at `0x531920`, executed top-to-bottom by the loader.
2. **`JNI_OnLoad(JavaVM*, void*)`** — called by `dlsym(libanogs, "JNI_OnLoad")` if the host process is a Dalvik/ART runtime. The game's APK manifest declares the library and `System.loadLibrary("anogs")` triggers this.

After this, the SDK is initialized **but inactive**. Only when the game later calls `AnoSDKInit(game_id)` does ACE actually start its scan threads.

## The 60 init_array constructors

Mapped:

| Idx | Address | Notes |
|---|---|---|
| 0 | `0x51F52C` | C++ runtime — global ctor (likely libc++ string globals) |
| 1 | `0x51FB60` | C++ runtime |
| 2 | `0x1E28F0` | **`ace_init_jni_method_table`** — populates `g_jni_native_methods` (11 entries) |
| 3 | `0x1E6F88` | TBD |
| 4 | `0x21F018` | TBD |
| 5 | `0x22DE40` | TBD |
| 6 | `0x23130C` | TBD |
| 7 | `0x33957C` | TBD |
| 8–59 | various | TBD — needs further analysis |

Each ctor is renamed `ace_init_ctor_NN` in the IDB. Most are 0-arg `void()` callbacks — used for setting up:
- Vtable initialization (function pointer arrays in `.data`)
- Singleton object construction
- Static lookup tables
- String pool registration

## JNI_OnLoad (`0x1E2444`) — verified flow

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    ace_jni_preinit();                                  // (a)
    ace_jni_store_vm(vm);                               // (b)

    if (!g_jni_already_registered) {                    // (c)
        JNIEnv *env = NULL;
        vm->GetEnv(&env, JNI_VERSION_1_6);              //  → 0x10004
        if (env) {
            // Class #1 — gcloud / TSS shell:
            jclass c1 = env->FindClass("com/tss/gamedemo/Game");
            if (c1) {
                env->RegisterNatives(c1, g_jni_class1_methods, 3);
                env->DeleteLocalRef(c1);
            }
            // Class #2 — ACE-internal "com/ace/gamesafe4/..." (built at runtime):
            jstring c2name = ace_build_jni_class_name();
            jclass c2 = env->FindClass(c2name);
            if (c2) {
                env->RegisterNatives(c2, g_jni_native_methods, 11);
                env->DeleteLocalRef(c2);
            }
        }
    }

    // (d) Chain to the previous JNI_OnLoad if one exists (gcloud SDK shell wrapping)
    if (g_orig_jni_onload_chained) {
        return ((jint(*)(JavaVM*, void*))(g_orig_jni_onload_chained + 112))(vm, reserved);
    }

    // (e) Late init
    ace_get_timestamp_leaf();
    const char *gcloud_id = ace_decrypt_xor1B(49827);            // "gcloud"
    if (ace_validate_and_dispatch(t, gcloud_id, 1, 1) & 1) {
        // VM stash chain
        sub_2DD084 → sub_2DD0F0 → sub_2DD2EC
    }

    ace_vtable_dispatch(ace_get_global_singleton());

    return JNI_VERSION_1_6;  // 0x10004
}
```

### What we verified
- `(c)` is gated on `g_jni_already_registered` — JNI is registered exactly once even if `JNI_OnLoad` runs twice (e.g. the library is loaded again by another process).
- ACE chains the original `JNI_OnLoad` from `g_orig_jni_onload_chained + 112` — this is how ACE wraps the host SDK (gcloud) without losing it.
- The gcloud identifier "gcloud" is decrypted via `ace_decrypt_xor1B(49827)` and dispatched through `ace_validate_and_dispatch` — likely registering the ACE module under the gcloud SDK's plugin system.

## Two JNI native-method tables (Java → native bridge)

### Class #1: `com/tss/gamedemo/Game`  (`g_jni_class1_methods` at 0x537350, 3 entries)

| Slot | Java name | Signature | Native handler |
|---|---|---|---|
| 1 | `init` | `()I` | `ace_jni_class1_method1` (`0x1E04E4`) |
| 2 | `onPause` | `()I` | `ace_jni_class1_method2` (`0x1E07E0`) |
| 3 | `onResume` | `()I` | `ace_jni_class1_method3` (`0x1E0B48`) |

The `com/tss/gamedemo/Game` class name strongly suggests this binary is built from a Tencent test/demo project — the test class name was left in production. The 3 lifecycle methods are the gcloud SDK's standard hooks.

### Class #2: `com/ace/gamesafe4/...` (`g_jni_native_methods` at 0x5792E8, 11 entries)

| Slot | Java name | Signature | Native handler |
|---|---|---|---|
| 1 | `init` | (built at runtime) | `ace_jni_init` |
| 2 | `setuserinfo` | (built at runtime) | `ace_jni_setuserinfo` |
| 3 | `setuserinfoex` | (built at runtime) | `ace_jni_setuserinfoex` |
| 4 | `setgamestatus` | (built at runtime) | `ace_jni_setgamestatus` |
| 5 | `getsdkantidata` | (built at runtime) | `ace_jni_getsdkantidata` |
| 6 | `setsenddatatosvrcb` | `(Ljava/lang/Object;)V` | `ace_jni_setsenddatatosvrcb` |
| 7 | `senddatatosdk` | `([BI)V` | `ace_jni_senddatatosdk` |
| 8 | `senddatatosvr` | `([BI)V` | `ace_jni_senddatatosvr` |
| 9 | `onruntimeinfo` | `([BI)V` | `ace_jni_onruntimeinfo` |
| 10 | `hasMatchRate` | `(I)I` | `ace_jni_hasMatchRate` |
| 11 | `setappobject` | `(ILjava/lang/Object;)I` | `ace_jni_setappobject` |

These are the **only entry points the game's Java code can invoke ACE through**. To stub the entire SDK from Java's perspective, replacing the 11 handlers with no-op JNI methods is sufficient.

## Critical globals discovered

| Symbol (renamed) | Address | Purpose |
|---|---|---|
| `g_jni_native_methods` | `0x5792E8` | The 11-entry JNINativeMethod table for class #2 |
| `g_jni_class1_methods` | `0x537350` | The 3-entry JNINativeMethod table for class #1 |
| `g_orig_jni_onload_chained` | `0x5792D8` | Pointer to chained host JNI_OnLoad (gcloud) |
| `g_jni_preinit_flag` | `0x57E0C0` | Set after `ace_jni_preinit` first call |
| `g_jni_already_registered` | `0x537038` | Guard so RegisterNatives runs once |
| `g_string_integrity_failed` | `0x58D290` | Set when string decryptor integrity fails |

## Bypass implications

To **completely neuter the SDK from Java's perspective**:
1. Replace all 11 functions in `g_jni_native_methods` and all 3 in `g_jni_class1_methods` with no-op stubs that return success.
2. Or, hook `RegisterNatives` and supply our own table.
3. Or, even simpler: hook `JNI_OnLoad` itself to return immediately without calling RegisterNatives.

To **emulate** the SDK:
- Build a stub libanogs.so that exports the 21 AnoSDK functions and 14 JNI methods listed above. Each can return success/empty without doing anything. The game's gcloud SDK sees "ACE present, no detections."
