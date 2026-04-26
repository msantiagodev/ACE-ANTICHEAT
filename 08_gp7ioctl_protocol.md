# GP7Service ⇄ libanort IPC Protocol — VERIFIED

## The Java→Native bridge

The `:GP7Service` Android service (separate process from main) calls the JNI native method **`gp7ioctl(String) -> void`** registered by libanort. This single string-based command channel is how Java-side ACE talks to native ACE.

**JNI registration** (libanort `init_array_0_268d0`, slot 5):
```c
{ name: "gp7ioctl", sig: "(Ljava/lang/String;)V", fn: JNI_ACE_CommandDispatch (0x25D94) }
```

## Command vocabulary (verified)

`JNI_ACE_CommandDispatch` parses the input String and dispatches:

| Command | Effect |
|---|---|
| `start_service` | Returns version info (likely populates a status field that the Java side reads back) |
| `start_worker` | Triggers `sscanf` for the format `"start_worker_%d"` to extract worker ID |
| `start_worker_<N>` | Starts worker thread N — calls `ace_config_handler_1` then `ace_config_handler_2(N)` |
| `stop` | **DANGEROUS** — if `ACE_ValidateConfig(cfg, "enable_gp7_exit_group", 1)` returns true, **calls `linux_eabi_syscall(__NR_exit_group, ...)` directly to kill the process** |

(There may be more commands — these are the verified ones. Re-decompile after more reverse work.)

## The "stop" kill path

Pseudocode of the kill path:
```c
if (strcmp(java_string, "stop") == 0) {
    cfg = ACE_CreateConfigObj(?);
    if (ACE_ValidateConfig(cfg, "enable_gp7_exit_group", 1) & 1) {
        // Direct syscall to exit_group — bypasses our libc.kill hook entirely
        linux_eabi_syscall(SYS_exit_group, NULL, ...);
    }
}
```

This is **NOT a libc PLT call**. It's a raw syscall instruction in the function body. Our existing libc-hook approach (via Dobby on `kill`/`exit`/`_exit`) **CANNOT catch this**. The path goes:
- Java GP7Service decides "kill the game"
- Java calls `gp7ioctl("stop")`
- Native `JNI_ACE_CommandDispatch` runs
- Validates config flag
- Issues `SVC #0` with `X8 = SYS_exit_group (94)` directly

## Bypass strategies

### Strategy A — Hook the JNI handler (cleanest)
```c
static void (*real_gp7ioctl)(JNIEnv*, jobject, jstring) = nullptr;

static void hooked_gp7ioctl(JNIEnv *env, jobject thiz, jstring cmd) {
    const char *str = env->GetStringUTFChars(cmd, nullptr);
    if (str && strcmp(str, "stop") == 0) {
        LOGI("blocked gp7ioctl(stop)");
        env->ReleaseStringUTFChars(cmd, str);
        return;
    }
    if (str) env->ReleaseStringUTFChars(cmd, str);
    return real_gp7ioctl(env, thiz, cmd);
}

// Install:
DobbyHook((void*)(libanort_base + 0x25D94), (void*)hooked_gp7ioctl, (void**)&real_gp7ioctl);
```

### Strategy B — Hook ACE_ValidateConfig

```c
static bool (*real_ACE_ValidateConfig)(void*, const char*, int) = nullptr;
static bool hooked_validate(void *cfg, const char *key, int val) {
    if (key && strcmp(key, "enable_gp7_exit_group") == 0) {
        return false;  // Always return "not enabled"
    }
    return real_ACE_ValidateConfig(cfg, key, val);
}

DobbyHook((void*)(libanort_base + 0x12A308), (void*)hooked_validate, (void**)&real_ACE_ValidateConfig);
```

### Strategy C — NOP the SVC instruction in JNI_ACE_CommandDispatch

Not recommended — the function has obfuscated control flow and the SVC site at 0x25F2C is one of many.

---

## What the Java side actually sends

To know WHEN GP7Service sends `"stop"`, we'd need to reverse the Java GP7Service code. From the JADX decompile of `ace_decrypted_strings.txt`:
- `gp7ioctl` is the JNI method
- The Java caller is in `com.gamesafe.ano` package OR `com.tencent.tp` package (both have JavaMethod classes registered)

Java pseudocode (inferred):
```java
class TssJavaMethod {
    static native void gp7ioctl(String cmd);
}

// On service start:
TssJavaMethod.gp7ioctl("start_service");
// Periodically:
TssJavaMethod.gp7ioctl("start_worker_3");
// On detection of cheat or anomaly:
TssJavaMethod.gp7ioctl("stop");
```

The "anomaly" detection in Java side likely correlates with our hooks. **The Java code in GP7Service is what's sending `"stop"` after detecting our hook activity.**

---

## ACE_ConfigUpdateFromServer details

Decompile shows:
- Guard: `dword_171118 & 0x100` OR `*(_BYTE *)(a1 + 24) != 0`
- Call: `ACE_SignedDataVerify(a1)` — verifies signed payload
- On failure: walks JNI to read `android.os.Build.VERSION.SDK` (Android API level)
- Then `ACE_ReportPacketBuilder(a1)` — sends report

**Bypass:** patch `dword_171118 |= 0x100` to disable config update. ACE then runs with whatever config is baked-in.

```c
*(uint32_t *)(libanort_base + 0x171118) |= 0x100;
```

---

## Summary

There are **at least three kill paths** in ACE:
1. **libanogs scanner-detect** → `ace_create_tdm_report` → `ace_custom_syscall_handler` → kill (the documented path)
2. **libanort string-decode integrity fail twice** → `linux_eabi_syscall(exit_group, &byte_7)` (raw syscall trap)
3. **libanort `gp7ioctl("stop")` from Java** → `linux_eabi_syscall(exit_group, NULL)` (raw syscall via Java command)

**To fully neutralize ACE's kill chain, we need to defeat ALL THREE:**
- Path 1: Tier 1 + Tier 2 from removal_emulation_blueprint
- Path 2: don't tamper with the encrypted string table; hook `ACE_DecryptString` if needed
- Path 3: hook `JNI_ACE_CommandDispatch` to drop "stop" commands OR hook `ACE_ValidateConfig`

This is why the previous bypass attempts kept dying — we addressed path 1 but not paths 2/3.
