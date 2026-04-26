# The 7 JNI Native Methods — Java's Entry Points into ACE

## Overview

ACE registers 7 native methods that Java code calls to drive the SDK. Each is registered via the `JNINativeMethod[]` table built at init_array[0]. They are the ONLY way Java communicates with the native ACE layer.

## Method 0: `JNI_ACE_Initialize` (libanort+0x259D0)

**Java name:** `AnoSDKMethodInit` (or equivalents under TSS/AceSDK names)

**Java signature:** `(...)I` — returns int (0 = success, -1 = failure)

**What it does:**
```c
JNI_ACE_Initialize(env, obj, p1, p2, p3, p4, p5):
    hash_state = ACE_HashCompute()
    result = ace_init_core_v4_9_30_24277_oversea(hash_state, env, obj, p1, p2, p3, p4, p5)
    return (result == 0) ? 0 : -1
```

This is **THE wakeup call**. Until Java invokes this, ACE is dormant. After it runs, all detection scanners are armed.

**Bypass implication:** Hooking this to return 0 immediately would skip ALL of `ace_init_core` — but ACE state would be uninitialized, likely crashing other dependent code. Don't hook.

## Method 1: `JNI_ACE_ProcessCommand` (libanort+0x1362A0)

**Java signature:** `(Ljava/lang/String;II)?` — string + 2 ints

**What it does:** Executes a named command via dynamic function resolution. Three command modes:
- `cmd_id == 23`: query (decrypts strings 9890+10026 via ACE_DecryptString)
- `cmd_id == 24/25`: execute (decrypts strings 9654+9772)

Each mode resolves a function pointer via `ACE_ResolveDynFunc(decrypt(9642), &nameStruct)`, then calls it with the user's string + session context.

**Decoded strings:**
- `decrypt(9642)` = library to dlopen for resolution
- `decrypt(9654)` / `decrypt(9772)` = function names for "execute" mode
- `decrypt(9890)` / `decrypt(10026)` = function names for "query" mode

The query mode returns a byte-array via JNI's `NewByteArray`/`SetObjectArrayElement`.

## Method 2: `JNI_ACE_GetByteArray` (libanort+0x136054)

**Java signature:** `([BI)?`

**What it does:** Copies a Java byte array into a malloc'd native buffer.

```c
JNI_ACE_GetByteArray(env, obj, jbyteArray, length):
    elements = env->GetByteArrayElements(jbyteArray, &is_copy)
    src_data = elements + 8         // skip 8-byte header
    env->ReleaseByteArrayElements(jbyteArray, elements, JNI_ABORT=2)
    
    buf = malloc(length)
    memcpy(buf, src_data, length)
    return buf
```

Used to import binary data (signed configs, certificate bytes, etc.) from Java.

**Caveat:** The `+ 8` offset suggests the caller passes a wrapped struct, not raw bytes. The first 8 bytes are some header (probably length + flag).

## Method 3: `JNI_ACE_QueryData` (libanort+0x136574)

**Java signature:** `(Ljava/lang/String;I)[?`

**What it does:** Query data via dynamic function resolution. Allocates a 24-byte result struct that contains 3 pointers into a 0x50-byte data buffer.

```c
JNI_ACE_QueryData(env, obj, jstr, idx):
    name = env->GetStringUTF(jstr, NULL)
    fn = ACE_ResolveDynFunc(decrypt(9642), &(decrypt(10162), decrypt(10294)))
    result = fn(name, idx, session, ...)
    
    if (!result) return NULL
    
    obj = new[24]              // 24-byte wrapper
    data = new[0x50]           // 80 bytes
    *data = result             // store result at start
    obj[0] = data
    obj[1] = data + 8
    obj[2] = data + 80         // hmm, 80 = data + 80 which is past the buffer
    return obj
```

The 24-byte object has 3 fields pointing into the 80-byte data buffer (start, +8, end). Returns a structured query result.

## Method 4: `JNI_ACE_FileOperation` (libanort+0x136AD8)

**Java signature:** `(ILjava/lang/String;)I`

**What it does:** Performs file operations based on `cmd` (a3):

| cmd | Operation |
|---|---|
| 0 | Check file exists: `access(path, 0)`. Returns 1 if missing, else `ACE_FileOp_ValidatePath` result. |
| 1 | `ACE_FileOp_SetState(0x22070009, hash, val)`, sets `g_anort_fileop_state = 1` |
| 2 | `ACE_FileOp_SetState(0x22070008, hash, val)`, sets `g_anort_fileop_state = 2` |
| else | Returns -1 (unknown) |

The input string has format `path|number` — pipe-delimited. ACE parses it, extracts the path and atoi's the number.

**Used for:** validating game asset paths, setting integrity flags, recording file-state events.

## Method 5: `JNI_ACE_CommandDispatch` (libanort+0x25D94) ★ **CRITICAL**

**Java signature:** `(Ljava/lang/String;)?`

**What it does:** This is the **gp7ioctl** entry point and contains **KILL PATH 4**.

```c
JNI_ACE_CommandDispatch(env, obj, jstr):
    cmd = env->GetStringUTF(jstr, NULL)
    
    // Match against decrypted commands
    
    if (cmd == decrypt(11935)):           // "version" probably
        return ACE_FormatVersion(ACE_GetVersionInfo())
    
    if (cmd starts with decrypt(11920)):  // "config:" prefix
        sscanf(cmd, decrypt(11951), &cfg_id)
        if (cfg_id >= 1):
            return ace_config_handler_2(ace_config_handler_1(...), cfg_id)
    
    if (cmd == decrypt(11969)):           // "stop" — probably
        cfg = ACE_CreateConfigObj(...)
        if (ACE_ValidateConfig(cfg, decrypt(12015), 1)):
            // KILL PATH 4: direct exit_group syscall
            linux_eabi_syscall(__NR_exit_group, NULL)
            // PROCESS DIES HERE
```

The `decrypt(11969)` command, if combined with `decrypt(12015)` validating to true, fires a **direct `exit_group` syscall** that bypasses libc entirely. No way to intercept from userspace except by hooking THIS function.

**Tier 3 of our bypass** is exactly this: hook this function to drop the kill command.

## Method 6: `JNI_NativeMethod_6` (libanort+0x25F48)

**Java signature:** unknown (not commonly invoked)

**What it does:** CFG-flattened wrapper that:
1. Calls `ace_lazy_dlopen_wrapper`
2. Gets `ACE_GetSingleton_SigVerify`
3. Calls `ACE_X509ProcessExtension(verify_ctx, env, obj, jarg)`

This is a **certificate / X509 extension processor**. Used by the cert3 scanner to validate APK signing certs.

## JNI vtable offsets used (Android 7+)

These are the `JNIEnv*` vtable offsets used across all 7 methods:

| Offset | Function |
|---|---|
| 1352 | GetStringUTFChars |
| 1360 | ReleaseStringUTFChars |
| 1368 | GetArrayLength |
| 1440 | NewByteArray |
| 1504 | GetByteArrayElements / SetObjectArrayElement (overloaded) |
| 1568 | ReleaseByteArrayElements |
| 1824 | ExceptionCheck |

Knowing these helps when hooking JNI calls — you can intercept specific vtable slots to filter what ACE sees.

## Java side: AnoSDK class

The Java side that calls these methods is at `com.gamesafe.ano.AnoJavaMethod` (decoded from string ID 4758 in libanort). The class has stubs that bridge to:

```java
public class AnoJavaMethod {
    public static native int AnoSDKMethodInit(...);          // → JNI_ACE_Initialize
    public static native ? AnoSDKProcessCommand(String, int, int);  // → JNI_ACE_ProcessCommand
    public static native byte[] AnoSDKGetByteArray(byte[], int);     // → JNI_ACE_GetByteArray
    public static native ? AnoSDKQueryData(String, int);             // → JNI_ACE_QueryData
    public static native int AnoSDKFileOperation(int, String);       // → JNI_ACE_FileOperation
    public static native ? AnoSDKCommandDispatch(String);            // → JNI_ACE_CommandDispatch (KILL!)
    public static native ? AnoNativeMethod6(...);                    // → JNI_NativeMethod_6
}
```

The Java code calls `AnoSDKMethodInit` from a service thread, then drives lifecycle via OnPause/OnResume hooks that funnel through `AnoSDKProcessCommand` and `AnoSDKCommandDispatch`.

## Bypass implications

1. **Tier 3 already covers Method 5** (kill switch).
2. **Method 0 should NOT be hooked** — would break game's expectation that ACE is initialized.
3. **Methods 1-4, 6 are mostly safe** — they're query/setter style and we don't need to filter them.
4. **Defense-in-depth**: We could hook Method 5 to log ALL commands ACE receives, helping us discover undocumented commands the server sends.

## To-do

- Decode strings 11935, 11920, 11951, 11969, 12015 (currently best-guess "version", "config", "stop")
- Find Java callers via JADX (need `com.gamesafe.ano.AnoJavaMethod` class)
- Document `ace_config_handler_1/2` (called from Method 5 config branch)
- Map `ACE_X509ProcessExtension` (Method 6 main work)
