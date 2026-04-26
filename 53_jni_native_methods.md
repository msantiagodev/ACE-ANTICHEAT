# 6 JNI Native Methods — The Java→Native Entry Surface

Every interaction between the game's Java code and ACE's native libanort.so happens through one of **6 JNI native methods**. These are populated at .so load time by `init_array_0_268d0` (libanort+0x268D0), which uses `ACE_DecryptString` to resolve method names/signatures at runtime so static analysis can't read them.

The method names are decrypted lazily — string indices `0, 13, 110, 211, 120, 102, 192, 200, 160, 237, 235, 1220, 139, 248, 158, 1222, 169, 123, 238, 147` are used by the init function.

## The 6 native methods

| # | Function | Address | What Java calls it for |
|---|---|---|---|
| 0 | `JNI_ACE_Initialize` | libanort+0x259D0 | The bootstrap call — wires up ACE state and invokes `ace_init_core_v4_9_30_24277_oversea` |
| 1 | `JNI_ACE_ProcessCommand` | libanort+0x1362A0 | Generic command dispatcher, type-based (23=query, 24/25=exec). Uses `ACE_ResolveDynFunc` |
| 2 | `JNI_ACE_GetByteArray` | libanort+0x136054 | Copies a Java byte[] from JNI to native heap (signatures, configs) |
| 3 | `JNI_ACE_QueryData` | libanort+0x136574 | Returns Java a 0x50-byte struct of native data |
| 4 | `JNI_ACE_FileOperation` | libanort+0x136AD8 | File access checks (parses pipe-delimited input). Cmd 0=access(), 1/2=state-set |
| 5 | `JNI_ACE_CommandDispatch` | libanort+0x25D94 | **Most dangerous** — string-keyed dispatch with `exit_group` kill-switch |

## JNI_ACE_Initialize (0x259D0) — boot entry

```c
int JNI_ACE_Initialize(JNIEnv*, jobject, jlong, jlong, jlong, jlong, jlong) {
    ACE_HashCompute();      // touches detection state
    return ace_init_core_v4_9_30_24277_oversea(...) ? -1 : 0;
}
```

Returns 0 on success, -1 on failure. CFG-flattened for obfuscation.

## JNI_ACE_ProcessCommand (0x1362A0) — type-keyed dispatcher

```c
jint JNI_ACE_ProcessCommand(JNIEnv*, jobject, jstring, jint, jint type) {
    String cmd = JNI_GetStringUTF(jstr);
    switch (type) {
        case 23:  // QUERY
            fn = ACE_ResolveDynFunc("decrypt(9642)", {"decrypt(9890)", "decrypt(10026)"});
            result = fn(cmd, ..., 0, ACE_GetSessionContext());
            return jni_NewByteArray copy of result;
        case 24:  // EXEC
        case 25:
            fn = ACE_ResolveDynFunc("decrypt(9642)", {"decrypt(9654)", "decrypt(9772)"});
            return fn(cmd, ..., 1, ACE_GetSessionContext());
    }
}
```

The decrypted strings (9642, 9654, 9772, 9890, 10026) are the **encrypted function names** that ACE resolves at runtime. We don't have these decrypted yet but they're queryable by running `ace_decrypt_string` on those indices.

## JNI_ACE_GetByteArray (0x136054)

Standard JNI byte[] copy:
1. `GetArrayLength` (vtable+1368)
2. `GetByteArrayElements` (vtable+1504)
3. `malloc(len)` + `memcpy` 
4. `ReleaseByteArrayElements` (vtable+1568)
5. Return native heap pointer

Used to receive bytes from Java for: signature blobs, config bytes, certificate data.

## JNI_ACE_QueryData (0x136574)

Like `JNI_ACE_ProcessCommand` (resolves a dyn-func with strings 9642, 10162, 10294, calls it), but allocates and returns a `0x50`-byte struct via `operator new[]`. The struct layout is:
- `[+0]` to `[+8]`  — single result pointer
- `[+16]..[+0x50]`  — additional fields

This appears to be the "rich query" path that returns structured results (vs `ProcessCommand` which returns raw bytes).

## JNI_ACE_FileOperation (0x136AD8) — file probe

```c
jint JNI_ACE_FileOperation(JNIEnv*, jobject, jint cmd, jstring input) {
    String s = jstring_to_native(input);
    parse_pipe_delimited(s, &v16);  // splits on '|'
    String path = v16[0];
    int arg = atoi(v16[2]);
    
    switch (cmd) {
        case 0:  // CHECK
            if (access(resolve_path(path), F_OK) != 0) return 1;
            return ACE_FileOp_ValidatePath(path, arg);
        case 1:  // SET_STATE_1
            ACE_FileOp_SetState(0x22049989, ..., arg);
            g_anort_fileop_state = 1;
            return 0;
        case 2:  // SET_STATE_2
            ACE_FileOp_SetState(0x22049989, ..., arg);
            g_anort_fileop_state = 2;
            return 0;
    }
    return -1;
}
```

The magic constant `570951689 = 0x22049989` is reused. `g_anort_fileop_state` is a 32-bit state global.

## JNI_ACE_CommandDispatch (0x25D94) — KILL PATH

This is the most dangerous JNI method because it can **directly terminate the host process**:

```c
jint JNI_ACE_CommandDispatch(JNIEnv*, jobject, jstring input) {
    String cmd = jstring_to_native(input);
    char buf[255];
    ACE_SpinlockAcquire(buf, cmd, 255);  // copy with spinlock-based memcpy
    
    if (strcmp(buf, decrypt(11935)) == 0)   // "version"?
        return ACE_FormatVersion(ACE_GetVersionInfo());
    
    if (strcmp_partial(buf, decrypt(11920)) == 0) {  // some prefix
        // matches → check second pattern
        if (strcmp(buf, decrypt(11969)) == 0) {     // "stop"?
            obj = ACE_CreateConfigObj();
            if (ACE_ValidateConfig(obj, decrypt(12015), 1)) {
                // CONFIG VALIDATION FAILED → KILL THE PROCESS
                syscall(__NR_exit_group, 0);
            }
        }
    } else {
        // Fallback: sscanf with format from decrypt(11951)
        int n;
        if (sscanf(buf, decrypt(11951), &n) >= 1)
            return ace_config_handler_2(ace_config_handler_1(...), n);
    }
}
```

**This is a confirmed kill path.** When the Java side sends a "stop"-command (string 11969) AND the config validation fails, ACE invokes `exit_group(0)` to terminate the entire host process group.

This is the **GP7Ioctl "stop" command** path documented in `08_gp7ioctl_protocol.md` — when the server tells ACE to shut down the game, it goes through this JNI method.

## Mitigation

In our bypass we already have:
- **Tier 5** (`g_anort_config_flags |= 0x100`) prevents `ACE_ConfigUpdateFromServer` from reading new config → server can't push fresh kill-criteria config
- The `ACE_ValidateConfig` call in `JNI_ACE_CommandDispatch` runs against locally-cached config, which our bypass corrupts

If we wanted **belt-and-suspenders**, we could hook `JNI_ACE_CommandDispatch` itself and refuse to forward any string that decrypts to "stop". This would be Tier 9 territory. Currently not deployed.

## ACE_ResolveDynFunc — the function-name resolver

`ACE_ResolveDynFunc(name, name_array)` (libanort+0x136650) is the runtime symbol resolver used by methods 1 and 3. Given an encrypted function name and an array of encrypted lib names, it does dlopen+dlsym to find the function pointer.

This is how ACE delays exposing its API surface: instead of importing functions directly (which would show in the GOT), it resolves them at runtime by encrypted name. We saw the same pattern in `ACE_DynamicSymbolResolver` (libanort+0x45CE8).

## qword_1A8268 — shared session global

Multiple JNI methods reference `qword_1A8268` as a session/handle pointer. This is the cached `ACE_GetSessionContext()` result, used to pass session state across calls without re-resolving.

## To-do

- Decrypt strings 9642, 9654, 9772, 9890, 10026, 10162, 10294, 11920, 11935, 11951, 11969, 12015 to know the actual command names
- Trace `ACE_ResolveDynFunc` to enumerate all dynamically-resolved native functions
- Check Java side (jadx) to confirm which Java classes invoke each native method
- Document the FULL list of input commands to JNI_ACE_CommandDispatch (currently only know "stop"-style)
