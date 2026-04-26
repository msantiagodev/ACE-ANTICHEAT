# libanort.so Boot Sequence — From dlopen to JNI_OnLoad

## Boot path (chronological)

When the Android runtime loads `libanort.so` via `dlopen`, this is the order things happen:

```
1. dlopen("libanort.so")
   └─> Linker maps the ELF segments
   └─> Linker resolves DT_NEEDED dependencies (libc, libdl, libm, etc.)
   └─> Linker invokes .init_array constructors IN ORDER
        ├─ init_array[0] = init_array_0_268d0 (libanort+0x268D0)
        │  └─ Builds JNINativeMethod[] table for JNI registration
        │  └─ Decrypts method names/signatures via ACE_DecryptString
        ├─ init_array[1] = init_array_1_3b7fc (libanort+0x3B7FC)
        │  └─ Sets up dynamic library state: obj/lpfunc/dlopen wrappers
        │  └─ Allocates 0x1000003B1 byte buffer at qword_1A4848
        │  └─ Allocates 0x400 byte buffer at qword_1A4850
        ├─ init_array[2] = ACE_InitDynamicLoader (libanort+0xE56CC)
        │  └─ Calls ACE_InitMutex(0x1A4A10)
        │  └─ Registers __cxa_atexit cleanup
        └─ init_array[3] = ACE_InitCryptoTables (libanort+0x1367D4)
           └─ Calls ACE_GetSessionContext, stores in qword_1A8268

2. JNI_OnLoad called by Android runtime
   └─> Returns 1.7 (Android JNI version)
   └─> RegisterNatives(env, class, &g_jni_methods, 7)
       Native methods registered:
       [0] JNI_ACE_Initialize          (0x259D0)
       [1] JNI_ACE_ProcessCommand      (0x1362A0)
       [2] JNI_ACE_GetByteArray        (0x136054)
       [3] JNI_ACE_QueryData           (0x136574)
       [4] JNI_ACE_FileOperation       (0x136AD8)
       [5] JNI_ACE_CommandDispatch     (0x25D94) ← gp7ioctl handler
       [6] JNI_NativeMethod_6          (0x25F48)

3. Java side calls AnoSDKMethodInit(...) [JNI_ACE_Initialize]
   └─> ace_init_core_v4_9_30_24277_oversea
       ├─ ACE_GetTime, ACE_DecryptString lazy-init
       ├─ ACE_GetSingleton_JNICache + ACE_ConfigUpdateFromServer
       │   (note: this just READS local config, doesn't fetch from server)
       ├─ ACE_GetSingleton_ConfigStore + ACE_LoadSignedConfig
       ├─ ACE_GetSingletonDword_1A4938 + sub_B8AF8
       ├─ ACE_ProcessCmdlineCheck
       │   (validates /proc/self/cmdline matches expected pattern)
       ├─ ACE_GetSingleton_SigVerify + ACE_SigVerifyLoadLibrary
       ├─ ACE_ShellDetector(detectionCtx, 1)
       ├─ sub_137C2C → sub_137CC0 (ACE_ZipExtractAndProcess)
       │   ├─ Reads ob_*.zip from local files
       │   ├─ Decrypts each module with S-box
       │   └─ ACE_VMModuleLoad + ACE_VMModuleListPrepend
       ├─ ACE_FormatVersion (returns "4.9.30.24277_oversea")
       └─ ACE_ConditionalTimingReporter
```

## The 4 init_array entries (verified)

### init_array[0]: `init_array_0_268d0` (libanort+0x268D0)

**Purpose:** Build the JNINativeMethod table for JNI registration. The table is at globals `g_jni_method_0..5_{name,sig,fn}` starting at `0x1A4748`.

The function is heavily CFG-flattened with state machine dispatch. It conditionally builds two slightly different versions of the method table based on a runtime check (the bytes look like opaque predicates that always select one branch).

**Decoded native methods:**
| Index | Java name | Signature | Native fn |
|---|---|---|---|
| 0 | (str id 0) | (str id 13) | JNI_ACE_Initialize |
| 1 | (str id 110) | (str id 211) | JNI_ACE_ProcessCommand |
| 2 | (str id 120/110) | (str id 102/169) | JNI_ACE_GetByteArray |
| 3 | (str id 192/123) | (str id 200/238) | JNI_ACE_QueryData |
| 4 | (str id 160/139) | (str id 237/248) | JNI_ACE_FileOperation |
| 5 | (str id 235/158) | (str id 1220/1222) | JNI_ACE_CommandDispatch |
| 6 | (str id 147) | (str id 1222) | JNI_NativeMethod_6 |

The dual values (e.g., 120/110 for method 2's name) reflect the two branches.

### init_array[1]: `init_array_1_3b7fc` (libanort+0x3B7FC)

**Purpose:** Set up the dynamic library state — buffers and pointers used by ACE's dlopen/dlsym wrappers.

Heavy CFG-flattened (3KB, 124 cyclomatic complexity). What it does:
- `qword_1A4848 = operator_new[](0x1000003B1)` — ~4GB allocation? NOT REALLY: this is a tagged pointer scheme. Actual size in low 32 bits = 0x000003B1 = 945 bytes. The high 32 bits (0x10000000) are flags.
- `qword_1A4850 = operator_new[](0x400)` — 1KB buffer
- `qword_1A4858 = qword_1A4848 + 1024` — endpoint pointer
- Registers cleanup via `__cxa_atexit(sub_39B80, &qword_1A4848, &off_162D10)`

These three pointers form a **scratch buffer + state pair** used by ACE's wrappers throughout runtime.

### init_array[2]: `ACE_InitDynamicLoader` (libanort+0xE56CC)

**Purpose:** Initialize the dlsym/dlopen mutex at `0x1A4A10`.

```c
ACE_InitMutex(&unk_1A4A10);       // pthread_mutex_init equivalent
__cxa_atexit(sub_11D380, &unk_1A4A10, &off_162D10);  // cleanup
```

Heavy CFG-flattened (73 cyclomatic complexity) but the functional core is just one mutex init and one atexit registration.

### init_array[3]: `ACE_InitCryptoTables` (libanort+0x1367D4)

**Purpose:** Allocate the cryptographic session context.

```c
qword_1A8268 = ACE_GetSessionContext(...);
```

`ACE_GetSessionContext` lazy-allocates a context struct on first call. This stores the AES/SHA state, nonces, etc. used by the report builder.

## fini_array (cleanup)

Two fini_array entries:
- `fini_array_0_25998` (libanort+0x25998): wraps `ACE_Nop()` — does nothing
- `fini_array_1_25980` (libanort+0x25980): calls `__cxa_finalize(&off_162D10)` — runs all registered atexit cleanup

## JNI_OnLoad

Standard JNI entry point. Returns 1.7 (Android JNI version constant), registers the 7 native methods built by init_array[0], and finishes.

## What's NOT in init_array

You might expect the ACE detection scanners and rule interpreter to start in init_array, but they DON'T. They're triggered by Java calling `AnoSDKMethodInit` (which dispatches to `JNI_ACE_Initialize` at libanort+0x259D0).

This means:
1. **Until Java calls AnoSDKMethodInit, no detection runs.** ACE is dormant.
2. **Detection lifecycle is Java-driven.** OnPause, OnResume, etc. all flow through JNI calls.
3. **If we delay or block AnoSDKMethodInit, ACE never wakes up.**

## ace_init_core entrypoint detailed

`ace_init_core_v4_9_30_24277_oversea` (libanort+0xC3A6C) is what Java calls. It does all the heavy lifting:

1. `ACE_GetTime(NULL)` → records boot timestamp at `ctx + 184`
2. `ACE_DecryptString(12303)` → fetches some lock name; `ACE_ConditionalLockAcquire`
3. `ACE_GetSingleton_JNICache()` + `ACE_ConfigUpdateFromServer()` → reads local config
4. `ACE_GetSingleton_ConfigStore()` + `ACE_LoadSignedConfig()` → loads signed config blob
5. `loc_E2B1C(signedConfig)` → processes the loaded config
6. `ACE_GetSingletonDword_1A4938()` + `sub_B8AF8()` → some module setup
7. `ACE_ProcessCmdlineCheck(ctx)` → validates process is the right one
8. `ACE_GetSingleton_SigVerify()` → APK signature verifier
9. `ACE_SigVerifyLoadLibrary(libpath)` → load+verify ACE's own libs
10. `ACE_GetDetectionContext()` + `ACE_ShellDetector(detCtx, 1)` → run shell detector
11. Triple call: `sub_137C2C → sub_137CC0 → sub_137E60`
   - `sub_137CC0` = `ACE_ZipExtractAndProcess` — extracts ob_*.zip and loads modules
12. `ACE_FormatVersion(...)` → format version string for reports
13. `ACE_ConditionalTimingReporter(...)` → record timing for thread_cracked check

State flag `dword_17115C` controls which path to take: if set to 1, takes a different init path that may skip some steps.

## Bypass implications

If we hook **`ace_init_core_v4_9_30_24277_oversea`** to return 0 immediately:
- ACE never loads config
- ACE never installs scanners
- ACE never starts the detection poller
- Game probably crashes (assumes ACE was init'd)

A safer hook: let the function run but set the right flags so detection is disabled (e.g., set ctx.+24 = 1 to skip ConfigUpdateFromServer, mock SigVerify to succeed, etc.).

The cleanest is what we already do: target SPECIFIC sensors via the 11 ANORT patches, not the init flow itself.

## To-do

- Decompile `sub_C78C4` (called from ConfigUpdateFromServer) to understand the JNI manager singleton
- Decompile `loc_E2B1C` (called between LoadSignedConfig and SingletonDword) to understand the config processor
- Find all places `dword_17115C` is read/written — it's the major init-path control flag
