# libanogs JNI Native API — The 11 Methods

`libanogs.so`'s `JNI_OnLoad` registers **11 native methods** on a target Java class. These are the Java-callable APIs that game code uses to interact with ACE.

## The 11 native methods

| Slot | Method name | Signature | Native function | String IDs |
|---|---|---|---|---|
| 0 | `init` | (?) | `ace_jni_init` | name=2970, sig=`sub_2DC3AC()` |
| 1 | `setuserinfo` | (?) | `ace_jni_setuserinfo` | name=2977, sig=`sub_2DC3B8()` |
| 2 | `setuserinfoex` | (?) | `ace_jni_setuserinfoex` | name=2991, sig=`sub_2DC3C4()` |
| 3 | `setgamestatus` | (?) | `ace_jni_setgamestatus` | name=3007, sig=`sub_2DC3D0()` |
| 4 | `getsdkantidata` | (?) | `ace_jni_getsdkantidata` | name=3023, sig=`sub_2DC3DC()` |
| 5 | `setsenddatatosvrcb` | (?) | `ace_jni_setsenddatatosvrcb_trampoline` | name=3040, sig=3140 (`(Ljava/lang/Object;)V`) |
| 6 | `senddatatosdk` | (?) | `ace_jni_senddatatosdk_impl` | name=3061, sig=3131 (`([BI)V`) |
| 7 | `senddatatosvr` | (?) | `ace_jni_senddatatosvr_trampoline` | name=3077, sig=3131 (`([BI)V`) |
| 8 | `onruntimeinfo` | (?) | `ace_jni_onruntimeinfo_trampoline` | name=3093, sig=3131 (`([BI)V`) |
| 9 | `hasMatchRate` | (?) | `ace_jni_hasMatchRate_trampoline` | name=3109, sig=3124 (`(I)I`) |
| 10 | `setappobject` | `(ILjava/lang/Object;)I` | `ace_jni_setappobject_trampoline` | hardcoded |

(Some signatures returned via separate functions sub_2DC3AC..sub_2DC3DC; we'd need to decompile each to get them.)

## Decoded signatures (partial)

| ID | Decrypted |
|---|---|
| 3124 | `(I)I` |
| 3131 | `([BI)V` |
| 3140 | `(Ljava/lang/Object;)V` |

## Class names

ACE registers methods on TWO classes:
1. **Class 1** (always `com/tss/gamedemo/Game`): only 3 methods — `init`, `onPause`, `onResume` (test class, not production?)
2. **Class 2** (built dynamically by `ace_build_jni_class_name`): the 11-method real class

Class 2 name is constructed at runtime to evade static analysis. We'd need to hook `ace_build_jni_class_name` to see the actual class name. Common candidates: `com.ace.AntiCheatExpert`, `com.tencent.GameProtect`, etc.

## Method semantics (educated guesses based on names)

### `init() -> int`
The bootstrap. Java code calls this once at app start. Returns 0 on success.

### `setuserinfo(byte[] data, int len) -> void`
Pushes user identity/account info to ACE. Used so detection reports include user ID.

### `setuserinfoex(byte[] data, int len) -> void`
Extended user info — additional fields (region, account verification, etc.).

### `setgamestatus(byte[] data, int len) -> void`
Pushes game state — current scene, level, mode, etc. Allows ACE to detect cheats specific to game state.

### `getsdkantidata() -> byte[]`
Returns ACE's collected detection data for upload to server.

### `setsenddatatosvrcb(Object callback) -> void`
Registers a Java-side callback for "send to server" events.

### `senddatatosdk(byte[] data, int len) -> void`
Push raw data INTO ACE (e.g., server response).

### `senddatatosvr(byte[] data, int len) -> void`
Push data OUT to server (typically the report packet).

### `onruntimeinfo(byte[] data, int len) -> void`
Runtime info notification (memory pressure, FPS drop, etc.).

### `hasMatchRate(int level) -> int`
"Match rate" — likely a confidence score check. Returns int based on how many detections fired.

### `setappobject(int what, Object obj) -> int`
Generic setter for objects. `what=0` might be "set Activity", `what=1` "set Application", etc.

## Integration with libanort (the JNI bridge documented earlier)

libanogs has its OWN JNI methods registered. libanort has 6 different JNI methods. Both are loaded into the same JVM, both register native methods on different classes:

- **libanort**: ~6 methods on a class resolved via 5 different decrypted strings (ACE_Initialize, ProcessCommand, GetByteArray, QueryData, FileOperation, CommandDispatch)
- **libanogs**: 11 methods on `(class name resolved at runtime)` — init, setuserinfo, etc.

So Java code calls EITHER libanort's JNI methods (for control plane: stop/scan commands) OR libanogs's JNI methods (for data plane: user info, game state, send/recv).

## Bypass implications

If we wanted to **fully isolate** ACE:
- Hook all 11 methods in libanogs to no-op
- Hook all 6 methods in libanort to no-op
- Total surface: ~17 JNI methods to neutralize

This would make ACE completely deaf to Java-side interactions. But:
- The game code calls these to inform ACE; if we silence them, the game itself may fail (e.g., expecting `init()` to return 0)
- ACE has its own thread-driven detection that doesn't need Java

So selective hooking is preferred — only block the truly dangerous methods (e.g., `senddatatosvr` to kill detection reporting).

## Decoding obfuscated method names

Each method name is decrypted via a different XOR variant (`ace_decrypt_xor46`, `xor4D`, `xor5B`, etc.). This is the standard ACE encryption scheme — 100 different XOR functions, each handling specific string ID ranges.

## Discovery method

To find more JNI methods that may be registered LATER (after JNI_OnLoad):
- Hook `RegisterNatives` (jni->RegisterNatives at vtable+1720)
- Log the JNINativeMethod array contents
- Capture native function addresses for analysis

This would catch any dynamic registration that happens at runtime (unlikely for ACE, but possible).

## To-do

- Decompile `sub_2DC3AC..sub_2DC3DC` to get exact JNI signatures for each method
- Hook each method in REPL bridge to log call arguments
- Determine the resolved class name from `ace_build_jni_class_name`
- Map `senddatatosvr` flow to know exactly what data ACE sends to server
- Cross-reference with detection reporting in libanort
