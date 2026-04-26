# libanogs JNI — Full Method Signatures and Behavior

Building on `66_libanogs_jni_native_api.md`, this is the complete signature table with confirmed types and observed behavior of the implementations.

## All 11 methods with full signatures

| # | Java method | Signature | Native impl | Notes |
|---|---|---|---|---|
| 0 | `init(Object obj)` | `(Ljava/lang/Object;)V` | `ace_jni_init` | Bootstrap; Object = current Application |
| 1 | `setuserinfo(Object userInfo)` | `(Ljava/lang/Object;)V` | `ace_jni_setuserinfo_impl` | Reads 8 fields from Java object |
| 2 | `setuserinfoex(Object userInfoEx)` | `(Ljava/lang/Object;)V` | `ace_jni_setuserinfoex_impl` | Extended user info |
| 3 | `setgamestatus(Object gameStatus)` | `(Ljava/lang/Object;)V` | `ace_jni_setgamestatus_impl` | Game state struct |
| 4 | `getsdkantidata(Object query) -> int` | `(Ljava/lang/Object;)I` | `ace_jni_getsdkantidata_impl` | Returns ACE detection report data |
| 5 | `setsenddatatosvrcb(Object cb)` | `(Ljava/lang/Object;)V` | `ace_jni_setsenddatatosvrcb_trampoline` | Java callback for outbound data |
| 6 | `senddatatosdk(byte[] data, int len)` | `([BI)V` | `ace_jni_senddatatosdk_impl` | Push bytes INTO ACE |
| 7 | `senddatatosvr(byte[] data, int len)` | `([BI)V` | `ace_jni_senddatatosvr_trampoline` | Push bytes OUT to server |
| 8 | `onruntimeinfo(byte[] data, int len)` | `([BI)V` | `ace_jni_onruntimeinfo_trampoline` | Runtime telemetry update |
| 9 | `hasMatchRate(int level) -> int` | `(I)I` | `ace_jni_hasMatchRate_trampoline` | Detection confidence query |
| 10 | `setappobject(int what, Object obj) -> int` | `(ILjava/lang/Object;)I` | `ace_jni_setappobject_trampoline` | Generic Object setter |

## `setuserinfo` — what fields are read

`ace_jni_setuserinfo_impl` reads **8 fields** from the input Object. Each field is identified by an encrypted-name string ID:

| Field | Type | String ID | Decrypted name |
|---|---|---|---|
| field_a | `I` (int) | 1991 | (unknown) |
| field_b | `I` (int) | 2002 | (unknown) |
| field_c | `I` (int) | 2013 | (unknown) |
| field_d | `Ljava/lang/String;` | 2023 | (unknown — string field) |
| field_e | `I` (int) | 2033 | (unknown) |
| field_f | `I` (int) | 2047 | (unknown) |
| field_g | `Ljava/lang/String;` | 2060 | (unknown — string field) |
| (type ids) | 1987 = `I`, 1941 = `Ljava/lang/String;` | | |

After reading, packs into a 144-byte struct (`v32`) and calls `sub_1CAF64` to process. Likely fields include user_id, account_type, game_id, region, IMEI, etc.

## `getsdkantidata` — the report retrieval flow

`ace_jni_getsdkantidata_impl` is the function the GAME calls to ASK ACE for its report data:

```c
int ace_jni_getsdkantidata_impl(JNIEnv* env, jobject self, jobject query) {
    char buf[1024];
    
    // Read string field "Ljava/lang/String;" (id 1941) from query Object
    jclass cls = env->GetObjectClass(query);
    jfieldID fid = env->GetFieldID(cls, query_field_name, "Ljava/lang/String;");
    jstring jstr = env->GetObjectField(query, fid);
    if (jstr) {
        const char* s = env->GetStringUTFChars(jstr, 0);
        memcpy(buf, s, 1024);
        env->ReleaseStringUTFChars(jstr, s);
    }
    
    // Compute hash of the query (it's just strlen — see ACE_strlen finding)
    if (ACE_strlen(buf)) {
        // Try to register the decoder entry
        if (ace_register_decoder_entry(buf, ...) == 0) {
            // Get the report buffer (cached detection data)
            void* report = ace_get_report_buffer();
            if (report) {
                // Send via the registered Java callback
                send_to_callback(env, self, query, "callback_method_name", report);
                return 0;
            }
        }
        // Fallback paths...
    }
    return -1;
}
```

The `query` Object is a Java struct with a `String` field — likely the desired report type (e.g., "anti_cheat", "anti_inject", etc.).

## `senddatatosvr` and the report packet

The `senddatatosvr(byte[] data, int len)` method is THE outbound channel for ACE to send detection reports to the server. The Java side receives the bytes and forwards them to the configured server URL (set via the callback in `setsenddatatosvrcb`).

This is the data plane — every detection eventually flows through here. **If we hook this method to drop bytes, server never sees detections.**

## ACE's anti-tamper integrity flag

`g_libanogs_string_integrity_failed` (libanogs+0x58D290) is set to 1 if any decrypted string fails its integrity check. Each `ace_decrypt_xorXX` function performs an XOR-checksum test:

```c
// At end of decryption loop:
if ((encrypted_table[end+1] ^ running_checksum ^ initial_key) != 0xFF)
    g_libanogs_string_integrity_failed = 1;  // ANTI-TAMPER FIRED
```

So ACE detects if its own encrypted string table has been modified. If we patched a decoded string in memory, the integrity check on the next decryption would fire, setting this flag. Downstream code may then take action (potentially exit, fail-closed).

## Decryption variant `ace_decrypt_xor46` (string ID range 1968-2027)

The 100 decoder family follows our skill's formula `(XOR_CONST=N, ADD_CONST=7-(N%7))`. For variant 0x46:
- `XOR_CONST = 0x46` (70)
- `ADD_CONST = 7 - (70%7) = 7 - 0 = 7`

The decoder rolls the key: `key = ((key + i) ^ 0x46) + 7`. Each variant handles a specific byte range of string IDs.

## Bypass implications

To **stop ACE from receiving game state**:
- Hook `ace_jni_setuserinfo_impl` and `ace_jni_setgamestatus_impl` to no-op. Game still calls them but ACE doesn't process.
- This breaks user-specific detection (ACE can't tag reports with user ID).

To **stop ACE from sending reports**:
- Hook `ace_jni_senddatatosvr_trampoline` to drop. ACE generates reports but they don't leave the device.
- Combined with cache-DB neutralization (`ACE_LoadCacheDb`), no detection state persists.

To **lie about device match rate**:
- Hook `ace_jni_hasMatchRate_trampoline` to always return 0 (no matches). The game's anti-cheat decision logic might base ban actions on this.

These would be Tier 11-13 candidates — currently not deployed.

## To-do

- Decompile each `ace_jni_*_trampoline` to see the trampoline logic
- Decrypt strings 1991, 2002, 2013, 2023, 2033, 2047, 2060 to know exact field names
- Decompile `sub_1CAF64` (the userinfo-struct processor)
- Map `ace_get_report_buffer` (libanogs+0x1C923C) — the detection data accessor
- Trace the full path from `senddatatosvr` → server (HTTP request, packet build, encryption)
