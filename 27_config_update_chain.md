# ACE_ConfigUpdateFromServer — What It Actually Does (Surprise!)

## TL;DR

`ACE_ConfigUpdateFromServer` (libanort+0x12CE98) does **NOT** download anything from the server. It's misleadingly named. What it actually does:

1. Reads a local file `%s/ace_shell_di.dat` (decrypted from string ID 7153)
2. Verifies the file's signature (magic 0x20212911, timestamp within 30 days)
3. Reads Android's `Build$VERSION.SDK` via JNI
4. Builds a status report packet
5. Writes the new packet to a TEMP file then renames over the original
6. Sets `a1+24 = 1` so it never runs again in this session

So it's actually `update_local_signed_config_with_current_status()` — a STATE PERSISTENCE function. The server fetch happens elsewhere (probably polled separately).

## Decoded chain

```c
ACE_ConfigUpdateFromServer(ctx) {
    if (g_anort_config_flags & 0x100) return 0;     // Tier 5 disable
    if (ctx.+24) return 0;                           // already ran
    
    if (!ACE_SignedDataVerify(ctx)) {               // verify local file
        ctx.+24 = 1;
        return 0;
    }
    
    singleton = sub_C78C4(hash_state);              // some manager singleton
    if (!singleton) return -1;
    
    // FindClass("android/os/Build$VERSION") via vfn[48]
    cls = singleton->vfn[48](singleton, decrypt(6359));   // = "android/os/Build$VERSION"
    if (!cls) {
        singleton->vfn[136](singleton);             // cleanup
        return -1;
    }
    
    if (!singleton->vfn[1824](singleton)) {         // some pre-check, must succeed
        cleanup;
        return -1;
    }
    
    // GetStaticStringField(cls, "SDK") via JNI helper
    sdk_string = ACE_JNIGetStaticStringField(decrypt(6443), singleton, cls, ...);
    //                                       ^
    //                                       = "SDK"
    
    ctx.+24 = 1;
    ACE_ReportPacketBuilder(ctx);                   // writes report to disk
    return 0;
}
```

## The decrypted strings

| String ID | Decoded | Used as |
|---|---|---|
| 6359 | `android/os/Build$VERSION` | JNI class name |
| 6386 | `SDK_INT` | static field name (alternative) |
| 6443 | `SDK` | static field name (used here) |
| 7153 | `%s/ace_shell_di.dat` | output file path template |

## ACE_SignedDataVerify

```c
ACE_SignedDataVerify(ctx) {
    path = ACE_FormatEncryptedPath_7153(buf, 1024);  // -> "%s/ace_shell_di.dat" 
                                                      //    formatted with package dir
    if (!path) return -1;
    
    ACE_FileReadToBuffer(buf, path);                  // load file contents
    
    parser = ACE_LinkedListNode_Init(data, size, 1);
    
    magic = ACE_MutexLock(parser);                    // ALL these MutexLocks are
                                                       // actually field readers from
                                                       // the parser!
    if (magic != 0x20212911) return -1;               // magic check
    
    file_time = ACE_MutexLock(parser);                // read timestamp
    now = ACE_GetTime();
    if (now - file_time > 0x278D00) return -1;        // 30 days = 2,592,000 seconds
    
    payload_offset = ACE_MutexLock(parser);
    expected_hash = ACE_MutexLock(parser);
    payload_size = sub_11B8C0(parser);
    
    if (payload_offset + payload_size > file_size) return -1;
    
    actual_hash = ACE_EventSignal(file_data + payload_size, payload_offset);
    if (actual_hash != expected_hash) return -1;     // hash check
    
    *ctx = ACE_ReadLengthPrefixedString(parser, 0); // extract payload
    return 0;
}
```

## ACE_ReportPacketBuilder

```c
ACE_ReportPacketBuilder(ctx) {
    if (!ctx.+24) return;
    
    buf = byte[1024];
    parser = ACE_LinkedListNode_Init(buf, 1024, 1);
    
    // Build packet header: magic + timestamp + 0 + 0
    ACE_CondWait(parser, 0x20211111);                // magic
    ACE_CondWait(parser, ACE_GetTime());             // timestamp
    ACE_CondWait(parser, 0);                          // reserved
    ACE_CondWait(parser, 0);                          // reserved
    
    payload_start = ACE_BufferPosition(parser);
    
    // Append payload from *ctx
    if (sub_11BAD0(parser, *ctx)) {                   // copy payload
        end = ACE_BufferPosition(parser);
        size = end - payload_start;
        hash = ACE_EventSignal(buf + payload_start, size);
        
        // Patch in size and hash at fixed offsets
        sub_11B89C(parser, payload_start - 8);       // size slot
        ACE_CondWait(parser, size);
        sub_11B89C(parser, payload_start - 4);       // hash slot
        ACE_CondWait(parser, hash);
        
        // Write to disk
        path = ACE_FormatEncryptedPath_7153(...);     // -> ace_shell_di.dat
        if (path && *path)
            sub_115150(path, buf, payload_start + size);  // file write
    }
    ACE_LinkedList_FreeAll(parser);
}
```

## sub_115150 (file writer)

```c
sub_115150(path, data, size) {
    sub_115074(path);                                // validate path
    
    // Build "%s.tmp" path
    snprintf(tmp_path, 1024, "%s.tmp", path);
    
    fp = ACE_FileOpen(tmp_path, "w");
    if (!fp) return -1;
    
    // Write in 4KB chunks
    for (offset = 0; offset < size; offset += 4096) {
        chunk = min(4096, size - offset);
        if (ACE_FileWrite(data + offset, 1, chunk, fp) != chunk) {
            ACE_FileClose(fp);
            unlink(tmp_path);
            return -1;
        }
    }
    ACE_FileClose(fp);
    
    // Atomic replace
    unlink(path);
    rename(tmp_path, path);
    
    return access(path, 0) ? -1 : 0;
}
```

## Where DOES the server fetch happen?

Not here. The actual server fetch is in a different function. Candidates:
- `ACE_DetectionPoller` (libanort+0x71484) — periodic poller, may include sync calls
- `ACE_LoadSignedConfig` (libanort+0x12C324) — separate function, mentioned in init
- TDM channel's vfn[40] — submits reports (may include response handling)

Will trace further later.

## Bypass implications

Tier 5 (`g_anort_config_flags |= 0x100`) is doubly effective:
- Blocks `ACE_ConfigUpdateFromServer` from running entirely (tested)
- ACE never updates `ace_shell_di.dat` on disk → stale file timestamps
- After 30 days, `ACE_SignedDataVerify` would reject ANY local config (timestamp > 30 days old)

So setting bit 0x100 once and leaving it set will eventually make ACE think it has no fresh config at all — and downloaded rule modules can't load without this baseline.

## Related TODOs

1. Trace `sub_C78C4` to understand what JNI manager singleton it returns.
2. Find the actual server-fetch code path (probably uses `java/net/URL` JNI).
3. Decode the file format of `ace_shell_di.dat` (16-byte header + length-prefixed payload).
4. Understand what `payload_start - 8` and `payload_start - 4` slots store (probably size and CRC).
