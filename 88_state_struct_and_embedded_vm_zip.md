---
iter: 64
title: Network State Struct + Embedded VM Module ZIP
status: definitive on state lifecycle and ZIP location
---

# Two more major pieces decoded

This iteration closes two long-standing unknowns:
1. The **complete network state struct** lifecycle (where does state[+32..+95] come from?)
2. The **embedded VM module ZIP** in libanort (~40 KB of VM bytecode bundled in .rodata)

## 1. Network state struct — full lifecycle

The state struct passed to all `ACE_NetworkSend*` and `ACE_PacketBuildAndSend` calls is **96 bytes** built in 3 stages:

### Stage A — `sub_147868` (state allocator/zero-init)

```c
void* sub_147868(void* state, void* openid_buf) {
    ((u64*)state)[0] = 0;            // state[+0..+7]  = 0
    ((u64*)state)[1] = 0;            // state[+8..+15] = 0
    if (openid_buf)
        ACE_SpinlockAcquire(state + 32, openid_buf, 64);  // state[+32..+95] = OpenID hex
    else
        state[32] = 0;
    return state;
}
```

The `openid_buf` arg is `byte_1A8520` — the **64-byte device OpenID hex string**.

### Stage B — `ACE_TLSHandshake` → `sub_147E4C` (session blob installation)

After connecting to `glcs.listdl.com:10012` (`ACE_NetworkConnectWithDNS`), the handshake:
1. Sends a Heartbeat packet (type=7) with empty payload
2. Server replies with 16-byte session blob + 19-byte mixing data
3. `sub_147E4C` writes:
   - `state[+16..+31]` = the 16-byte session blob (server-generated)
   - `state[+8] = state[+12]` = 32-bit hash derived from blob mixed with client+server data, modulo `0x2DB03 (=187139)`

The seq counter at state[+12] starts at this hash value (NOT zero) — making it harder to predict from sniffed traffic alone.

### Stage C — Operational

After Stage B, the state is fully initialized:

| Offset | Size | Field | Filled by |
|---|---|---|---|
| +0..+7 | 8 | reserved (zero) | Stage A |
| +8..+11 | 4 | counter A (= initial hash) | Stage B |
| +12..+15 | 4 | seq counter (= initial hash, then ++) | Stage B then per-call |
| +16..+31 | 16 | **session blob** | Stage B |
| +32..+95 | 64 | **OpenID hex string** (null-terminated) | Stage A |

### What is the OpenID?

`ACE_HBThread_DispatchPending` → `sub_146AE4` builds the OpenID by combining:
1. Timestamp (`ACE_ClockDriftValidator` returns Unix epoch micros)
2. PackageName (`com.ubisoft.the.division.mobile.combat.shooting.open.world.rpg`)
3. Two strings from `ACE_ReturnNA_1/_2` (typically `"NA"` if unset)
4. Subobject string (`ACE_GetSubObject`)
5. JNI cache string (`ACE_GetStringOrNA`)

These are formatted as `"%lld_%s_%s_%s_%s_%s"` then **MD5'd via `ACE_ComputeMemoryHashHex`** to produce a 32-character hex string in `byte_1A8520`. Then padded to 64 bytes.

### Why the protocol-hash field uses OpenID

The 131-base hash at outer-header offset +10 (the "protocol hash" we documented in doc 87) is computed over `state[+32..+95]`, which is the OpenID. So:

> **Every outbound packet's +10 field uniquely identifies the device.**

The server can correlate packets from the same device session. This was missed in doc 87 where we incorrectly called this a "protocol-name" hash. The string is in fact a per-device identity hash. (Doc 87's offset of "+33" was off-by-one; the actual string starts at state+32.)

### Spoofing implications

To send packets accepted as a target device's traffic:
- Need the target's **PackageName** (public)
- Need their **JNI cache string** (probably the player ID — possibly knowable)
- Need their **timestamp** — but `ACE_ClockDriftValidator` may snap to whole minutes/seconds
- Then can reproduce the OpenID hash

Realistically the server validates session-blob freshness so old captured blobs won't work. But this confirms the threat surface: NO crypto, just data correlation.

## 2. Embedded VM module ZIP

While auditing the tail of the opcode table at 0x164AF0, we found that what appeared to be "trailing opcode handlers" are actually **C++ vtable entries for VM module loaders**. The opcode table proper ends earlier (around 0x14555C); the bytes from offset 0x164FB0 onward belong to a different vtable structure.

### The ZIP file

`sub_14692C` returns `&unk_19887B` — a pointer to the start of an **embedded ZIP archive** in libanort's .rodata section.

```
0x19887B: 50 4B 03 04 14 00 00 00 08 00 80 5C 3A 5C 7F F0 ...
          ^^^^^^^^^^^                                  ^^^
          PK\x03\x04                                   ZIP local file header
```

`sub_146938` returns `40302` (= 0x9D6E) — the **size in bytes** of the embedded ZIP.

### VM module loaders

Two distinct loaders found, each requesting a specific file from the embedded ZIP:

#### `ACE_LoadVMModule_GP7Worker` (libanort+0x1467E8)
```c
// Decrypted string 11976 = "vm_gp7worker.img"
ACE_StringCopyToVector(&filename, "vm_gp7worker.img");
ACE_LinkedList_Insert(file_list, filename);

ACE_ZipExtractAndProcess(
    output_modules,
    "builtin",                       // string 11285
    file_list,                       // ["vm_gp7worker.img"]
    decrypted_string_11325,          // some filter or password
    embedded_zip_ptr,                // unk_19887B
    embedded_zip_size,               // 40302
    tree_ctx,
    *(int*)(this + 52)
);
ACE_VMExecutionDriver(loaded_modules);
```

#### `ACE_LoadVMModule_GP7Service` (libanort+0x146610)
- Same flow, but loads `vm_gp7service.img` (decrypted string 11995)
- Gated by `prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0` — only runs if the process can mark itself dumpable (ptraceable)
- This is likely an anti-restricted-environment check: hardened sandboxes may reject the prctl, in which case the GP7 service module is skipped

### Decrypted string IDs in the loaders

| ID | Decrypted | Use |
|---|---|---|
| 11285 | `builtin` | Source-tag string passed to ZipExtractAndProcess |
| 11325 | (TBD — needs decrypt) | Filter or password to ZipExtractAndProcess |
| 11976 | `vm_gp7worker.img` | Filename of GP7 worker VM module |
| 11995 | `vm_gp7service.img` | Filename of GP7 service VM module |

### What this means

ACE's VM bytecode is **not** loaded from disk at runtime — it's **embedded directly inside libanort.so** as a 40 KB ZIP archive. To dump the VM modules:
1. Compute runtime address: `libanort_base + 0x19887B`
2. Read 40,302 bytes
3. Save as `vm_modules.zip`
4. Standard `unzip` should reveal `vm_gp7worker.img`, `vm_gp7service.img`, and possibly more

Comparing this dumped ZIP against `down.anticheatexpert.com` CDN-served `ob_*.zip` files would reveal whether the embedded modules ever differ from the CDN-served ones (likely the embedded set is a fallback/initial cache).

### Bypass implications

#### Tier candidate: kill VM module loaders directly
Hooking the two VM-module-loader entrypoints (`0x146610` and `0x1467E8`) to return without calling `ACE_VMExecutionDriver` would prevent these specific modules from ever running, **regardless** of whether `ACE_VMExecutionDriver` is patched. Currently the bypass relies on global VM driver suppression (Tier 8). This would be more surgical.

#### Static dump of VM modules
Add to bypass `Main.cpp`:
```c
void dump_embedded_vm_zip() {
    void* base = dlopen("libanort.so", RTLD_NOW);
    void* zip_addr = (char*)base + 0x19887B;
    FILE* f = fopen("/sdcard/Android/data/<pkg>/files/embedded_vm.zip", "wb");
    fwrite(zip_addr, 1, 40302, f);
    fclose(f);
}
```
Then `unzip` to inspect what bytecode is actually inside.

## Renames applied this iteration

| Address | Old | New |
|---|---|---|
| 0x14692C | sub_14692C | `ACE_GetEmbeddedVMZipPtr` |
| 0x146938 | sub_146938 | `ACE_GetEmbeddedVMZipSize` |
| 0x19887B | unk_19887B | `g_ace_embedded_vm_modules_zip` |
| 0x146610 | vfunc_2_146610 | `ACE_LoadVMModule_GP7Service` |
| 0x1467E8 | vfunc_2_1467e8 | `ACE_LoadVMModule_GP7Worker` |
| 0x11C6F8 | vfunc_0_11c6f8 | `ACE_VMModuleLoader_Destructor` |
| 0x146908 | vfunc_1_146908 | `ACE_VMModuleLoader_DeleteAndDestroy_v1` |
| 0x1468E4 | vfunc_1_1468e4 | `ACE_VMModuleLoader_DeleteAndDestroy_v2` |
| 0x147868 | sub_147868 | `ACE_NetworkStateInit` |
| 0x147E4C | sub_147E4C | `ACE_TLSHandshake_InstallSessionBlob` |
| 0x14A6CC | (already named) | (no change) |
| 0x146AE4 | sub_146AE4 | `ACE_GetOrComputeOpenID` |

## Cross-references

| Doc | Topic |
|---|---|
| `87_outbound_wire_format_complete.md` | Wire format (this doc supersedes the "+33" offset note; correct offset is +32) |
| `80_network_endpoint_full.md` | glcs.listdl.com:10012 endpoint |
| `81_heartbeat_thread_internals.md` | HBThread that drives the network state |
| `22_libanort_arm64_emulator.md` | The VM emulator that runs the unzipped modules |
| `46_arm64_emulator_handler_extension.md` | Opcode coverage extension |

## To-do

- Dump the 40,302-byte embedded ZIP at runtime, unpack `vm_gp7worker.img` and `vm_gp7service.img`
- Decompile `ACE_ZipExtractAndProcess` to see the filter/password (string 11325)
- Disassemble the VM bytecode inside the modules using our 80+ documented opcode handlers
- Look for additional VM module loaders beyond GP7Worker/GP7Service — check 0x164FB0..0x164F90 region for more vtable entries
- Recompute `ACE_PacketHeaderInit_Inner` field semantics with corrected +32 string offset (already correct in implementation, doc 87 has the typo)
