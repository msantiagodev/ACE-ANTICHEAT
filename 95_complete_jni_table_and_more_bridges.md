---
iter: 71
title: COMPLETE JNI Dispatch Table — All 229 Decoded + More __ff_<n>
status: every CRC32 in g_ace_jni_dispatch_tree mapped to a JNI function name
---

# Complete JNI Dispatch Table — 229/229 Decoded

After expanding the brute-force dictionary to include the full standard JNI API (JNINativeInterface_ from `jni.h`, 228 methods), we matched **all 229 CRC32 entries** in `g_ace_jni_dispatch_tree`. The dispatch table is **literally the entire standard JNI invocation table**, CRC32-indexed.

## Implication

The 229-entry RB-tree at libanort+0x1A84C8 IS the JNI vtable, with every single Java Native Interface function exposed:

```
cmd[0..228] ↔ JNINativeInterface_ struct (jni.h)
            ↔ Each entry's "offset" field = struct member offset (32 + i*8)
            ↔ At runtime, JNIEnv*->FunctionAt(offset)(args...)
```

When VM bytecode in `vm_main.img` calls a JNI function, the sequence is:
1. Bytecode loads the JNI method NAME (string) into a register
2. Bytecode invokes `__ff_96` → computes `CRC32(name)`, looks up entry, returns offset
3. Bytecode loads JNIEnv pointer + offset, calls `__ff_97` → invokes `JNIEnv->methods[offset/8]`

This is a **deliberate obfuscation layer** — instead of having JNIEnv-relative offsets baked into the bytecode (which would be obvious), ACE indirects through CRC32 of the human-readable name. Trivially reversible (we did it in minutes) but requires recognizing the pattern first.

## Full mapping (229 entries)

| Index Range | JNI API Group | Notes |
|---|---|---|
| 0..2 | GetVersion, DefineClass, FindClass | Class loader |
| 3..14 | FromReflected*, ToReflected*, Throw, Exception* | Reflection + exceptions |
| 15..22 | LocalFrame, GlobalRef, LocalRef, IsSameObject | Reference management |
| 23..28 | AllocObject, NewObject*, GetObjectClass, IsInstanceOf | Object construction |
| 29..59 | GetMethodID + Call*Method (Object/Boolean/Byte/Char/Short/Int/Long/Float/Double/Void × 3 variants) | Instance method calls (90 entries!) |
| 60..89 | CallNonvirtual* (× 30 variants) | Non-virtual method calls |
| 90..108 | GetFieldID, Get/Set*Field | Field accessors |
| 109..139 | GetStaticMethodID, CallStatic*Method (× 30 variants) | Static method calls |
| 140..158 | GetStaticFieldID, Get/SetStatic*Field | Static field accessors |
| 159..166 | NewString*, GetString*, ReleaseString* | String handling |
| 167..210 | GetArrayLength, New*Array, Get*Array*, Release*Array*, Get/SetArray*Region | Array operations |
| 211..215 | RegisterNatives, UnregisterNatives, MonitorEnter/Exit, GetJavaVM | Misc |
| 216..221 | GetString*Region, *Critical | More string/array ops |
| 222..223 | NewWeakGlobalRef, DeleteWeakGlobalRef | Weak refs |
| 224 | ExceptionCheck | |
| 225..227 | NewDirectByteBuffer, GetDirectBufferAddress, GetDirectBufferCapacity | Direct buffers |
| 228 | GetObjectRefType | Final entry |

That's the **complete JNI function set** (counted with all 3 variants of method calls, exact match to JNI spec).

## __ff_109/110/111 identified (next top imports after the memory glue)

| Bridge | Function | Purpose |
|---|---|---|
| `__ff_109` | `ace_vm_ff109_set_ctx_field` (libanort+0x13DCA0) | Single-line: `ctx[+284] = *input`. A simple field-write helper. |
| `__ff_110` | `ace_vm_ff110_hash_lookup` (libanort+0x13DCAC) | Calls `ACE_HashCompute()` then `sub_C7CA8(hash)`, returns VM-relative pointer. Likely a singleton/object lookup-by-hash. |
| `__ff_111` | `ace_vm_ff111_get_obfuscated_str` (libanort+0x13DCE0) | Returns VM-relative pointer to obfuscated string `"Txy*#xP?@xxP6~C"` at libanort+0x171108. This is a Layer-2 encrypted string (cipher TBD). |

## Bypass implications — refined

### Confirmed best bypass: hook `__ff_97`
With ALL 229 dispatch entries mapping to JNI functions, every JNI call from VM bytecode goes through the same chain:
- Bytecode → `__ff_96` (lookup offset) → `__ff_97` (invoke function)

**Patching `__ff_97` to return 0 disables 100% of JNI usage from ANY VM module** — instant kill for all Java-introspection-based detection (which is the bulk of detection logic since strings showed massive use of class/method/field reflection).

### Alternative: spoof `__ff_96` to return offset 0
Returning offset 0 from `__ff_96` would direct every JNI call to `JNIEnv->GetVersion`, which always succeeds and returns harmless data. This might keep the VM running normally (no crashes from null function pointers) while making all detection results meaningless.

### Implementation outline (Tier 14 candidate)
```c
// Hook ace_vm_ff97_native_funcptr_call (libanort+0x13DA54)
__int64 hook_ff97(void* a1) {
    *(_QWORD*)a1 = 0;  // pretend the JNI call returned 0/NULL
    return 0;
}
```
One-line patch. Affects nothing else since __ff_97 is exclusively used for native function pointer calls within VM bytecode.

## CRC32 brute-force strategy

For future readers: when you find an unidentified table of CRC32-indexed values in ACE-style code:
1. Build a dictionary of likely names (here: all JNI function names from `jni.h`)
2. CRC32 each (IEEE 802.3 polynomial 0xEDB88320, init 0xFFFFFFFF, xor 0xFFFFFFFF)
3. Match against the table — many will hit
4. The pattern of which hit + which don't reveals what API the table is wrapping

This works because:
- ACE always uses the same CRC-32 (doc 86)
- Function names are usually drawn from a public-spec API (JNI, libc, OpenSSL, etc.)
- Even custom names often follow predictable patterns (camelCase, snake_case)

## Renames + comments

| Address | Old | New |
|---|---|---|
| 0x13DCA0 | sub_13DCA0 | `ace_vm_ff109_set_ctx_field` |
| 0x13DCAC | sub_13DCAC | `ace_vm_ff110_hash_lookup` |
| 0x13DCE0 | sub_13DCE0 | `ace_vm_ff111_get_obfuscated_str` |

## Static artifacts

| File | Description |
|---|---|
| `command_dispatch_crcs.txt` | All 229 CRC32→JNI function mappings (now complete) |
| `jni_brute_v2.py` | Reproducible brute-forcer with full JNI dictionary |

## Cross-references

| Doc | Topic |
|---|---|
| `94_jni_dispatch_table.md` | First 32 entries identified (now superseded) |
| `92_vm_module_bytecode_format.md` | The native bridge import system |

## To-do

- Identify the Layer-2 string cipher (still encrypted strings like `"Txy*#xP?@xxP6~C"`, `']T_@QA'`, `'ok\\RY'`)
- Map the rest of the 162-entry __ff table — we've now identified ~12 of 162 (ff_1..ff_12, ff_21, ff_96, ff_97, ff_109..111, ff_167, ff_168)
- Trace which JNI methods VM bytecode actually CALLS (statically — by tracking the BL→__ff_96 sequences and identifying the preceding string load)
- Find the RSA-2048 public key used to verify a64.sig
