---
iter: 70
title: VM JNI Dispatch Table — 32 of 229 Commands Identified as JNI Functions
status: jni dispatch mechanism reverse-engineered, 32 entries decoded by CRC brute-force
---

# VM JNI Dispatch Table

This iteration solves a major mystery: what is the 229-entry RB-tree built by `__ff_96`? It's the **VM's JNI invocation table**.

## __ff_96 = `ace_vm_ff96_jni_dispatcher` (libanort+0x13BCE8)

When VM bytecode wants to call a JNI function (e.g., `FindClass`), it doesn't reference the JNI function pointer directly. Instead:

1. The bytecode passes a string (e.g., `"FindClass"`) and arguments
2. `__ff_96` is invoked, which:
   - Lazy-initializes a 229-entry RB-tree on first call (mapping CRC32→offset)
   - Computes `CRC32(input_string)` via `ACE_CRC32`
   - Looks up the matching entry in the RB-tree
   - Returns a dispatcher offset (32, 40, 48, ..., 1856 — 8-byte stride)
3. The dispatcher offset is then used by `__ff_97` to invoke the actual JNI function via raw function-pointer call

So the **CRC32 of the JNI function name** is the lookup key. This obfuscation hides which JNI methods are being called from static analysis — until you brute-force the CRCs against a dictionary, which we just did.

## __ff_97 = `ace_vm_ff97_native_funcptr_call` (libanort+0x13DA54)

The DANGEROUS one. Takes an opaque function pointer + 8 args from emulated registers and calls it directly:

```c
result = (*(fnptr*)a1)(*(_QWORD*)(a1+8), *(_QWORD*)(a1+16), ..., *(_QWORD*)(a1+56),
                       *(_QWORD*)(*(_QWORD*)(a1+416) + *(_QWORD*)(a1+256)));  // 8th arg from VM stack
```

**No pointer translation, no validation.** This is the universal "invoke any native function" primitive in the VM. Critical bypass target — if we hook this to be a no-op, ALL JNI detection from VM bytecode silently fails.

## 32 of 229 commands decoded as JNI methods

By CRC32-brute-forcing our 2,510 known ACE strings against the dispatch table, we identified the following JNI methods explicitly:

| Index | CRC32 | JNI Method |
|---|---|---|
| 2 | `0x26616EC1` | `FindClass` |
| 13 | `0xB3E91CD8` | `ExceptionClear` |
| 19 | `0xF492B3D7` | `DeleteLocalRef` |
| 24 | `0x5F5E8338` | `NewObject` |
| 27 | `0xC0FEB398` | `GetObjectClass` |
| 29 | `0x2003D224` | `GetMethodID` |
| 30 | `0x16A37048` | `CallObjectMethod` |
| 33 | `0x4712BDC2` | `CallBooleanMethod` |
| 57 | `0x272A78A9` | `CallVoidMethod` |
| 90 | `0x96D49340` | `GetFieldID` |
| 91 | `0x7640EF5F` | `GetObjectField` |
| 96 | `0x2F8BDC85` | `GetIntField` |
| 109 | `0xC1425E8C` | `GetStaticMethodID` |
| 110 | `0x073E7444` | `CallStaticObjectMethod` |
| 125 | `0x8A56CDDC` | `CallStaticIntMethod` |
| 140 | `0xD9C0230B` | `GetStaticFieldID` |
| 141 | `0x37C64527` | `GetStaticObjectField` |
| 142 | `0xF468834B` | `GetStaticBooleanField` |
| 146 | `0xCECA502D` | `GetStaticIntField` |
| 163 | `0x0BB4ED6B` | `NewStringUTF` |
| 165 | `0x216C2E97` | `GetStringUTFChars` |
| 166 | `0xBF04D100` | `ReleaseStringUTFChars` |
| 167 | `0x28D28013` | `GetArrayLength` |
| 168 | `0x55716900` | `NewObjectArray` |
| 169 | `0x80190399` | `GetObjectArrayElement` |
| 170 | `0xD90415CE` | `SetObjectArrayElement` |
| 172 | `0x321BFB5F` | `NewByteArray` |
| 180 | `0xF789C36A` | `GetByteArrayElements` |
| 188 | `0xDF987999` | `ReleaseByteArrayElements` |
| 196 | `0xBBCE6251` | `GetByteArrayRegion` |
| 204 | `0x9EC5E94F` | `SetByteArrayRegion` |
| 224 | `0x6AD641CD` | `ExceptionCheck` |

**Pattern**: indices 0-89 are early/Java-class JNI methods, 90-160 are field/method ID resolvers, 160-229 are array/string operations. Standard JNI API surface.

The remaining 197 entries are likely:
- Other JNI methods we missed (maybe newer/version-specific)
- Internal ACE detection helpers exposed via the same dispatcher
- Java reflection methods (Class.getName, getDeclaredMethods, etc.)

## What ACE does with these JNI methods

The full JNI surface ACE uses tells us exactly **what it scans**:

### Class introspection
- `FindClass`, `GetObjectClass`, `GetMethodID`, `GetStaticMethodID` — load and inspect Java classes
- `GetSuperclass`, `getName`, `toString` (from doc 90 strings) — class hierarchy walking
- ACE walks the entire class tree to find suspicious classes

### Field reading
- `GetObjectField`, `GetIntField`, `GetStaticObjectField`, `GetStaticBooleanField`, `GetStaticIntField`
- `GetFieldID`, `GetStaticFieldID`
- ACE reads field values from suspect classes (config strings, flag booleans, hash data)

### Method invocation
- `CallObjectMethod`, `CallBooleanMethod`, `CallVoidMethod`
- `CallStaticObjectMethod`, `CallStaticIntMethod`
- ACE calls Java methods to e.g. query PackageManager, get application info, check intent filters

### Array/string handling
- `NewByteArray`, `GetByteArrayElements`, `ReleaseByteArrayElements`
- `GetByteArrayRegion`, `SetByteArrayRegion`
- `NewStringUTF`, `GetStringUTFChars`, `ReleaseStringUTFChars`
- ACE reads byte arrays (signature checks, certificate validation, file contents) and processes UTF8 strings

### Exception handling
- `ExceptionCheck`, `ExceptionClear`
- ACE clears exceptions to avoid crashes during introspection

## Other top __ff_<n> identified

- **`__ff_21`** = `ace_vm_ff21_memcpy_with_xlate` (libanort+0x13ADB8) — VM memcpy with VM↔host pointer translation. 82 invocations.
- **`__ff_167`** = `ace_vm_ff167_returns_0` (libanort+0x13E9CC) — boolean false constant. 22 invocations.
- **`__ff_168`** = `ace_vm_ff168_returns_1` (libanort+0x13E9D4) — boolean true constant. 20 invocations.

## Entry point — confirmed

`ACE_VMModuleLoad` sets `ctx[+264] = sub_138F94(v12)`. Reading sub_138F94: `return *(_QWORD*)(a1+96)` — the field at module struct +96 is `v36` from the header (the 5th u32 read). For vm_main.img, **v36 = 0**, so VM PC starts at offset **0** of the bytecode.

The opening instruction `cbnz x28, #...` IS the legitimate first instruction. (The bytecode is heavily optimized/unconventional, not corrupt.)

## Bypass implications

### Highest leverage: hook `__ff_97`
Patching `ace_vm_ff97_native_funcptr_call` (libanort+0x13DA54) to return 0 (or no-op) **disables ALL JNI calls from VM bytecode**. Every detection routine that uses Java introspection (most of them) silently fails. Single-instruction patch.

### Medium leverage: hook `__ff_96`
Patching `ace_vm_ff96_jni_dispatcher` to never find a match means VM bytecode can never RESOLVE JNI function names. Same end result as above but with a different patch site.

### Surgical: hook just the JNI methods we care about
For each cmd[N] entry above, we can selectively bypass specific JNI methods. E.g., patch `cmd[2] = FindClass` to always return null → ACE can't find ANY Java classes → all class-based detection fails.

### Static reproduction
With the 229-entry CRC32 list dumped to `command_dispatch_crcs.txt`, future iterations can:
- Brute-force harder dictionaries (full Android API names, known reflection invocations)
- Map every detection routine in vm_main.img bytecode that hits a specific JNI method via the BL→__ff_96 sequence

## Renames + comments

| Address | Old | New |
|---|---|---|
| 0x13ADB8 | ACE_VMExecMemcpy | `ace_vm_ff21_memcpy_with_xlate` |
| 0x13BCE8 | ace_init_command_dispatch_tree | `ace_vm_ff96_jni_dispatcher` |
| 0x13DA54 | ace_vm_call_native_funcptr | `ace_vm_ff97_native_funcptr_call` |
| 0x13E9CC | sub_13E9CC | `ace_vm_ff167_returns_0` |
| 0x13E9D4 | sub_13E9D4 | `ace_vm_ff168_returns_1` |
| 0x1A84C8 | g_ace_command_dispatch_tree | `g_ace_jni_dispatch_tree` |

## Static artifacts

| File | Description |
|---|---|
| `command_dispatch_crcs.txt` | 229 CRC32→offset entries from the JNI dispatcher |
| `94_jni_dispatch_table.md` | This doc |

## Cross-references

| Doc | Topic |
|---|---|
| `93_vm_main_disassembly.md` | The vm_main.img disassembly that showed __ff_96/__ff_97 references |
| `92_vm_module_bytecode_format.md` | Native bridge import enumeration |
| `86_crc32_and_vm_context_health.md` | The CRC32 algorithm used here |
| `91_vm_modules_catalog.md` | Source modules |

## To-do

- Brute-force more JNI methods (CallStaticVoid, CallByteMethod, etc.) and Java reflection (Class.getMethod, etc.)
- Extract the actual function-pointer table the dispatcher resolves to (each cmd[i] points to offset N in some struct — find that struct)
- Identify the remaining 197 unknowns — likely include `ToReflectedMethod`, `IsInstanceOf`, etc.
- Decompile __ff_109, __ff_110, __ff_111 (next top imports we haven't identified)
