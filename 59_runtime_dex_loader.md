# Runtime DEX Loader — ACE's Java Bytecode Backdoor

`JNI_ACE_ProcessCommand` and `JNI_ACE_QueryData` use `ACE_ResolveDynFunc` to resolve **internal libart.so symbols** at runtime, then invoke them to **load arbitrary DEX bytecode from memory or disk**, bypassing Android's normal class loader.

## The 6 dynamically-resolved libart symbols

| String ID | Mangled symbol | Demangled |
|---|---|---|
| 9654 | `_ZN3art7DexFile4OpenEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEEEEjPKNS_10OatDexFileEbPS9_` | `art::DexFile::Open(uint8_t* data, uint32_t size, string& location, uint32_t checksum, art::OatDexFile* oat_dex, bool verify, art::DexFile** out)` (32-bit length) |
| 9772 | (same with `m` for size_t) | Same as above but **size_t** for length (newer Android) |
| 9890 | `art::DexFile::OpenMemory(uint8_t* data, uint32_t size, string& location, uint32_t checksum, art::MemMap* mem_map, art::OatDexFile* oat_dex, art::DexFile** out)` | (32-bit length) |
| 10026 | (same with `m`) | Same with **size_t** length |
| 10162 | `art::DexFile::OpenMemory(uint8_t* data, uint32_t size, string& location, uint32_t checksum, art::MemMap* mem_map, art::OatFile* oat_file, art::DexFile** out)` | OatFile variant |
| 10294 | (same with `m`) | OatFile variant, **size_t** length |

## What this means

**ACE can take a raw byte array of compiled Java bytecode (a `.dex` file) and ask libart.so to load it directly into the JVM**, bypassing:

- Android's `DexClassLoader` (which is hookable)
- Google Play's APK review (the bytecode never went through any review)
- The host app's manifest declarations
- Any `BaseDexClassLoader` instrumentation

This means ACE has a **runtime Java code injection capability** that's invisible to standard Android tooling.

## Why ACE needs this

1. **Server-pushed Java detection updates** — ACE can ship new Java-side detection code without app store updates.
2. **Anti-hook stealth** — `DexClassLoader` is a public API and can be hooked. `art::DexFile::OpenMemory` is internal C++.
3. **Faster iteration** — push a new DEX, no need to rebuild the SO.

## Bypass implications

If we wanted to **stop ACE from loading runtime DEX**:
1. Hook `JNI_ACE_ProcessCommand` (libanort+0x1362A0) — drop the call.
2. Hook `ACE_ResolveDynFunc` (libanort+0x136650) — return NULL for `_ZN3art7DexFile*` symbols.
3. Hook `dlsym()` to filter the resolution.

We don't currently do any of these. Our existing bypass works because:
- We don't actually trigger the Java→native command path. (No game code we control sends "process_command(23/24/25)" to ACE.)
- Even if ACE loads internal Java detection, our Tier 4 (drop scan results) neutralizes it before it can fire.

## Specifications of the call

The Java side calls (via the registered native method):

```java
// Java (from inside the game)
Native.processCommand(jstring jsonOrCommand, jint type);
// type = 23 → query
// type = 24/25 → execute (load DEX)
```

Native side dispatches to `ACE_ResolveDynFunc(libart.so, "art::DexFile::Open" or similar)` and invokes it with the byte buffer.

## The location string passed in

`art::DexFile::Open` takes a `std::string& location` parameter — typically a path-like identifier for the loaded DEX. ACE uses `qword_1A8268` (the session context global) as a session identifier, so loaded DEX files are tagged with the session.

## Cross-version compatibility

ACE has 6 different symbols because:
- 32-bit Android (Android 7-): `j` (uint32_t) for length params
- 64-bit Android (Android 8+): `m` (uint64_t/size_t) for length params
- Sub-variants for `OatDexFile*` vs `OatFile*` parameter (different Android versions)

ACE tries each variant until `dlsym` returns non-null, picking the right one for the running OS.

## Why this is alarming

This is essentially a **persistent backdoor**. Tencent ACE can:
- Push new Java code at runtime without user knowledge
- Bypass app review on Google Play
- Bypass any user-level monitoring (only kernel-level can detect it)

For competitive gaming this is "for anti-cheat updates", which is reasonable. But the same mechanism could push:
- Spyware
- Crash payloads
- Unauthorized data collection

There's no legitimate reason this couldn't have been done via standard Android update mechanisms.

## To-do

- Hook the dyn-resolved function pointer in REPL bridge to log every DEX load (path, size, checksum)
- Capture a sample of the DEX bytes ACE loads and decompile to see what Java detection code it adds
- Determine the cadence — does ACE load DEX every session? On server-push? On detection threshold?
- Cross-reference with the 6 JNI methods to know exact entry conditions
