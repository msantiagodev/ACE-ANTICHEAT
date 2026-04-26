# THE Other VM — libanort's Bytecode Sandbox

## Major discovery

ACE has **TWO VMs**, not one:

1. **libanogs expression-tree VM** — AST-walker, 150 operators, used for scan rule evaluation. Documented in `13_expression_engine.md`.
2. **libanort bytecode VM** — 32-bit instruction stream, 64KB memory, opcode-dispatch. Used to load and run downloaded modules from `ob_*.zip`. **This document.**

The two VMs run independently. The bytecode VM (libanort) is the *outer* layer that runs whatever code is downloaded; the expression-tree VM (libanogs) is one of the *programs* it can run.

## How an ob_*.zip is loaded

Pipeline (entry point: `ace_init_core_v4_9_30_24277_oversea`):

```
ACE_GetSingleton_JNICache + ACE_ConfigUpdateFromServer
        │     downloads ob_*.zip from CDN
        ▼
ACE_GetSingleton_ConfigStore + ACE_LoadSignedConfig
        │     stores it
        ▼
sub_137C2C → sub_137CC0 (ACE_ZipExtractAndProcess wrapper)
        │
        ▼
ACE_ZipArchiveExtract_2(data, len, key, &buffer)
        │     decrypts the ZIP using key (sub_145948() returns the key)
        ▼
sub_1372FC (the parser)
        │     for each entry in extracted ZIP:
        │     - read length-prefixed name
        │     - read length-prefixed encrypted body
        │     - decrypt body with S-box: body[i] = sbox[body[i] ^ 0x23]
        │     - check name against ace_DecryptString(11309) filter
        │     - call ACE_VMModuleLoad to register
        │     - call ACE_VMModuleListPrepend to add to module list
        ▼
ACE_VMExecutionDriver(module_list)
        │     loop:
        │       ACE_VMRunModules(list, &count, 150000)
        │       if count > 1000001: sleep 800ms
        │       yield every 10000 iterations
        ▼
ACE_VMRunModules → ACE_VMExecuteLoop (per module)
        │     dispatches opcodes
        ▼
[Detection code runs in sandboxed module]
```

## Wire format (deduced)

```
[length:4 bytes][name:N bytes][length:4 bytes][encrypted_data:M bytes]
[length:4 bytes][name:N bytes][length:4 bytes][encrypted_data:M bytes]
...
[length:0 = end of stream]
```

The data is decrypted byte-by-byte using:

```c
// 256-byte S-box at libanort+0x1747C9 (extracted)
const unsigned char ACE_SBOX[256] = {
    0xab,0xe4,0x7f,0xa8,0x46,0x24,0x58,0x9d, 0x7d,0xb8,0xf0,0x91,0x08,0x13,0x80,0x60,
    0xd6,0x97,0xff,0x15,0x69,0xf8,0xc2,0xd9, 0x30,0x29,0x16,0xee,0x3e,0xbb,0x83,0xf9,
    0x47,0xcd,0x62,0x1d,0x4e,0xf4,0x78,0x23, 0x64,0x8f,0xa7,0x74,0x70,0x96,0xa5,0x75,
    0xd3,0x39,0x34,0x36,0x17,0x73,0x92,0x07, 0x3b,0xc1,0x0e,0xfa,0x32,0x0f,0x03,0xda,
    0xbe,0x31,0x67,0x2a,0xaf,0xef,0x84,0x88, 0xe5,0xe7,0xd1,0x79,0xe9,0x76,0x0c,0xcc,
    0xc4,0x25,0xa2,0x01,0x7b,0xbf,0x6a,0xf1, 0x2e,0x6d,0xc9,0x27,0x7a,0x48,0x3a,0x9a,
    0x55,0x5b,0xfe,0x3c,0x0b,0xae,0x89,0x6c, 0x54,0x7c,0x2c,0x42,0x90,0x9b,0x1a,0x8d,
    0xca,0x5f,0x33,0x4c,0x61,0x35,0xaa,0x2b, 0xa4,0xbc,0x26,0xdf,0x85,0xb5,0x4f,0xde,
    0x0a,0xe8,0x06,0x40,0x50,0x9f,0x19,0xed, 0xb0,0xf2,0xec,0x65,0x51,0xba,0xc8,0x57,
    0x04,0x4d,0xd7,0xa0,0x8a,0x56,0xea,0xf5, 0x5c,0x71,0x44,0x45,0x77,0xac,0x93,0x12,
    0x00,0xe0,0xc3,0xc5,0xbd,0xad,0x6f,0xfc, 0x18,0xb1,0x0d,0x1b,0x28,0x95,0xf3,0xc7,
    0x72,0x37,0x8b,0x87,0x1f,0x6e,0xb9,0xb7, 0x66,0xd0,0xd2,0xd4,0xc6,0x21,0x3f,0x2d,
    0x1e,0xfd,0xf6,0xdc,0x9e,0x8c,0xe2,0x5d, 0x86,0x10,0x1c,0xa1,0xc0,0x09,0x7e,0x4a,
    0x94,0x05,0xd8,0xb4,0x99,0x52,0xa6,0x49, 0x11,0x98,0x43,0xa9,0x81,0xce,0x63,0x22,
    0x9c,0xb3,0xf7,0x14,0xdd,0xe1,0x8e,0x68, 0x59,0xe6,0xdb,0x38,0xb2,0x53,0x5e,0xeb,
    0xd5,0xcb,0x4b,0x02,0x82,0x5a,0xa3,0x20, 0x41,0xb6,0x2f,0xfb,0x3d,0xcf,0xe3,0x6b
};

void ace_decrypt_module_body(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        data[i] = ACE_SBOX[data[i] ^ 0x23];
}
```

## VM Module struct (0xE8 = 232 bytes)

After `ACE_VMModuleLoad`, the module struct contains:

| Offset | Size | Field | Notes |
|---|---|---|---|
| `+0` | 8 | parent context | a6 (the big context passed in) |
| `+240` | 8 | program counter prev | -1 = no prev |
| `+256` | 8 | stack base | base of 64KB VM RAM + 65472 |
| `+264` | 8 | program counter | initial PC from sub_138F94 |
| `+276` | 4 | running magic | 0x20218923 (539100707) |
| `+280` | 4 | branch flag | non-zero = branch taken |
| `+284` | 4 | jump flag | non-zero = jump occurred |
| `+288` | 4 | halt flag | non-zero = halt VM |
| `+296` | 4 | instruction count | reset each batch, capped by limit arg |
| `+300` | 4 | total instruction count | accumulated across batches |
| `+376` | 8 | code pointer | byte stream of instructions |
| `+384` | 8 | code size | length |
| `+392` | 1 | active flag | 1 = module is currently running |
| `+393` | 1 | special-name flag | 1 if module name == DecryptString(11285)/(11259) match |
| `+400` | 8 | parser context | the original v45 parser (0x40 bytes) |
| `+408` | 8 | a4 (the key) | passed-through ZIP key |
| `+416` | 8 | source data ptr | original encrypted module bytes |

## Instruction execution loop (`ACE_VMExecuteLoop`, libanort+0x137984)

```c
ACE_VMExecuteLoop(module, instr_limit) {
    code = module.+376;                        // start of instruction stream
    instr_count = 0;
    func_table = sub_138F8C(module.+400);      // 256-entry func table from parser
    pc = module.+264;
    module.+392 = 1;                            // mark active
    
    while (pc != -1) {
        module.+288 = 1;                        // assume halt
        opcode_byte = *(uint32_t*)(code + (pc>>2)*4);  // read 4-byte instruction
        handler = func_table[(pc>>2) * 8];     // look up handler in table
        handler(opcode_byte, module);          // execute (may write to module.+264)
        
        if (module.+288)                       // halt requested
            break;
        
        new_pc = module.+264;
        if (new_pc == pc) {                     // no jump
            pc += 4;                            // advance instruction
            module.+264 = pc;
            if (module.+280) break;             // branch was set, but pc same? exit
        } else {
            // pc was modified by handler — jump occurred
            module.+296++;                      // count instruction
            if (++instr_count > instr_limit && !module.+284)
                break;                          // budget exceeded
            pc = new_pc;
            if (module.+280) break;             // branch flag set
        }
    }
    module.+300 += module.+296;                 // accumulate total
    
    if (pc != -1) ACE_VMReportError(module, instruction_at_pc);
    return 0;
}
```

So the VM:
1. Indexes a function table via `pc>>2` (each handler entry = 8 bytes).
2. Each handler reads its operand (the 4-byte instruction word at `code + (pc>>2)*4`).
3. The handler can mutate `module.+264` (PC), set the halt flag at `+288`, set branch at `+280`, set jump at `+284`.
4. If the handler doesn't modify PC, the loop auto-advances by 4.
5. Per-call instruction budget limits how long the VM runs in one slice.

## What can the bytecode VM do?

Based on the function-table dispatch architecture, **everything**: read/write memory, system calls, network I/O, and crucially — invoke libanogs functions. The downloaded modules can essentially do anything ACE can do natively.

This is the wide-open design choice that makes ACE so flexible: server pushes new bytecode → device parses + runs it → instant new detection or counter-detection capability without an SDK update.

## Throttle and idle behavior

`ACE_VMExecutionDriver` runs a tight loop:

```c
while (module_list_not_empty) {
    if (counter == 10000) { yield(1); counter = 0; }
    counter++;
    
    int processed = 0;
    ACE_VMRunModules(list, &processed, 150000);   // budget: 150,000 instructions
    
    if (processed > 1000001)
        sleep_us(800000);   // 800ms cooldown if heavy load
}
```

So:
- Each batch processes up to 150,000 instructions
- If the batch crosses 1M instructions, sleep 800ms (anti-tracing throttle)
- Yield (sched_yield) every 10,000 iterations regardless

## Bypass implications

Multiple kill points:

1. **`ACE_VMExecutionDriver`** (libanort+0x137804) — replace with `RET 0`. Stops the entire downloaded-module pipeline. Cleanest single point.
2. **`ACE_ZipExtractAndProcess`** (libanort+0x137204) — return -1. Modules never load.
3. **`ACE_ConfigUpdateFromServer`** (libanort+0x12CE98) — neutralize. ACE never downloads ZIPs.
4. **`g_anort_init_path_flag` (`dword_17115C`)** — set to 1 to force the alt code path that doesn't trigger downloads.
5. **Network DNS block** — `*.anticheatexpert.com` blocked at iptables/DNS level.
6. **Hook the S-box decrypt** — corrupt the decrypted bytes so module load always fails the magic check.
7. **`ACE_VMModuleLoad`** — return 0xFFFFFFFF unconditionally.

The cleanest combo: **#3 + #5** (disable update + network block). With both, the only rules ACE runs are the baked-in ones in libanogs.

## Cross-VM relationship

```
[CDN: ob_*.zip downloaded]
      │
      ▼
[libanort bytecode VM] ← decrypts, loads, runs modules
      │
      │ (one of the modules calls into libanogs)
      ▼
[libanogs expression-tree VM] ← evaluates AST-based scan rules
      │
      ▼
[Detection result] → TDM report → server
```

The **libanort bytecode VM is the outer container**. It runs the downloaded modules, which in turn invoke specific scan rules in the libanogs expression-tree VM. So defeating the libanort VM defeats *everything* that's downloaded; defeating libanogs defeats the scan logic.

For maximum coverage, hook BOTH:
- libanort: `ACE_VMExecutionDriver` (no modules ever execute)
- libanogs: `ace_run_scan_rules` (no scan rules evaluate)

## To-do

- Decode the function table at `sub_138F8C(parser+400)` — 256-entry handler table for the bytecode VM opcodes.
- Reverse the per-opcode handlers in `func_table[0..255]`.
- Capture an actual ob_*.zip from the device, decrypt with our S-box, study the wire format empirically.
- Map ACE_VMReportError to find what happens when the VM faults.
