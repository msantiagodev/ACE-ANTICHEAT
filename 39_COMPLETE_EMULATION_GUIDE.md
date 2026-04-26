# Building Your Own ACE Emulator — Complete Step-by-Step Guide

This guide gives you everything you need to write your own ACE-compatible emulator. With this, you could:
- Decode `ob_*.zip` modules on a workstation (no device needed)
- Test detection rules without running on a phone
- Build a fuzzer for ACE bypass
- Just understand the system completely

## Pre-requisites

You need:
- A copy of `libanort.so` (extract from any Tencent game APK)
- The 256-byte S-box (we already have it — see Part 1 below)
- The opcode dispatch table (we have it — see Part 2 below)
- A way to compute encrypted-string keys (already documented in `01_string_decryption.md`)

That's it. Everything you need is in the files we've already documented.

---

## Part 1: The S-Box (already extracted)

This is the 256-byte substitution box ACE uses for module-body decryption:

```python
ACE_SBOX = bytes([
    0xab, 0xe4, 0x7f, 0xa8, 0x46, 0x24, 0x58, 0x9d,
    0x7d, 0xb8, 0xf0, 0x91, 0x08, 0x13, 0x80, 0x60,
    0xd6, 0x97, 0xff, 0x15, 0x69, 0xf8, 0xc2, 0xd9,
    0x30, 0x29, 0x16, 0xee, 0x3e, 0xbb, 0x83, 0xf9,
    0x47, 0xcd, 0x62, 0x1d, 0x4e, 0xf4, 0x78, 0x23,
    0x64, 0x8f, 0xa7, 0x74, 0x70, 0x96, 0xa5, 0x75,
    0xd3, 0x39, 0x34, 0x36, 0x17, 0x73, 0x92, 0x07,
    0x3b, 0xc1, 0x0e, 0xfa, 0x32, 0x0f, 0x03, 0xda,
    0xbe, 0x31, 0x67, 0x2a, 0xaf, 0xef, 0x84, 0x88,
    0xe5, 0xe7, 0xd1, 0x79, 0xe9, 0x76, 0x0c, 0xcc,
    0xc4, 0x25, 0xa2, 0x01, 0x7b, 0xbf, 0x6a, 0xf1,
    0x2e, 0x6d, 0xc9, 0x27, 0x7a, 0x48, 0x3a, 0x9a,
    0x55, 0x5b, 0xfe, 0x3c, 0x0b, 0xae, 0x89, 0x6c,
    0x54, 0x7c, 0x2c, 0x42, 0x90, 0x9b, 0x1a, 0x8d,
    0xca, 0x5f, 0x33, 0x4c, 0x61, 0x35, 0xaa, 0x2b,
    0xa4, 0xbc, 0x26, 0xdf, 0x85, 0xb5, 0x4f, 0xde,
    0x0a, 0xe8, 0x06, 0x40, 0x50, 0x9f, 0x19, 0xed,
    0xb0, 0xf2, 0xec, 0x65, 0x51, 0xba, 0xc8, 0x57,
    0x04, 0x4d, 0xd7, 0xa0, 0x8a, 0x56, 0xea, 0xf5,
    0x5c, 0x71, 0x44, 0x45, 0x77, 0xac, 0x93, 0x12,
    0x00, 0xe0, 0xc3, 0xc5, 0xbd, 0xad, 0x6f, 0xfc,
    0x18, 0xb1, 0x0d, 0x1b, 0x28, 0x95, 0xf3, 0xc7,
    0x72, 0x37, 0x8b, 0x87, 0x1f, 0x6e, 0xb9, 0xb7,
    0x66, 0xd0, 0xd2, 0xd4, 0xc6, 0x21, 0x3f, 0x2d,
    0x1e, 0xfd, 0xf6, 0xdc, 0x9e, 0x8c, 0xe2, 0x5d,
    0x86, 0x10, 0x1c, 0xa1, 0xc0, 0x09, 0x7e, 0x4a,
    0x94, 0x05, 0xd8, 0xb4, 0x99, 0x52, 0xa6, 0x49,
    0x11, 0x98, 0x43, 0xa9, 0x81, 0xce, 0x63, 0x22,
    0x9c, 0xb3, 0xf7, 0x14, 0xdd, 0xe1, 0x8e, 0x68,
    0x59, 0xe6, 0xdb, 0x38, 0xb2, 0x53, 0x5e, 0xeb,
    0xd5, 0xcb, 0x4b, 0x02, 0x82, 0x5a, 0xa3, 0x20,
    0x41, 0xb6, 0x2f, 0xfb, 0x3d, 0xcf, 0xe3, 0x6b
])

def ace_decrypt_module_body(data: bytes) -> bytes:
    return bytes(ACE_SBOX[b ^ 0x23] for b in data)
```

## Part 2: ZIP Wire Format

Each `ob_*.zip` extracted file is a series of length-prefixed entries:

```
[length:4 bytes][name:N bytes][length:4 bytes][encrypted_body:M bytes]
[length:4 bytes][name:N bytes][length:4 bytes][encrypted_body:M bytes]
...
```

The `name` is plaintext UTF-8. The `encrypted_body` must be S-box decrypted before parsing.

## Part 3: Module File Format (.img)

After S-box decryption, each module body is a `.img` file:

```
[magic:           4 bytes]    must be 0x20218923
[version:         4 bytes]    must be 193  
[type_id:         4 bytes]    must be 148 (matches opcode count)
[func_count:      4 bytes]    bytes_in_code / 4
[unk1, unk2:      8 bytes]
[256 × {opcode_id:uint16, padding:uint16}]   ← maps each instruction to a handler
[v14 × RBT_entry]  ← red-black tree of (key, value) pairs (the symbol table)
[v15 × {string, key1:dword, key2:dword}]   ← string-to-int mapping
[v16 × {2 dwords each}]    ← misc
[length:4 bytes][code: N×4 bytes]    ← the actual instructions
[end magic: 4 bytes]    must be 0x20218923
```

The instruction stream is N 4-byte instructions. Each instruction has its own handler from the opcode_id table.

## Part 4: VM Execution Loop (psuedocode)

```python
def execute_vm(module):
    pc = module.initial_pc
    while pc != -1:
        i = pc >> 2
        instruction = module.code[i]   # 4-byte word
        opcode_id = module.func_table[i]   # uint16
        handler = OPCODE_HANDLERS[opcode_id]   # one of 148
        
        if handler is None:
            raise VMError(f"Unsupported opcode {opcode_id}")
        
        old_pc = pc
        handler(instruction, module)   # may modify module.pc
        
        if module.halt:
            break
        
        if module.pc == old_pc:
            pc += 4
            module.pc = pc
            if module.branch_taken:
                break
        else:
            pc = module.pc
            if module.branch_taken or module.jump_taken:
                break
        
        module.insn_count += 1
        if module.insn_count > LIMIT:
            break
```

## Part 5: Opcode Handlers (31 of 148 documented)

| Opcode | Handler | Equivalent ARM64 |
|---|---|---|
| 8 | `ace_vm_op_add_imm` | `ADD Rd, Rn, #imm12 [LSL #12]` |
| 9 | `ace_vm_op_add_shifted_reg` | `ADD Rd, Rn, Rm, shift` |
| 10 | `ace_vm_op_adds_imm` | `ADDS Rd, Rn, #imm12 [LSL #12]` (with NZCV) |
| 11 | `ace_vm_op_adds_shifted_reg` | `ADDS Rd, Rn, Rm, shift` (with NZCV) |
| 13 | `ace_vm_op_adrp` | `ADRP Rd, #imm21` |
| 14 | `ace_vm_op_and_imm` | `AND Rd, Rn, #bitmask_imm` |
| 15 | `ace_vm_op_and_shifted_reg` | `AND Rd, Rn, Rm, shift` |
| 16 | `ace_vm_op_bfm` | `BFM/UBFM/SBFM` |
| 18 | `ace_vm_op_bic_shifted_reg` | `BIC Rd, Rn, Rm, shift` |
| 19 | `ace_vm_op_branch_imm26` | `B/BL #imm26` (with native bridge) |
| 22 | `ace_vm_op_eor_imm` | `EOR Rd, Rn, #bitmask_imm` |
| 23 | `ace_vm_op_ldrsw` | `LDRSW Rt, [Rn, ...]` |
| 24 | `ace_vm_op_ldr_register` | `LDR Rt, [Rn, Rm, shift]` |
| 25 | `ace_vm_op_orn_shifted_reg` | `ORN Rd, Rn, Rm, shift` |
| 26 | `ace_vm_op_subs_extended_reg` | `SUBS Rd, Rn, Rm, ext` |
| 27 | `ace_vm_op_and_imm_extr` | `AND with ROR variant` |
| 28 | `ace_vm_op_rev` | `REV Rd, Rn` |
| 29 | `ace_vm_op_lsl_register` | `LSL Rd, Rn, Rm` |
| 30 | `ace_vm_op_madd` | `MADD Rd, Rn, Rm, Ra` |
| 31 | `ace_vm_op_orr_imm` | `ORR Rd, Rn, #bitmask` |
| 32 | `ace_vm_op_orr_shifted_reg` | `ORR Rd, Rn, Rm, shift` |
| 33 | `ace_vm_op_ror_register` | `ROR Rd, Rn, Rm` |
| 34 | `ace_vm_op_div` | `SDIV/UDIV Rd, Rn, Rm` |
| 35 | `ace_vm_op_subs_imm` | `SUBS Rd, Rn, #imm12` |
| 36 | `ace_vm_op_subs_shifted_reg` | `SUBS Rd, Rn, Rm, shift` |
| 37 | `ace_vm_op_sub_shifted_reg` | `SUB Rd, Rn, Rm, shift` |
| ... | (and more) | |

## Part 6: CPU State (Module Struct, 232 bytes)

```c
struct ace_vm_module {
    uint64_t parent_ctx;       // +0
    uint64_t reg_x[31];         // +8..+247 (x0..x30)
    uint64_t sp;                // +256
    uint64_t pc;                // +264
    uint32_t nzcv;              // +272 (N=bit31, Z=bit30, C=bit29, V=bit28)
    uint32_t running_magic;     // +276 (must equal 0x20218923 while running)
    uint32_t branch_taken;      // +280
    uint32_t jump_taken;        // +284
    uint32_t halt_flag;         // +288
    uint32_t error_flag;        // +292
    uint32_t insn_count;        // +296
    uint32_t total_count;       // +300
    uint64_t code_ptr;          // +376
    uint64_t code_size;          // +384
    uint8_t  active;             // +392
    uint8_t  is_special;         // +393
    uint64_t parser_ctx;         // +400 (the .img header struct)
    uint8_t  load_special_path;  // +297
};
```

When you access register N, you do:
```c
if (N == 31)
    return module.sp;     // SP encoding
else
    return module.reg_x[N];  // GPR
```

## Part 7: The Native Bridge (Symbol Table)

When emulated code does:

```
BL #0x48D958     // special label resolution
```

…the handler calls `ace_vm_lookup_label_pc(parser_ctx, current_pc)` which is an RB-tree lookup:
- key = current_pc (4-byte int at node offset +24)
- result = target PC (4-byte int at node offset +28)

The handler sets `module.pc = result` and saves `module.lr = current_pc + 4`.

When emulated code does:

```
B #0     // native function call
```

…the handler calls `ace_vm_lookup_native_function(parser_ctx, current_pc)` which is also an RB-tree lookup:
- key = current_pc (4-byte int)
- result = native function pointer (8-byte qword at node offset +32)

The handler invokes the native function directly with the module struct as argument, then continues at `current_pc + 4`.

So the **emulator can call native code by special branch encoding**. This is how downloaded modules invoke ACE's native API.

## Part 8: Building the Emulator

To build a working emulator:

1. Parse the `ob_*.zip` (extract length-prefixed entries)
2. Decrypt each body via S-box
3. Parse the .img header (validate magic 0x20218923)
4. Build the symbol table (RB-tree at parser+0/+16)
5. Read 256-entry opcode_id list
6. Resolve each opcode_id → handler via the documented table (Part 5)
7. Allocate 64KB VM memory + 232-byte module struct
8. Set initial PC + SP
9. Run the loop

For native bridges, you'll need to implement the opcode handlers' call-into-native paths. Some natives are just data lookups (timestamp, version), but others touch real OS resources (open files, walk /proc, mmap).

For initial development, you can:
- Stub out network operations (return success)
- Stub out file ops (return canned data for `/proc/*`)
- Stub out timestamps (return increasing values)
- Run the emulator over a captured ob_*.zip

This gives you the SAME execution path ACE takes, but on your laptop instead of a phone. You can break execution at any opcode for inspection.

## Part 9: Building a Decoder Tool

Even simpler: write a tool that just decompiles the modules.

```python
#!/usr/bin/env python3
"""
Decode an ob_*.zip module to readable form.
"""
import struct
import sys

# Insert the S-box from Part 1 here

def parse_zip(blob):
    """Parse the length-prefixed ZIP entries."""
    cursor = 0
    while cursor < len(blob):
        name_len = struct.unpack_from("<I", blob, cursor)[0]
        cursor += 4
        if name_len == 0:
            break
        name = blob[cursor:cursor+name_len].decode('utf-8', errors='replace')
        cursor += name_len
        body_len = struct.unpack_from("<I", blob, cursor)[0]
        cursor += 4
        body = blob[cursor:cursor+body_len]
        cursor += body_len
        yield name, body

def decrypt_body(encrypted_body):
    return bytes(ACE_SBOX[b ^ 0x23] for b in encrypted_body)

def parse_img(decrypted):
    if struct.unpack_from("<I", decrypted, 0)[0] != 0x20218923:
        raise ValueError("Bad magic")
    
    # Skip header
    cursor = 16
    
    # Read 256 opcode IDs (uint16 + uint16 padding)
    opcode_ids = []
    for _ in range(256):
        oid = struct.unpack_from("<H", decrypted, cursor)[0]
        cursor += 4  # uint16 + uint16 padding
        opcode_ids.append(oid)
    
    # ... (rest follows the format from Part 3)
    
    return {"opcode_ids": opcode_ids, ...}

def main():
    with open(sys.argv[1], "rb") as f:
        zip_data = f.read()
    
    for name, body in parse_zip(zip_data):
        print(f"=== {name} ===")
        decrypted = decrypt_body(body)
        if name.endswith(".img"):
            module = parse_img(decrypted)
            print(f"  Opcodes: {module['opcode_ids']}")

if __name__ == "__main__":
    main()
```

## Part 10: Running ACE Reduced Emulation

To verify your emulator works:

1. Set breakpoints at OPCODE_HANDLERS[i] for each i.
2. Run a captured `ob_*.zip` through it.
3. Check that the same PC sequence runs as on a real device.
4. Compare register values at each step.

If your emulator matches the real device's execution, you can use it for:
- Testing bypass without flashing the device
- Fuzzing detection rules
- Reverse-engineering server-pushed updates

## Part 11: Limitations

You can't fully emulate without:
- The native function implementations (you'd need to stub or proxy them to a real device)
- The actual server config (you can capture one)
- The hook descriptor registry state (you can mock it)
- Timing/clock state (just stub with monotonic counter)

For most reverse-engineering work, stubs are enough.

## Part 12: References

- `21_libanort_bytecode_vm.md` - Original VM discovery
- `22_libanort_arm64_emulator.md` - ARM64 emulator details
- `36_install_strategies.md` - Trampoline strategies
- `37_install_hook_callers.md` - 6 hook entry points
- `01_string_decryption.md` - The 100-decoder family
- `38_detection_inventory.md` - Every string ACE looks for

## Final Notes

This is the "child guide" for emulation. Anyone with intermediate Python skills can build a functional ACE emulator from the documents above. The hard work was reverse-engineering the system; the emulation is mechanical once you know the structure.

Total time to write a working stub emulator: ~2-3 days for an experienced developer.
Total time to fully integrate native bridges: ~1-2 weeks (depends on which functions are needed).

Good luck!
