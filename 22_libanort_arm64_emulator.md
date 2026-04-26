# THE Real Truth: libanort Has a Full ARM64 Emulator

## The discovery

What I previously called the "libanort bytecode VM" is actually a **complete userspace ARM64 emulator**. The 148 opcode handlers in `g_ace_vm_opcode_table` (libanort+0x164AF0) each emulate a specific ARM64 instruction class.

The downloaded `ob_*.zip` modules contain pre-decoded ARM64 code: each instruction is paired with its handler index, so dispatch at runtime is O(1) (no decode needed).

## Module's CPU state layout

The module struct (allocated to 0xE8 bytes by ACE_VMModuleLoad) contains a complete ARM64 register file:

| Offset | Field | ARM64 register equivalent |
|---|---|---|
| `+0..+247` | `x0..x30` | 31 GPR registers (8 bytes each) |
| `+256` | `SP` | Stack pointer (special value when Rn/Rd == 31) |
| `+264` | `PC` | Program counter |
| `+272` | `NZCV` | Flags register (bit31=N, bit30=Z, bit29=C, bit28=V) |
| `+276` | `running_magic` | 0x20218923 = "active module" |
| `+280` | `branch_taken` | 1 = branch taken this insn |
| `+284` | `jump_taken` | 1 = jump occurred this insn |
| `+288` | `halt_flag` | 1 = stop execution |
| `+296` | `insn_count` | per-batch instruction count |
| `+300` | `total_count` | accumulated lifetime |
| `+376` | `code` | instruction stream |
| `+384` | `code_size` | bytes |
| `+392` | `active` | 1 = currently executing |
| `+393` | `is_special_module` | 1 if module name matched DecryptString(11285)/(11259) |
| `+400` | `parser_ctx` | parser context (has func table at +104) |

## Confirmed instruction-class handlers (iteration 19 expanded)

These were verified by decompiling their decode logic and matching against ARM64 spec:

| Handler | Address | Decoded Instruction | Notes |
|---|---|---|---|
| `ace_vm_op_rev` | 0x141260 | `REV32 / REV` | byte-swap 32 or 64-bit |
| `ace_vm_op_add_imm` | 0x1413BC | `ADD Rd, Rn, #imm12 [LSL #12]` | 32/64-bit, optional shift |
| `ace_vm_op_add_shifted_reg` | 0x141430 | `ADD Rd, Rn, Rm, shift #amount` | LSL/LSR/ASR/ROR ×6 |
| `ace_vm_op_adds_imm` | 0x141510 | `ADDS Rd, Rn, #imm12 [LSL #12]` | sets NZCV |
| `ace_vm_op_adds_shifted_reg` | 0x141610 | `ADDS Rd, Rn, Rm, shift #amount` | sets NZCV |
| `ace_vm_op_adrp` | 0x1417E0 | `ADRP Rd, label` | 21-bit signed offset, page-aligned |
| `ace_vm_op_and_imm` | 0x141B0C | `AND Rd, Rn, #bitmask_imm` | bitmask immediate (immr/imms decode) |
| `ace_vm_op_and_shifted_reg` | 0x141D5C | `AND Rd, Rn, Rm, shift` | sets NZCV |
| `ace_vm_op_bfm` | 0x141F44 | `BFM/UBFM/SBFM` (BitField Move) | generic for UBFX/SBFX/BFI/etc. |
| `ace_vm_op_bic_shifted_reg` | 0x142258 | `BIC Rd, Rn, Rm, shift` | bit-clear (AND NOT) |
| `ace_vm_op_branch_imm26` | 0x142314 | `B / BL #imm26` | unconditional branch, 26-bit signed offset × 4 |
| `ace_vm_op_eor_imm` | 0x142A74 | `EOR Rd, Rn, #bitmask_imm` | XOR with bitmask immediate |
| `ace_vm_op_ldrsw` | 0x143598 | `LDRSW Rt, [Rn, ...]` | load signed word, sign-extend to 64 |
| `ace_vm_op_orn_shifted_reg` | 0x143B28 | `ORN Rd, Rn, Rm, shift` | OR-NOT with shifted register |
| `ace_vm_op_subs_extended_reg` | 0x1449E4 | `SUBS Rd, Rn, Rm, ext #shift` | with UXT/SXT extension |
| `ace_vm_op_and_imm_extr` | 0x145158 | `AND/EXTR` variant | rotated AND-immediate |

The B/BL handler at `ace_vm_op_branch_imm26` is particularly interesting:

```c
// Decoded immediate: bits[25:0] sign-extended × 4
v4 = (instr & 0x03FFFFFC) | (sign_extend_bit27 ? 0xF0000000 : 0);
if (v4 == 0x48D958) {     // special opcode = "BL into native"
    target = sub_1390E0(parser_ctx, current_pc);  // resolve native function pointer
    if (!target) return;
    module.X30 = current_pc + 4;       // save return addr (BL semantic)
    module.PC = target;
} else if (v4 == 0) {     // plain B
    func = sub_139118(parser_ctx, current_pc);    // lookup native callback
    func(module);                                  // execute it
    module.+240 = current_pc + 4;
}
```

This means **the emulator can call native code** via two mechanisms:
1. The "BL-into-native" pattern (special opcode 0x48D958) — switches from emulated to native execution.
2. The plain `B` handler — looks up a callback function in the parser context and invokes it directly with the module struct.

This is the **bridge** between emulated downloaded code and native ACE host functions. Specific opcodes can effectively call into ACE's native API surface, bypassing the emulator's sandbox model.

## Updated confirmed-handler count (iteration 26)

We've now mapped **31 of 148** opcode handlers (~21% coverage):

| Class | Handlers |
|---|---|
| Arithmetic | ADD-imm/shifted, ADDS-imm/shifted, ADRP, REV |
| Logical | AND-imm/shifted, EOR-imm, ORR-imm/shifted, BIC-shifted, ORN-shifted |
| BitField | BFM, BFI, AND-extr |
| Sub/Compare | SUBS-extended-reg |
| Mul/Div | MADD, DIV (signed/unsigned) |
| Shift | LSL-register, ROR-register |
| Conditional | CSNEG (CSEL/CSINC/CSINV variant) |
| Memory load | LDRSW, LDR-register, LDRB-register, LDRH-immediate |
| Memory store | STR-immediate, STR-register, STRH, STRH-immediate, STRB |
| Pair | STP |
| Branch | B/BL-imm26 (with native-bridge opcode 0x48D958) |

Still TBD (~117 handlers): MOV/MOVK/MOVN/MOVZ, SUB variants, SXT/UXT, LSR/ASR, MUL/UMUL/SMUL/MSUB, CSEL/CSINC/CSINV, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET, LDP variants, system instructions, possibly SVC bridge.

The flag-update arithmetic in ADDS handlers exactly matches ARM's "Rd = Rn + op2; N=Rd[31]; Z=(Rd==0); C=carry-out; V=signed-overflow" semantics.

## Decode pattern (universal across handlers)

Every handler uses the same encoding-bit-extraction pattern:

```c
Rd      = (insn >>  0) & 0x1F;     // destination
Rn      = (insn >>  5) & 0x1F;     // source 1
Rm      = (insn >> 16) & 0x1F;     // source 2
imm     = (insn >> 10) & 0xFFF;    // 12-bit immediate
shift   = (insn >> 22) & 0x3;      // shift type (LSL/LSR/ASR/ROR)
amount  = (insn >> 10) & 0x3F;     // 6-bit shift amount
sf      = (insn >> 31) & 0x1;      // size flag (32/64-bit)
```

Special-case: `Rn == 31` or `Rd == 31` means SP — the handler reads/writes module+256 instead of the GPR file. (In some opcodes, register 31 means XZR/WZR — return zero. The interpretation depends on the specific instruction.)

## Why ACE has its own ARM64 emulator

This is the genius of the design. By emulating ARM64 in userspace, ACE:

1. **Hides detection logic from static analysis.** The actual scan code is shipped as encrypted bytes in `ob_*.zip` and only ever runs in the emulator — never as native ARM code on the CPU.
2. **Sidesteps anti-debugging tools.** Hooks on real CPU instructions (e.g., breakpoints on `dlopen`) don't fire when the same instruction runs inside the emulator.
3. **Enables sandboxing.** The emulator can mediate every memory access, syscall, and library call. Detection logic can be granted privileges that real code doesn't get.
4. **Allows runtime updates.** Server pushes new emulated code → device runs new detection without an SDK update.
5. **Constrains the attack surface.** A jailbreak of the emulator only escapes into ACE's sandboxed view of the world, not direct kernel access.

## How execution works

1. Server pushes `ob_cdn2.zip` (encrypted with per-install key)
2. `ACE_ConfigUpdateFromServer` downloads it
3. `ACE_LoadSignedConfig` verifies signature
4. `ACE_ZipExtractAndProcess` decompresses
5. `ace_parse_module_zip_entries` extracts each module entry, decrypts body via S-box
6. `ACE_VMModuleLoad` parses module:
   - Validates magic 0x20218923
   - Reads N×4 bytes of code
   - Reads N×8 bytes of `(opcode_id : uint16, padding : uint16)` from func table
   - Resolves opcode IDs via `ace_vm_resolve_opcode` to handler pointers
   - Stores `code` at module+376, `func_table` at parser+104
7. Module added to module list
8. `ACE_VMExecutionDriver` repeatedly calls `ACE_VMRunModules`
9. `ACE_VMRunModules` walks list, runs each non-completed module
10. `ACE_VMExecuteLoop`:
    - `i = pc >> 2`
    - `handler = func_table[i]`
    - `insn = code[i*4]` (or `code + 4*i`)
    - `handler(insn, module_struct)` — emulates the instruction
    - Handler updates module's PC, registers, flags
    - Loop continues until halt or budget exceeded

## What about non-arithmetic instructions?

We've only confirmed arithmetic so far (148 handlers total). The other handler classes (need decompilation) likely include:

- **Memory:** LDR/STR (immediate, register, pre/post-indexed, exclusive)
- **Bitwise:** AND/ORR/EOR (imm + shifted reg + shifted with flags)
- **Compare:** CMP (alias for SUBS), CMN (alias for ADDS), TST
- **Branch:** B, B.cond, BL, BR, BLR, RET
- **Conditional:** CSEL, CSINC, CSINV, CSNEG
- **Bit manipulation:** BFI, BFM, BFX, UBFM, SBFM
- **Move:** MOV, MOVK, MOVZ, MOVN
- **Sub:** SUB/SUBS variants
- **Shift:** LSL/LSR/ASR/ROR (the helper at 0x14557C)
- **Multiply:** MUL, UMUL, SMUL, MSUB, MADD
- **Divide:** UDIV, SDIV
- **System:** MRS, MSR, NOP, HINT, ISB, DSB, DMB
- **Compare-branch:** CBZ, CBNZ, TBZ, TBNZ
- **Possibly syscall/SVC:** for downstream calls

148 opcodes total = roughly equivalent to a stripped ARMv8.0 base ISA.

## What about loads/stores into native memory?

The emulator has access to the full 64KB VM memory at module+376 (`code` pointer). When the emulated code does `LDR X0, [X1]`, the LDR handler reads from `module+376[X1 register value]`, NOT from the host process's actual memory.

So the emulator runs in **its own virtual address space**. It can't directly read the host process's data unless ACE's emulator handlers explicitly bridge it (e.g., a special opcode that means "read host memory at this address" or "call host function X").

This makes the emulator effectively a sandbox: the downloaded code can do whatever ARM64 stuff it wants in its 64KB RAM, but every "outside" interaction must go through an explicitly-provided opcode bridge.

## Bypass implications

We have two complementary attacks:

1. **Hook the dispatch loop** (`ACE_VMExecuteLoop` at libanort+0x137984). Make every emulated instruction a no-op. The downloaded code "runs" but does nothing.

2. **Hook the opcode resolver** (`ace_vm_resolve_opcode` at libanort+0x141094). Make every opcode resolve to NULL. Module load fails because every instruction lands on a NULL handler.

3. **Hook ACE_VMExecutionDriver** (Tier 8 in our Main.cpp) — the outer scheduler. Already deployed.

Each is a single-point kill. Tier 8 is the cleanest because it's at the highest level.

## To-do (next iteration)

- Decompile every one of the 148 handlers and build a complete instruction table.
- Find the "bridge" opcodes that let the emulated code call host functions.
- Identify any "dangerous" opcodes (memory read of host process, syscall passthrough, dlopen).
- Build a custom emulator script in Python that can decode `ob_*.zip` modules and disassemble them to ARM64 mnemonics — would let us read what ACE actually checks.
- Look for the magic indicating "syscall passthrough" handler — likely an SVC emulator.
