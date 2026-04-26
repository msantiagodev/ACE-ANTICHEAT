# ARM64 Emulator Handler Extension — Iteration 41

This doc extends `22_libanort_arm64_emulator.md` with newly confirmed handlers from three mapping passes. **Coverage now: 80+ of 148 (~54%) opcode handlers documented.**

## CRITICAL FINDING — opcode 1 = SVC syscall bridge (see `48_svc_syscall_bridge.md`)

`vfunc_1_1411dc` (libanort+0x1411DC) — opcode 1 — is the **SVC #imm16** handler, which is the kernel syscall bridge. It calls `syscall(sysno, x0..x6)` from libc, allowing emulated ACE detection code to invoke any kernel syscall directly. This is the **single chokepoint** for all emulator → kernel access. **Already neutralized** by Tier 1 (ANORT_PATCHES[3] = 0x1411DC patched to MOV X0,#0;RET).

## New handlers — confirmed via decompilation

| Handler | Address | Decoded Instruction | Notes |
|---|---|---|---|
| `ace_vm_op_sub_imm` | 0x144AC0 | `SUB Rd, Rn, #imm12 [LSL #12]` | bit-31=64-bit; no flag update |
| `ace_vm_op_sub_shifted_reg` | 0x144B3C | `SUB Rd, Rn, Rm, shift #amount` | LSL/LSR/ASR/ROR via `ace_arm_bitwise_shift` |
| `ace_vm_op_subs_imm` | 0x144DAC | `SUBS Rd, Rn, #imm12 [LSL #12]` | sets full NZCV; CMP alias when Rd==WZR |
| `ace_vm_op_subs_shifted_reg_v2` | 0x144ED8 | `SUBS Rd, Rn, Rm, shift` | flag-setting shifted-reg variant |
| `ace_vm_op_b_cond` | 0x141E54 | `B.cond label` | tests cond via `sub_145600`; PC += signed 19-bit×4 |
| `ace_vm_op_tbnz` | 0x145078 | `TBNZ Rt, #imm6, label` | bit-test-and-branch-if-non-zero, 14-bit signed offset |
| `ace_vm_op_tbz` | 0x1450E8 | `TBZ Rt, #imm6, label` | bit-test-and-branch-if-zero |
| `ace_vm_op_udiv` | 0x145418 | `UDIV Rd, Rn, Rm` | div-by-zero returns 0 (ARMv8 spec) |
| `ace_vm_op_madd_w` | 0x14548C | `MADD Wd, Wn, Wm, Wa` | 32-bit form; Rd = Ra + Rn × Rm |
| `ace_vm_op_smulh_umulh` | 0x1454F8 | `SMULH/UMULH Rd, Rn, Rm` | high 64 bits of 128-bit product (calls `ACE_Multiply128`) |
| `ace_vm_op_and_shifted_reg_v2` | 0x141A4C | `AND Rd, Rn, Rm, shift` | second AND-shifted-reg encoding (alt opcode ID) |
| `ace_vm_op_branch_imm26_v2` | 0x141EB0 | `B / BL #imm26` | second B/BL encoding; supports native bridge opcode 0x48D958 |
| `ace_vm_op_extr` | 0x142D64 | `EXTR Rd, Rn, Rm, #lsb` | 64-bit "double-width shift" (concatenate then shift) |
| `ace_vm_op_ldr_immediate` | 0x142F04 | `LDR Rt, [Rn{, #imm}]` | scaled (v2=0 with pre/post-index via bits 0xC00) and unscaled (v2=1) |

## Iteration 41 third pass — additional ~13 handlers

| Handler | Address | Decoded Instruction | Notes |
|---|---|---|---|
| `ace_vm_op_svc_syscall` | 0x1411DC | `SVC #imm16` | **CRITICAL** — kernel syscall bridge. opcode 1. See `48_svc_syscall_bridge.md` |
| `ace_vm_op_nop_hint` | 0x143B20 | `NOP / HINT` | literal NOP — clears flags only |
| `ace_vm_op_orr_imm` | 0x143BE4 | `ORR Rd, Rn, #bitmask_imm` | bitmask immediate decode |
| `ace_vm_op_orr_shifted_reg` | 0x143E10 | `ORR Rd, Rn, Rm, shift` | shifted-reg variant |
| `ace_vm_op_ror_register` | 0x143F04 | `ROR Rd, Rn, Rm` | rotate-right register |
| `ace_vm_op_bfi` | 0x143FA8 | `BFI Rd, Rn, #lsb, #width` | BitField Insert |
| `ace_vm_op_sdiv` | 0x1442B8 | `SDIV Rd, Rn, Rm` | Signed Divide |
| `ace_vm_op_smaddl` | 0x144330 | `SMADDL Rd_64, Rn_32, Rm_32, Ra_64` | Signed Multiply-Add Long |
| `ace_vm_op_smull` | 0x14439C | `SMULL Rd_64, Rn_32, Rm_32` | Signed Multiply Long (32×32→64) |
| `ace_vm_op_stp_pair` | 0x144404 | `STP Rt, Rt2, [Rn, #imm]` | Store Pair |
| `ace_vm_op_str_register` | 0x1445DC | `STR Rt, [Rn, Rm]` | Store with register offset |
| `ace_vm_op_strb_immediate` | 0x1446A0 | `STRB Rt, [Rn{, #imm}]` | Store byte immediate |
| `ace_vm_op_strb_register` | 0x14475C | `STRB Rt, [Rn, Rm]` | Store byte register offset |
| `ace_vm_op_stur_str_unscaled` | 0x1448B4 | `STUR Rt, [Rn, #simm9]` | Store with unscaled signed 9-bit imm |
| `ace_vm_op_subs_extended_reg_v2` | 0x144C28 | `SUBS Rd, Rn, Rm, ext #shift` | extended-reg variant (alt encoding) |
| `ace_vm_op_ldur` | 0x1436A4 | `LDUR Rt, [Rn, #simm9]` | Load with unscaled signed 9-bit imm |

## Iteration 40 second pass — additional 14 handlers

| Handler | Address | Decoded Instruction | Notes |
|---|---|---|---|
| `ace_vm_op_adr` | 0x1417AC | `ADR Rd, label` | PC-relative add (companion to ADRP); 21-bit signed offset in immlo+immhi |
| `ace_vm_op_and_imm_v2` | 0x141820 | `AND #bitmask_imm` (full decode) | full ARM64 bitmask-imm decode with rotation/replication for 32 and 64-bit |
| `ace_vm_op_blr` | 0x1423B0 | `BLR Rn` | Branch with Link to Register; saves return-addr to X30 (slot at +240) |
| `ace_vm_op_br_ret` | 0x1423E4 | `BR Rn / RET` | Indirect branch, no link save |
| `ace_vm_op_cbnz` | 0x14240C | `CBNZ Rt, label` | Compare-and-branch on non-zero |
| `ace_vm_op_cbz` | 0x142464 | `CBZ Rt, label` | Compare-and-branch on zero |
| `ace_vm_op_ccmn_imm` | 0x1424C4 | `CCMN/CCMP #imm5, #nzcv, cond` | conditional compare with immediate operand |
| `ace_vm_op_csel` | 0x1427C4 | `CSEL Rd, Rn, Rm, cond` | Conditional Select (basic form) |
| `ace_vm_op_csinv` | 0x1428FC | `CSINV Rd, Rn, Rm, cond` | Conditional Select Invert |
| `ace_vm_op_eor_shifted_reg` | 0x142CA0 | `EOR Rd, Rn, Rm, shift #amount` | XOR with shifted-reg |
| `ace_vm_op_ldrb_strb_immediate` | 0x143290 | `LDRB/STRB Rt, [Rn, #imm]` | byte load/store with pre/post-index |
| `ace_vm_op_ldrh_unsigned_imm` | 0x143750 | `LDRH Rt, [Rn{, #uimm12<<1}]` | unsigned-imm halfword load |
| `ace_vm_op_ldrsw_register` | 0x143608 | `LDRSW Rt, [Rn, Rm{, ext}]` | sign-extend word load (register offset) |
| `ace_vm_op_ldrsw_unsigned_imm` | 0x1437A4 | `LDRSW Rt, [Rn{, #uimm}]` | sign-extend word load (immediate) |
| `ace_vm_op_lsl_register` | 0x143804 | `LSL Rd, Rn, Rm` | Logical Shift Left (register variant) |
| `ace_vm_op_lsr_register` | 0x143884 | `LSR Rd, Rn, Rm` | Logical Shift Right (register variant) |
| `ace_vm_op_madd` | 0x1438F8 | `MADD Rd, Rn, Rm, Ra` | Multiply-Add: Rd = Ra + Rn × Rm |
| `ace_vm_op_movk` | 0x14399C | `MOVK Rd, #imm16, LSL #hw` | Move-with-Keep (preserve other 16-bit fields) |
| `ace_vm_op_movn` | 0x143A18 | `MOVN Rd, #imm16, LSL #hw` | Move-Not: Rd = ~(imm16 << hw) |
| `ace_vm_op_movz` | 0x143A48 | `MOVZ Rd, #imm16, LSL #hw` | Move-with-Zero: Rd = imm16 << hw |

## Nullsub handlers identified

These dispatch table slots point to literal NOP functions. They mark **reserved opcode IDs** that the emitter never uses but are kept for forward-compatibility:

```
0x1411D8, 0x141228, 0x14122C, 0x141230, 0x141234, 0x141238,
0x14123C, 0x141240, 0x141244, 0x141248, 0x14124C, 0x141250,
0x141254, 0x141258, 0x14125C, 0x141E50, 0x142A6C, 0x142D5C,
0x142D60, 0x142E4C, 0x142F00, 0x14308C, 0x1454F4, 0x14555C,
0x145560
```

(25 nullsubs found out of 148 total entries; the actual usable instruction set is 148 - 25 - 1_null_at_table[0] = ~122 distinct opcodes.)

## Pattern recognition — handler families

Each ARM64 instruction has multiple encodings in real ARM64 (e.g., immediate vs. shifted-register), and ACE's emulator tracks each as a separate dispatch slot. We've now seen these families:

### Arithmetic (no flag update)
- `ADD #imm12 [LSL #12]` → 0x1413BC
- `ADD shifted-reg` → 0x141430
- `SUB #imm12` → 0x144AC0
- `SUB shifted-reg` → 0x144B3C

### Arithmetic (sets NZCV)
- `ADDS #imm12` → 0x141510
- `ADDS shifted-reg` → 0x141610
- `SUBS #imm12` → 0x144DAC
- `SUBS shifted-reg` → 0x144ED8 (v2)
- `SUBS extended-reg` → 0x1449E4

### Logical
- `AND #bitmask_imm` → 0x141B0C
- `AND shifted-reg` → 0x141D5C, 0x141A4C (v2)
- `BIC shifted-reg` → 0x142258
- `EOR #bitmask_imm` → 0x142A74
- `ORN shifted-reg` → 0x143B28

### Bitfield / Shift
- `BFM/UBFM/SBFM` → 0x141F44
- `EXTR Rd, Rn, Rm, #lsb` → 0x142D64
- `AND-extr` (rotated AND-imm) → 0x145158

### Branch
- `B/BL #imm26` → 0x142314, 0x141EB0 (v2)
- `B.cond` → 0x141E54
- `TBZ Rt, #imm6, label` → 0x1450E8
- `TBNZ Rt, #imm6, label` → 0x145078

### Memory
- `LDR Rt, [Rn], #imm` (post/pre-index) → 0x142F04
- `LDR Rt, [Rn, Rm]` (register) → 0x142FE0
- `LDRSW Rt, ...` → 0x143598
- `LDRH/STRH halfword` → 0x143434

### Multiply / Divide
- `MADD Wd, ...` → 0x14548C
- `SMULH/UMULH Rd, Rn, Rm` → 0x1454F8
- `UDIV Rd, Rn, Rm` → 0x145418

## Native bridge — multiple entry points

The emulator has **two independent B/BL handlers** (0x142314, 0x141EB0) that both implement the special opcode `0x48D958` for "branch into native function". This redundancy means:
- Multiple opcode IDs can trigger the bridge.
- Patching one bridge does not block the other.
- Our existing Tier 7 (or Tier 8) blocks at a higher level (the VM execution driver), neutralizing both.

Both handlers also support the plain `B #0` "lookup native callback" form, which calls `ace_vm_lookup_native_function(parser_ctx, current_pc)` and invokes the result with `module_struct` as arg. This is the **primary cross-VM-to-host bridge**.

## Bypass implications

For the bypass:
- **None of these handlers individually need patching.** They all operate on the VM's emulated register file (offsets +0..+247 in module struct), not on host process memory.
- **The native bridge in B/BL is the dangerous part** — but it's already neutralized at the VM execution driver level.
- **Tier 7 + Tier 8 cover this** at the top of the call chain.

## Coverage analysis

We now have ~36% of the opcode table mapped. The remaining 95 handlers include:
- More memory variants (LDP/STP, exclusive load/store, atomics)
- More conditional ops (CSEL/CSINC/CSINV variants)
- Compare-branch (CBZ/CBNZ — different from TBZ/TBNZ)
- BR/BLR/RET (register-indirect branches)
- System instructions (NOP, HINT, ISB, DSB, DMB, SVC bridge)
- More multiply variants (MUL, UMULL, SMULL, MSUB)
- Move variants (MOV, MOVK, MOVN, MOVZ)
- More shift register variants

## To-do (next iteration)

- Decompile remaining ~95 handlers in batches of 10
- Identify which handlers expose host memory (the "dangerous" ones)
- Build a Python disassembler that decodes `ob_*.zip` modules to ARM64 mnemonics — would let us read what ACE actually checks
- Document `ace_arm_bitwise_shift` (libanort+0x14557C) — the universal shift helper
- Document `sub_145600` — the B.cond condition test (needs to map all 16 condition codes)
