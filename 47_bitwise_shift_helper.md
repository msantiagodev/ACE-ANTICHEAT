# `ace_arm_bitwise_shift` — Universal Shift Helper (libanort+0x14557C)

This is the helper called by every shifted-register opcode handler in the ARM64 emulator. Decompiled and confirmed:

```c
unsigned __int64 ace_arm_bitwise_shift(
    unsigned __int64 value,    // x0
    int shift_type_plus_1,     // w1: 1=LSL, 2=LSR, 3=ASR, 4=ROR
    int amount,                // w2: shift amount
    char bit_width             // w3: 32 or 64
) {
    if (shift_type_plus_1 == 1) {       // LSL
        return value << amount;
    } else if (shift_type_plus_1 == 2) {  // LSR
        return value >> amount;
    } else if (shift_type_plus_1 == 3) {  // ASR
        if (amount == 0) return value;
        // sign-extend bit (bit_width-1) and shift right with extension
        return ((int64_t)(value >> (bit_width-1) << 63) >> 63)
             & (-1LL << (bit_width - amount))
             | (value >> amount);
    } else if (shift_type_plus_1 == 4) {  // ROR
        if (amount == 0) return value;
        return (value << (bit_width - ((bit_width-1) & amount)))
             | (value >> ((bit_width-1) & amount));
    }
    return value;  // unknown shift type → no-op
}
```

## Encoding map

The `shift_type_plus_1` parameter is **one-based** to ensure 0 means "no operation":

| Caller passes | Operation |
|---|---|
| 0 | (no-op, returns value unchanged) |
| 1 | LSL — Logical Shift Left |
| 2 | LSR — Logical Shift Right |
| 3 | ASR — Arithmetic Shift Right (sign-extends MSB) |
| 4 | ROR — Rotate Right |

The standard ARM64 encoding uses bits[22:23] (`shift_type` in the table below):

| ARM64 shift_type | Mnemonic | Caller passes |
|---|---|---|
| 0b00 | LSL | 1 |
| 0b01 | LSR | 2 |
| 0b10 | ASR | 3 |
| 0b11 | ROR | 4 |

Hence the `v4 + 1` we see in handler decompilations.

## bit_width parameter

Always passed as 32 or 64 depending on the `sf` bit (instruction bit 31).

## Edge cases

- **amount == 0** for ASR or ROR returns the input unchanged (no shift). ARM64 spec actually defines amount==0 with no shift for these, so the helper is correct.
- **amount >= bit_width** is technically undefined in C; ACE's helper passes the full value so behavior depends on hardware shift count masking. For LSL and LSR this is mostly harmless since the result is "all zeros / shifted out".
- The helper does NOT update flags. Flag-setting variants (e.g., ANDS, SUBS) compute flags in the caller after.

## Callers (where this helper is used)

| Caller | Opcode | Shift role |
|---|---|---|
| `ace_vm_op_add_shifted_reg` | ADD | shift Rm before adding |
| `ace_vm_op_adds_shifted_reg` | ADDS | same, sets flags |
| `ace_vm_op_and_shifted_reg` | AND | shift Rm before AND |
| `ace_vm_op_and_shifted_reg_v2` | AND (alt) | duplicate dispatch slot |
| `ace_vm_op_bic_shifted_reg` | BIC | shift Rm before AND-NOT |
| `ace_vm_op_eor_shifted_reg` | EOR | shift Rm before XOR |
| `ace_vm_op_orn_shifted_reg` | ORN | shift Rm before OR-NOT |
| `ace_vm_op_sub_shifted_reg` | SUB | shift Rm before subtract |
| `ace_vm_op_subs_shifted_reg_v2` | SUBS | shift Rm before subtract, sets flags |

(There is also a separate "extended-register" form for SUBS/ADDS that does sign/zero-extend instead of shift; that uses a different helper.)

## To-do

- Find the extended-register helper (UXTB/UXTH/UXTW/UXTX/SXTB/SXTH/SXTW/SXTX)
- Confirm ARM64-spec compliance: ASR with amount==0 should be a no-op, ROR with amount==bit_width should be a no-op.
