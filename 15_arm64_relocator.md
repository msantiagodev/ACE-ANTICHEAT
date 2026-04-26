# ACE's Built-In ARM64 Instruction Relocator

`ace_arm64_instruction_relocator` (libanogs+0x3F9CFC) is ACE's complete homegrown equivalent of Dobby's instruction rewriter. When ACE installs an inline hook on an ARM64 function, this routine copies the original prologue bytes into a trampoline page AND fixes up any PC-relative instructions so they still execute correctly from the new location.

## Why ACE has its own relocator

When you replace 4 bytes (one instruction) of a function with `B trampoline`, those original bytes have to live somewhere — the trampoline. But ARM64 has lots of PC-relative instructions:

- `B`, `BL` (±128MB)
- `B.cond`, `CBZ`, `CBNZ` (±1MB)
- `TBZ`, `TBNZ` (±32KB)
- `ADR`, `ADRP` (±1MB / ±4GB)
- `LDR` literal (`LDR Wd, =label`, `LDR Xd, =label`)

If the trampoline lives far from the original code, these instructions would compute wrong addresses. The relocator detects each one, computes the **original** target, and emits a patched sequence that produces the same effective behavior at the trampoline's new location.

## Hook descriptor layout (deduced from accesses)

ACE's hook descriptor is the data structure passed in `a2` (`v47`). Field offsets:

| Offset | Field | Meaning |
|---|---|---|
| `+120` | `original_addr` | original function's PC where bytes came from |
| `+232` | `relocator_state_offset` | byte offset for relocator scratch in the buffer |
| `+240` | `prologue_len_bytes` | how many bytes of the original prologue are being relocated (multiple of 4) |
| `+248` | `original_bytes` | inline copy of the original prologue bytes |
| `+280` | `padding_bytes` | header bytes preceding the rewritten instructions |
| `+288` | `trampoline_buffer_ptr` | RWX page where rewritten instructions go |
| `+296` | `byteoffset_within_descriptor_to_inst_byte` | byte offset to the instruction byte field |

The relocator writes into `trampoline_buffer_ptr + (padding_bytes+4) + cursor` and advances `cursor` after each instruction.

## Output sequence per input instruction

### B / BL (encoding `0x14000000` / `0x94000000`)

Original: `B target` or `BL target` (target = PC + signed 26-bit imm × 4)

Rewritten:
```
[only for BL]
ADR  X30, +20       ; 0x100000BE — sets link reg to "after .qword"
LDR  X16, [PC+0x8]  ; 0x58000050
BR   X16            ; 0xD61F0200
.qword target       ; absolute target address
```

If the target is back inside the original prologue range (i.e. it's a self-jump within the bytes being copied), the relocator points it to the new copy in the trampoline so the loop still works.

### ADRP (encoding `0x10000000 | imm21`)

Original: `ADRP Xd, page` — loads (PC&~0xFFF) + (imm21 << 12) into Xd.

Rewritten — three cases:

1. **In-range ADRP (target page within ±4GB of trampoline):** Just emit a new ADRP with re-computed immediate (page diff between trampoline and original target).
2. **Tiny absolute (target ≤ 1MB from trampoline):** Same as case 1 but no offset adjustment needed.
3. **Out-of-range:** Replace with `LDR Xd, [PC+8]; B +12; .qword absolute_target`. Costs 16 bytes instead of 4.

Encoded constants:
- `0x58000040 + Rd` = `LDR Xd, [PC+0x8]` (variable Rd)
- `0x14000003` = `B +12` (skip the qword) = decimal 335544323

### B.cond / CBZ / CBNZ (encodings `0x54000000` / `0x34000000` / `0x35000000`)

Original: `B.cond +imm19` (or `CB[N]Z Rd, +imm19`) — 19-bit signed offset × 4.

Rewritten:
```
B.cond +0x10        ; 4-byte forward branch (taken-case)
B +20               ; 0x14000005 — fall-through (skip the absolute jump)
LDR  X17, [PC+0x8]  ; 0x58000071
BR   X17            ; 0xD61F0220
.qword target       ; absolute target
```

The original branch's condition bits are preserved; only the immediate is replaced with `+0x10` so the trampoline jumps over the fall-through code into the LDR/BR sequence.

### TBZ / TBNZ (encoding `0x36000000` / `0x37000000`)

Same shape as B.cond rewrite, but the immediate is 14 bits at bits[5..18] (× 4 = ±32KB).

Output is identical to the B.cond rewrite because the BR X17 reaches anywhere.

### LDR literal — `LDR Wx/Xx, label` (high byte 0x18 or 0x58)

Original: `LDR Wd/Xd, label` — loads from `PC + signed_imm19 × 4`.

Rewritten — uses two scratch registers:
```
STP Xd, Xs, [SP, #-16]!        ; push original Rd and a scratch reg s
LDR Xs, [PC+8]                 ; load absolute address into scratch
LDR Wd/Xd, [Xs]                ; load the actual value (size from HIBYTE)
LDP Xd, Xs, [SP], #16          ; restore (only Xs needed, but pair-restore is required)
B +12                          ; skip the qword
.qword absolute_load_address
```

The scratch register is chosen as any of x0..x30 that isn't the original Rd. This is the most expensive rewrite — 7 instructions for 1.

### Default (any other instruction)

Just memcpy 4 bytes verbatim. No rewriting needed.

## Tail trampoline

If **any** instruction was rewritten, the relocator emits a final block to return to the original function past the prologue:

```
LDR X16, [PC+0x8]
BR  X16
.qword (original_addr + prologue_len)
```

This is what makes the trampoline behave like the original function: after running the (possibly rewritten) prologue, it jumps back into the rest of the original code.

## Final steps

1. `ace_clear_icache_range(buffer, buffer+180)` — flush instruction cache so CPU sees the new code.
2. `ace_write_inline_jump(original_addr, ..., prologue_len)` — write the actual `B/BR` from the original code into the trampoline.

## Implications for our bypass

- **All hook installations go through this relocator.** Every detection that ACE installs at runtime — to monitor `dlopen`, `dlsym`, `mprotect`, `read`, `clock_gettime`, etc. — flows through here.
- **If we hook this function once (e.g., make it return `false`), every subsequent ACE hook installation fails silently.** The detection code never gets installed.
- **The trampoline buffers are RWX** — they're inherently visible to ACE's own RWX scanner (ironic). That's why ACE uses `prctl(PR_SET_VMA_ANON_NAME)` to disguise them in /proc/maps.

## Verification

This decompilation was verified by:
1. Decoding the magic constants to ARM64 mnemonics (matched LDR X16/X17, BR X16/X17, ADR X30, B +12, B +20).
2. Cross-checking the bit-field decoding against ARMv8 encoding tables.
3. Confirming `+120 (orig_addr)`, `+240 (length)`, `+288 (trampoline)` match the field accesses elsewhere in `ace_install_inline_hook`.

## Bypass code (drop-in)

```cpp
// In Main.cpp, after libanogs is loaded:
static bool always_succeed_relocator(uintptr_t /*self*/, uintptr_t /*hook_descriptor*/) {
    return true;  // Pretend hook was installed; original bytes remain in place
}
DobbyHook(reinterpret_cast<void*>(libanogs_base + 0x3F9CFC),
          reinterpret_cast<void*>(always_succeed_relocator),
          nullptr);
```

This single hook neutralizes ACE's entire **runtime-installed** hook fleet (libc PLT hooks, vtable hooks, syscall hooks). It does NOT affect the static hooks ACE installed at boot via `init_array` — those use a different code path through `ace_install_hook_caller_1..6`.
