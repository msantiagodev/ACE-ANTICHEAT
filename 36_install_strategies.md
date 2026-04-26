# ACE Hook Install Strategies — Bytecode Templates Decoded

ACE has 4 different inline-hook install strategies, each tailored for a specific hook type. They differ in:
- The shape of the prologue replacement bytes
- The trampoline allocation strategy (location, alignment)
- Whether they emit `LDR X16` or `ADRP X16`

## Strategy 1: `ace_hook_install_default` (libanogs+0x3FC730)

**Used for:** sub-types 0, 8, and default cases (the bulk of hooks).

**Allocates:** standard trampoline (anywhere in process memory).

**Prologue replacement (8 bytes at descriptor+200+v8):**
```
58 00 00 50    LDR X16, [PC + 0x8]
D6 1F 02 00    BR X16
[8 bytes]      .qword <hook function pointer>
```

This means: when execution reaches the hooked function's first 4 bytes, it loads the hook target from the next pc+8 location (which holds an 8-byte address) and branches there.

**Trampoline middle (instruction relocation):**
At `descriptor+v8+8` onwards, the relocated original instructions live (rewritten by `ace_arm64_instruction_relocator`).

**Trampoline tail (jumps back to original):**
```
A9 6F 07 E0    STP X0, X1, [SP, #-0x10]!     ; push (saved by relocator)
58 00 00 50    LDR X16, [PC + 0x8]
D6 1F 02 00    BR X16
[8 bytes]      .qword <orig function + prologue_len>
```

So the trampoline shape is:
```
[prologue replacement]  ← target of the original function jump
[relocated original prologue] ← preserves semantics
[tail back to original] ← jumps back into the original function past the prologue bytes that were replaced
```

## Strategy 2: `ace_hook_install_type_12` (libanogs+0x3FCD5C)

**Used for:** sub-type 12 hooks.

**Allocates:** a page-aligned trampoline within ±4GB of the target.

The function loops up to 5 times calling `sub_3FC584(...)` until it gets a page whose distance from the target is < 0x100000000 (4GB) AND is page-aligned. Failed attempts get `munmap`'d.

**Prologue replacement uses ADRP instead of LDR:**
```
[8 bytes: ADRP X16, page; BR X16]
```

The ADRP instruction encodes the trampoline page directly (21-bit signed displacement, ±4GB range). This is more efficient than LDR-literal because:
- No memory read needed
- Doesn't require trailing 8 bytes for the target
- Trampoline is 8 bytes total instead of 16

The `(addr & 0xFFF) == 0` check ensures page alignment, since ADRP only encodes pages.

**Trampoline middle and tail:** same as default (relocated prologue + LDR/BR back).

## Strategy 3: `ace_hook_install_type_extended` (libanogs+0x3FB9DC)

**Used for:** descriptors with `+393` flag set.

This handles "extended" hooks where the descriptor needs more state than fits in the standard layout. Likely used when the hook captures additional context (registers, return address, etc.) beyond what the standard prologue covers.

(Decompilation pending — function size suggests substantial logic.)

## Strategy 4: `ace_hook_install_special_offset` (libanogs+0x3FD698)

**Used for:** descriptors with `+297 == 1 || +297 == 2`.

This handles hooks at specific offsets within a function (not the prologue). Useful for hooking mid-function points without disturbing the prologue's stack setup.

(Decompilation pending — function size moderate.)

## Magic constants in the bytecode

When you see these byte patterns in trampolines, you know what they mean:

| Bytes | Instruction | Where |
|---|---|---|
| `50 00 00 58` | `LDR X16, [PC+8]` | Standard prologue jump load |
| `00 02 1F D6` | `BR X16` | Standard branch |
| `E0 07 6F A9` | `STP X0, X1, [SP, #-0x10]!` | Trampoline preamble (saved registers) |
| `50 00 00 58 ... 00 02 1F D6 ... [.qword]` | LDR-literal pattern | Standard hook trampoline |
| `[ADRP X16] 00 02 1F D6` | ADRP-based jump | Type-12 strategy |

## Hook callback dispatch

When the hook fires, control jumps to either:
- `sub_3FC288` (libanogs+0x3FC288) — for cases when v22 (a3 flag) is set
- `sub_3FC490` (libanogs+0x3FC490) — for default case
- a6 (caller-provided callback) — when explicitly given

These are **dispatcher** functions that:
1. Save caller's full register state on stack
2. Set up arguments for the actual hook routine
3. Call the user's hook function
4. Restore registers
5. Return to the trampoline middle (which runs the original prologue, then jumps back to the original function past the hooked prologue)

## Bypass implications

Hooking ANY of the 4 strategy functions (or their dispatcher entries `sub_3FC288/sub_3FC490`) effectively neutralizes hook installation. But Tier 7 (hooking `ace_arm64_instruction_relocator`) is cleaner because it short-circuits before any of these run.

If a future ACE update adds a new strategy, our Tier 7 still catches it (they all eventually call the relocator).

## To-do

- Decompile `sub_3FC584` (the trampoline allocator used by type-12)
- Decompile dispatcher `sub_3FC288` and `sub_3FC490` (the hook callback bridges)
- Find what `+393` flag means semantically (when does extended path get taken?)
- Map hook chains to which strategy each one uses
