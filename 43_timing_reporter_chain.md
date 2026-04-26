# ACE Timing Reporter Chain

ACE submits "I'm alive and I think the host environment is X" reports through a small chain of timing functions. These reports go up alongside detection results — they show server-side how long the agent has been running and what stages have been reached.

## The chain

```
ace_init_core_v4_9_30_24277_oversea (libanort+0xC3A6C)
        |
        +-- ace_detect_elf_section_tamper (libanort+0x323F4)
        |           |
        |           +-- ACE_ConditionalTimingReporter (libanort+0xEA5C4)
        |                           |
        |                           +-- ACE_TimingReporter (libanort+0xEAB00) [called twice via opaque branches]
        |
        +-- direct ACE_ConditionalTimingReporter call (from boot)
```

## ACE_ConditionalTimingReporter (libanort+0xEA5C4)

CFG-flattened state machine. Internally:

1. Sets a 32-bit "current state" int (`v18`/`v20`).
2. Loads three opaque magic values: `0x2AC4`, `0x36B9`, `0xDC18` into stack slots.
3. Computes a derived value `v28 = (v25 + v27 + (v24 ^ v25) + 1) ^ v26` where `v24 = 0x2AC4` (10980), `v25 = 0x36B9` (14009), and `v26 = v24 | v25`, `v27 = v24 | ~v25`.

   The arithmetic always yields the same constant (it's a tautological obfuscation). The check `v10 = (v27 | v23) + v23 - (v23 & ~v27) == v27 + v23` is also always true.
   
4. Walks through the state machine until it hits one of two `ACE_TimingReporter()` call sites — both reachable, both fire under their state.

The function's purpose: **call `ACE_TimingReporter` exactly twice** during init, but obscure that it does so by hiding the calls behind opaque predicates.

## ACE_TimingReporter (libanort+0xEAB00)

The real reporter. Builds a tiny struct {phase_id, monotonic_ns, host_pid} and sends it to `tdm_main` (the report dispatch trunk we documented in `20_tdm_report_chain.md`).

## Why ACE has two reporters

This pattern shows up in malware QC: redundant reports in different code paths to make tampering noisier. If you patch one site and miss the other, the server sees a count mismatch (1 instead of 2) → flagged.

**Bypass implication**: don't patch `ACE_TimingReporter` itself — let it run. The data it sends is harmless boot-time telemetry. We're already blocking the report channel further down via `tdm_main` killer (Tier 2).

## To-do

- Trace what `phase_id` byte ACE sends (different value at boot vs. mid-game?)
- Check if `ACE_TimingReporter` can be dropped silently (server may compare drop count to ban list)
- Find the third path — there's an indirect xref from a vtable somewhere that we haven't enumerated
