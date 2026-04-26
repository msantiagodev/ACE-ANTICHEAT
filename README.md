# ACE Anti-Cheat — Reverse Engineering Notes

Notes from picking apart Tencent's ACE ("Anti-Cheat Expert") SDK — the
`libanort.so` + `libanogs.so` pair that backs PUBG Mobile, Honor of
Kings, Call of Duty Mobile, Arena Breakout, Tower of Fantasy, and most
other big Tencent-published Android games. The specific binary
analyzed here ships inside a recent UE4 4.26 mobile title.

This is a working set, not a polished writeup. Files were produced
over months of IDA Pro work as one-subsystem-per-file deep dives.
They assume you already read ARM64 disassembly and know what an ELF
`init_array` does. If you don't, the "child guides" listed below
are written in plain English.

## Where to start

| You want... | Open |
|---|---|
| The whole thing in five minutes | `00_TLDR_FULL_SYSTEM.md` |
| Plain English, no jargon | `34_CHILD_GUIDE.md`, `77_FINAL_CHILD_GUIDE.md` |
| Browse by subsystem | `INDEX.md` |
| Architecture overview | `ACE_MASTER.md` |
| End-to-end implementation thinking | `39_COMPLETE_EMULATION_GUIDE.md` |
| What a real bypass actually has to cover | `73_bypass_status_audit.md` |

## What's in here

- ~100 markdown files, each scoped to one subsystem: string
  decryption, scanner modules, the embedded ARM64 emulator that
  runs most of the heavy detection bytecode, the report wire
  format, kill paths, network protocol, JNI dispatch tables, the
  GP3-GP7 protection layer hierarchy, persistent storage formats,
  and the boot/heartbeat handshake protocol
- `INDEX.md` — categorized navigation
- `ACE_MASTER.md` — high-level system summary

## Caveats

ACE is a moving target. Tencent ships new SDK versions on roughly
a quarterly cadence, and individual games enable different feature
subsets. Every offset, struct layout, and rule fingerprint in here
is a snapshot of one specific build. They will be wrong on others.
Use the analysis as a map of how the system thinks; verify the
numbers yourself against whatever build you're actually looking at.

These are research notes, not a turnkey bypass. They describe what
each detector looks for and where the kill paths live; they do not
ship working cheats, embedded keys, or anything specific to any one
game's ranking or economy.

## Source material

- Game binary: `libUE4.so` (UE4 4.26.2, ~450k functions)
- ACE binaries: `libanort.so` (~1.6 MB) and `libanogs.so` (~5.7 MB), both ARM64
- Analysis done statically in IDA Pro. Live tracing was not needed
  for the static portion that makes up these notes.

