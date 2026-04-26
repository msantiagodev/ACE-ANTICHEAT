# Complete libc Hook Watch List — 31 Functions

`ace_build_libc_hook_watch_list` (libanogs+0x266F4C) registers **31 libc functions** that ACE actively watches for inline hooks. If any of these have been modified (e.g., by Dobby, Frida, Substrate), ACE flags it as detection.

## The 31 watched libc functions

These are stored in a linked list at `g_ace_libc_hook_watch_list` (a static singleton). Each entry has:
- `+0`: next pointer
- `+8`: data pointer (24 bytes — addr, expected_bytes, flags?)

| # | Function | Why ACE cares |
|---|---|---|
| 1 | `open` | File-system access (Frida hooks open() to fake paths) |
| 2 | `read` | File reads (Frida hooks read() to fake content) |
| 3 | `write` | File writes |
| 4 | `fopen` | Higher-level file open |
| 5 | `fread` | Higher-level read |
| 6 | `fgets` | Line read |
| 7 | `fseek` | File position |
| 8 | `readdir` | Directory enumeration (catches "hide su binary" hooks) |
| 9 | `syscall` | Direct syscall (Frida hooks to filter syscall numbers) |
| 10 | `access` | File access check (catches "fake F_OK on frida-server") |
| 11 | `stat` | File metadata (catches lying about file existence) |
| 12 | `fstat` | FD-based metadata |
| 13 | `getenv` | Environment variable read |
| 14 | `kill` | Send signal (used by ACE for thread death detection) |
| 15 | `gettimeofday` | High-res time (catches anti-debug timing skew) |
| 16 | `sleep` | Pause execution |
| 17 | `select` | Multi-FD wait (catches network hijack) |
| 18 | `connect` | Network connection |
| 19 | `send` | Network send |
| 20 | `recv` | Network receive |
| 21 | `opendir` | Directory open |
| 22 | `ptrace` | Debugging primitive (catches anti-debug bypass) |
| 23 | `execl` | Process exec |
| 24 | `clock_gettime` | Monotonic time |
| 25 | `fdopen` | FD → FILE* conversion |
| 26 | `getpid` | Process ID |
| 27 | `dlopen` | Dynamic linker (catches `dlopen` hooks for lib hiding) |
| 28 | `dlclose` | Dynamic linker close |
| 29 | `pthread_create` | Thread spawn (catches thread interception) |
| 30 | `fork` | Process fork |
| 31 | `mmap` | Memory mapping (catches anti-mprotect tools) |
| 32 | `ace_custom_syscall_handler` | **Self-protection** — ACE's own internal handler |

## How the check works

For each registered function:
1. ACE hashes the first ~16 bytes of the function's machine code
2. Compares against an expected hash baked into the binary
3. If mismatch → "hook detected" → set detection flag

The detection runs at:
- Boot (initial baseline + verify)
- Periodic scan (every 30 seconds)
- On-demand (server-pushed force-scan)

## Anti-Frida significance

**Frida's standard `Interceptor.attach()` modifies the first instructions** of the hooked function (replacing them with a jmp to the trampoline). So Frida hooks on any of these 31 functions are detectable.

To evade: use Frida's **inline-hook-with-relocation** (e.g., via Dobby), which preserves the original instructions in a trampoline. ACE's check on the first ~16 bytes catches that too — unless we patch the SCANNER first.

## Cross-reference with our bypass

Our deployed bypass uses **DobbyHook** which DOES patch the first instructions. This means our `lua_pcallk` and other game-side hooks ARE detectable IF this scanner runs. But we've patched the actual scanner functions:

- **ANORT_PATCHES[2] = 0x45CE8** (`ACE_DlOpenScanner_PATCHED`) — disables the dlopen-watching scan
- **ANORT_PATCHES[6] = 0x0CE64C** (`library_integrity_scanner`) — disables the library integrity check
- **ANORT_PATCHES[7] = 0x0A7E7C** (`memory_region_validator`) — disables RWX page detection (catches Dobby trampolines)

These patches return immediately so the check never iterates the watch list. ACE's hook detection is effectively dead.

## Self-protection: `ace_custom_syscall_handler`

The 32nd entry in the watch list is ACE's own internal syscall handler. ACE protects ITSELF too — if anyone modifies its handler, it self-detects.

This is the recursive aspect: ACE assumes attackers might try to hook ACE's hooks. So ACE hooks itself watching for that.

To bypass this: don't modify the function (which we don't). Or patch the scanner that checks it (Tier 6 in our bypass).

## Bypass implications

For our existing bypass: **fully neutralized** at the scanner level. ACE registers the watch list, but the scanners that walk it are killed.

If we wanted **fine-grained** control:
- Hook `ace_hook_table_append` to NOT register specific functions (ACE wouldn't watch them)
- Hook the actual hash check to always return "clean"

We don't need this — Tier 6 covers it.

## To-do

- Find the actual hash function used (likely a CRC or simple byte sum on first 16 bytes)
- Determine if there are MORE registered watch functions added at runtime by other init paths
- Document the data structure size (24 bytes per entry seen)
- Cross-reference with the actual scanner that walks the list (ACE_DlOpenScanner_PATCHED?)
