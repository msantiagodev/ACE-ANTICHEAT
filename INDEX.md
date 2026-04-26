# ACE Documentation Index — 68 Documents (10,000+ lines)

This is the master navigation index for the complete ACE reverse-engineering documentation. Start with the **Quick Start** if you're new.

## Quick Start (read these first)

1. **`77_FINAL_CHILD_GUIDE.md`** — **NEW**: Comprehensive plain-English guide updated through Iteration 52
2. **`00_TLDR_FULL_SYSTEM.md`** — What is ACE, in 5 minutes
3. **`34_CHILD_GUIDE.md`** — Earlier 600-line plain-English explainer (no jargon)
4. **`39_COMPLETE_EMULATION_GUIDE.md`** — End-to-end implementation guide
5. **`73_bypass_status_audit.md`** — Current bypass coverage and gaps
6. **`PROGRESS.md`** — Iteration ledger of all work done
7. **`INDEX.md`** — This file

## Architecture & Boot Flow

| Doc | What it covers |
|---|---|
| `02_init_flow.md` | High-level init flow |
| `28_libanort_boot_sequence.md` | libanort boot sequence (low-level) |
| `30_libanogs_init_array.md` | libanogs init_array execution |
| `55_ob_zip_extraction_chain.md` | ob_*.zip → VM execution chain |
| `63_boot_heartbeat_chain.md` | Boot HB request/response protocol |

## String Encryption / Decoding

| Doc | What it covers |
|---|---|
| `01_string_decryption.md` | The 100-decoder XOR scheme |
| `64_master_string_dictionary.md` | All decoded strings by category |
| `10_libanort_strings.md` | libanort-specific decoded strings |

## Detection Engine

| Doc | What it covers |
|---|---|
| `03_detection_targets.md` | What ACE looks for |
| `13_expression_engine.md` | The expression VM (libanogs) |
| `14_rule_state_machine.md` | Rule interpreter |
| `19_interpreter_loop.md` | The main scan loop |
| `33_detection_poller_clarified.md` | Detection polling clarification |
| `38_detection_inventory.md` | 200+ detection strings cataloged |
| `41_strategy_inventory.md` | Strategy keys |
| `61_emulator_detection_inventory.md` | Emulator detection (FULL) |
| `58_virtual_app_signatures.md` | 21 virtual-app patterns detected |
| `65_scan_dsl_and_api_surface.md` | sys_ver_eq, brand_contains DSL |

## Scanner Modules (libanogs)

| Doc | What it covers |
|---|---|
| `05_scanner_modules.md` | Original scanner module overview |
| `31_scanner_module_anatomy.md` | C++ anatomy of scanner classes |
| `68_libanogs_scanner_module_inventory.md` | All 14 scanner modules |
| `29_conditional_scanners.md` | Condition-gated scanners |

## ARM64 VM Emulator (libanort's secret weapon)

| Doc | What it covers |
|---|---|
| `21_libanort_bytecode_vm.md` | Original VM doc |
| `22_libanort_arm64_emulator.md` | Full emulator anatomy + 31 handlers |
| `46_arm64_emulator_handler_extension.md` | +50 handlers (now ~80 mapped) |
| `47_bitwise_shift_helper.md` | Universal shift helper |
| `15_arm64_relocator.md` | ARM64 instruction relocator |
| `48_svc_syscall_bridge.md` | SVC handler — kernel access bridge |

## Native Bridges (Emulator → Host)

| Doc | What it covers |
|---|---|
| `52_native_bridges_complete_inventory.md` | All 6 bridges enumerated |
| `49_native_function_registry.md` | 184 native functions exposed |
| `50_command_dispatch_tree.md` | 190-key command hash dispatch |
| `51_ff_wrappers_sample.md` | Sample of __ff_<n> wrappers |
| `62_no_dlsym_symbol_resolver.md` | dlsym-bypassing symbol resolver |

## Hook Architecture

| Doc | What it covers |
|---|---|
| `04_libc_hook_watch.md` | libc hook detection |
| `09_ace_inline_hooks.md` | Inline hook installer |
| `24_hook_descriptor_registry.md` | Hook descriptor RB-tree |
| `35_inline_hook_installer.md` | Hook install internals |
| `36_install_strategies.md` | 4 install strategies |
| `37_install_hook_callers.md` | Hook caller chains |

## Networking & Reporting

| Doc | What it covers |
|---|---|
| `08_gp7ioctl_protocol.md` | GP7 IOCTL protocol |
| `20_tdm_report_chain.md` | TDM report chain |
| `25_network_protocol.md` | Network packet format |
| `42_format_strings_inventory.md` | All printf format strings |
| `43_timing_reporter_chain.md` | Timing reporter |
| `82_packet_format_and_chunking.md` | Outer packet build + chunking (sender) |
| `83_packet_dispatch_full.md` | Receive dispatch + server command surface |
| `84_complete_wire_format.md` | First-pass wire format (superseded by 87 for outer) |
| `85_tlv_compose_variants.md` | TLV records + 4 PacketCompose variants overview |
| `86_crc32_and_vm_context_health.md` | CRC-32 (was "EventSignal") + 21s VM context health |
| `87_outbound_wire_format_complete.md` | DEFINITIVE: every byte of outer header + all 4 inner serializers |
| `88_state_struct_and_embedded_vm_zip.md` | Network state lifecycle (OpenID source) + embedded VM modules ZIP at libanort+0x19887B |
| `89_a64_dat_internal_structure.md` | Both embedded VM ZIPs dumped + a64.dat header decoded; XOR-by-0x83 outer layer; 17/18 module enumeration |
| `90_a64_dat_decrypted.md` | Inner cipher (sbox[byte XOR 0x23]) reverse-engineered, 306 plaintext strings extracted, target libs/APIs identified |
| `91_vm_modules_catalog.md` | Complete VM module catalog: all 5 modules extracted (vm_main.img 256KB, vm_hb, timeout_looper, gp7worker, gp7service) |
| `92_vm_module_bytecode_format.md` | Per-module .img file format reverse-engineered; 234 native imports cataloged; top __ff_<n> identified as VM memory glue |
| `93_vm_main_disassembly.md` | First disassembly of vm_main.img bytecode (18,943 ARM64 insns, 1827 branches, 9 SVC syscalls, 97 native call sites) |
| `94_jni_dispatch_table.md` | VM JNI dispatch reverse-engineered (229 entries, 32 identified as JNI functions via CRC32 brute-force); top __ff_<n> identified |
| `95_complete_jni_table_and_more_bridges.md` | ALL 229 JNI dispatch entries decoded (full JNI API exposed); __ff_109/110/111 mapped; refined bypass analysis |
| `96_layer2_string_cipher_cracked.md` | Layer-2 string cipher cracked (same alphanumeric XOR as module names); 84 strings decoded; ACE total cipher count = 3 |
| `97_more_bridges_and_layer2_corpus.md` | 5 more __ff bridges (fstatfs/access/atoll/ctx-reader/syscall-dispatcher); full Layer-2 corpus saved |
| `98_syscall_chain_and_more_bridges.md` | Syscall chain end-to-end (sub_120EE0→ACE_RawSyscall); 11 more __ff bridges (linked-list ops, integrity hash, shellcode call) |

## JNI (Java Bridge)

| Doc | What it covers |
|---|---|
| `32_jni_native_methods.md` | Original JNI doc |
| `53_jni_native_methods.md` | All 6 libanort JNI methods |
| `66_libanogs_jni_native_api.md` | All 11 libanogs JNI methods |
| `67_libanogs_jni_full_signatures.md` | Full signatures + behavior |

## Persistent Storage

| Doc | What it covers |
|---|---|
| `17_ob_zip_format.md` | ob_*.zip wire format |
| `54_signed_cache_db_format.md` | ace_cache_db.dat format |
| `57_complete_file_inventory.md` | All 13+ persistent files |

## Configuration

| Doc | What it covers |
|---|---|
| `27_config_update_chain.md` | Config update flow |
| `40_config_flags_inventory.md` | g_anort_config_flags (11 of 32 bits) |

## Kill Paths

| Doc | What it covers |
|---|---|
| `11_thread_cracked_detection.md` | Thread cracked detection |
| `12_complete_kill_path_inventory.md` | All known kill paths |
| `26_anort_11_patches_explained.md` | The 11 ANORT patches we apply |
| `45_watchdog_search.md` | Watchdog hunt (negative result) |
| `56_probabilistic_detection_timer.md` | 0.1%/day deep audit |
| `60_validate_config_kill_chain.md` | exit_group via JNI "stop" |

## Bypass Strategy

| Doc | What it covers |
|---|---|
| `06_removal_emulation_blueprint.md` | Original bypass blueprint |
| `26_anort_11_patches_explained.md` | The deployed patches |
| `48_svc_syscall_bridge.md` | Critical SVC kill (Tier 1) |
| `59_runtime_dex_loader.md` | DEX loader backdoor (NOT killed) |
| `73_bypass_status_audit.md` | **Comprehensive audit of bypass coverage** |

## ACE Architecture (Tencent's Tier System)

| Doc | What it covers |
|---|---|
| `71_gcloud_remote_config.md` | GCloud SDK — remote config delivery |
| `72_gp_protection_layers.md` | GP3-GP7 protection layer hierarchy |
| `74_anti_macro_touch_detection.md` | Touch listener proxy + auto-clicker detection |
| `75_detected_libraries_catalog.md` | Every .so ACE checks for |
| `76_wb_command_protocol.md` | Java↔Native pipe-delimited protocol |

## Special Topics

| Doc | What it covers |
|---|---|
| `07_libanort_structure.md` | libanort .so layout |
| `16_rule_callers.md` | Rule call hierarchy |
| `18_obstub_dispatcher.md` | obstub dispatcher |
| `23_corereport_vtables.md` | CoreReport vtables |
| `44_periodic_scan_thread.md` | The 30-sec scan thread |

## Key file paths

- **IDA databases**: `C:\Users\Administrator\Documents\Unreal_Engine\SoDecompilation\arm64\libanort.so.i64` and `libanogs.so.i64`
- **String tables (decoded)**: `decoder_call_sites.txt` (libanogs), `decoder_call_sites_libanort.txt` (libanort)
- **Bypass code**: `C:\Users\Administrator\Documents\Unreal_Engine\Android-Mod-Menu\app\src\main\jni\Main.cpp`
- **String decryptor skill**: `C:\Users\Administrator\.claude\skills\ace-string-decryptor\`

## Statistics (Iteration 50)

- **73 doc files** (~12,000+ lines total)
- **2,300+ functions named** in IDA Pro databases (libanort 1,700+, libanogs 580+)
- **900+ comments added** to functions
- **~250 string IDs decrypted and named**
- **Coverage**:
  - String table: ~80% of strings by ID-density (all interesting strings decoded)
  - VM opcode handlers: 80+ of 148 (~54%)
  - Config flag bits: 11 of 32 (verified)
  - Native function registry: 25 of 184 wrappers documented (full table cataloged)
  - JNI native methods: 17 of 17 (libanort 6, libanogs 11)
  - Scanner modules: 14 of 14
  - GP layers: 5 of 5 (GP3-GP7)
  - ZIP variants: 22 of 22
  - libc hook watch list: 31 of 31
  - Init flow: complete (boot → modules → HB → main loop)
  - GCloud channel: documented
  - Bypass audit: complete

## Next priorities

1. Decompile the remaining ~70 ARM64 VM opcode handlers
2. Decode the obfuscated trampolines for senddatatosvr / setsenddatatosvrcb / hasMatchRate
3. Sample 50+ more `__ff_<n>` wrappers
4. Build a runtime DEX dumper for vm_main.img
5. Reverse the heartbeat hash function (so we can fake responses)
6. Document the full decryptor for `comm.zip` (which is actually an ELF)
