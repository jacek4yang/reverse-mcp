# #19 capability audit (main @ 7b5830f)

Scope items -> status -> plan.

## Database / binary metadata
| item | status | plan |
|---|---|---|
| input hashes (md5/sha256) | MISSING | new `ida_db info` fields via `meta.input_file_md5/sha256` (safe idalib) |
| image base | MISSING | `get_imagebase` via new shim (nalt.hpp inline getinf INF_IMAGEBASE) |
| entry points | PARTIAL (addresses only via `idb.entries()`) | new `db.metadata` method: entries + names via `get_entry_ordinal`/`idalib_entry_name` |
| TLS callbacks | NOT EXPOSED by SDK for idalib scope | declare unsupported honestly (capability `tls_callbacks:false`) |
| imports + modules + usage sites | MISSING | new shims: `get_import_module_qty`, `get_import_module_name`, `enum_import_names` (callback collects ea+name+ord); usage sites via xrefs_to per import thunk |
| exports | PARTIAL (via names) | exports from entries() + names(); for DLLs use entry list |
| relocations/fixups | MISSING | new shims: `get_first_fixup_ea`, `get_next_fixup_ea`, `get_fixup`; bounded iteration |
| exception handlers | NOT EXPOSED (no low-level tryblks API used) | declare unsupported honestly |
| file-offset <-> EA mapping | MISSING | shims `get_fileregion_offset` / `get_fileregion_ea` (loader.hpp) |

## Functions / control flow
| item | status | plan |
|---|---|---|
| function chunks/tails | PARTIAL (flags only) | shim `func_tail_iterator_set`/`func_tail_iterator_next` via C shim -> tails list; plus `get_fchunk_qty`/`getn_fchunk` |
| create/delete/resize functions safely | MISSING | shims `add_func_ex`-style: use `add_func` (funcs.hpp) / `del_func` / `set_func_start` / `set_func_end`; mutation + revision |
| basic blocks, preds/succs | DONE (graph cfg) | keep; extend node payload with block kind |
| switch/jump-table metadata | MISSING | shim `get_switch_info` (nalt.hpp) -> bounded struct read (jumps, cases, elbase, jsize, vsize, flags) |
| correct callees/callers whole function | DONE (#23) | keep |
| indirect call metadata | PARTIAL (is_indirect_jump only) | per-insn `is_call` + operand type != o_near/o_far => indirect flag in disassemble output + switch info linking |

## Hex-Rays
| item | status | plan |
|---|---|---|
| ctree traversal typed summaries | MISSING | new shim `idalib_ctree_summary(cfunc)` walking `citem_t`/`cinsn_t`/`cexpr_t` by `op` (cit_*/cot_*) producing bounded typed node list; no raw pointer exposure |
| pseudocode line <-> EA | MISSING | `cfunc.get_eamap()` (hexapi) -> ea->insn list; map per-line via `sv` + anchors is GUI-free: use eamap only; expose `lines` already in pseudocode + per-line first-ea |
| lvars, args, return type | MISSING | shims `cfunc.get_lvars()` (lvars_t qvector<lvar_t>) -> name/type/width/is_arg/is_result; return type via `cfunc.get_func_type(tinfo_t)` -> `print_tinfo` |
| rename/retype lvars | MISSING | shims `restore_user_lvar_settings` + `save_user_lvar_settings` (hexapi, no GUI) with lvar_saved_info_t; mutation + revision |
| microcode generation/inspection | MISSING | shim `gen_microcode(mba_ranges_t, hf, retlist, flags, maturity)` + `mba.qty`/`get_mblock(n)`/`mblock.npred/nsucc/pred/succ` + per-block instruction walk via `mblock.head`/`minsn.next` with `mcode_t` name + `mop_t.t` summary; bounded |
| decompiler warnings/failure reasons | PARTIAL (HexRaysError code) | failure: `hexrays_failure_t.code/errea/str` already surfaced; add `mba.notes`-style warnings via `cfunc.get_warnings()` shim (bounded) |

## Types
| item | status | plan |
|---|---|---|
| local types | MISSING | shims `get_idati`, `get_ordinal_limit`, `get_numbered_type_name`, `print_tinfo`; bounded list |
| structs/unions/enums + members | MISSING | shim `tinfo_t.get_udt_details` via `get_tinfo_details(typid, BTF_STRUCT, buf)` -> udt_type_data_t (total_size, is_union, members: name/offset/type via print_tinfo/dstr) ; enums via BTF_ENUM + `get_type_details` |
| type parse/declare/apply | MISSING | shims `parse_decl` (PT_* flags) + `set_named_type`-equivalent `save_tinfo` + `apply_tinfo(ea, tif, TINFO_DEFINITE)`; mutation + revision |
| function prototypes/calling conventions | PARTIAL (decompile output text) | `apply_tinfo` for set; `get_tinfo(ea)` + `print_tinfo` for get; cc from tinfo (`get_calling_convention`) shim |
| stack frames | MISSING | `func_t` direct fields (frsize/frregs/argsize/fpd via existing func ptr access shims) + stkvar enumeration via tinfo `get_func_frame` shim -> udt members |
| type/field xrefs | MISSING | skip to #11 (needs its own index); declare unsupported here |
| type libraries | PARTIAL | `add_til` shim + list loaded via get_idati? (keep minimal: add_til + count) |

## Instructions / data
| item | status | plan |
|---|---|---|
| operand decoding and values | PARTIAL (text) | extend disassemble: per-operand structured {type(o_*), dtype, value/addr, reg} from `insn.ops` (safe: `insn.operand(n)` already typed) |
| instruction feature metadata | MISSING | `insn.get_canon_feature(ph)` shim -> feature bits (CF_CALL etc) per insn; bounded flags list |
| integer/string/global reads | PARTIAL (bytes only) | add typed reads get_word/dword/qword (shims exist) exposed via `ida_bytes get size=`; string read at ea via strlist |
| data definitions and arrays | MISSING | item size + is_data/is_code via flags64 (`get_flags` shim exists) -> expose item info in inspect; array params via `get_array_parameters` shim |
| names/demangling | PARTIAL | shim `demangle_name(name, 0, DQT_FULL)`; expose in names/inspect |
| register/stack-pointer tracking | MISSING | `get_sp_delta(func, ea)` shim -> per-insn sp delta in disassemble (bounded, only when requested) |

## Analysis/signatures
| item | status | plan |
|---|---|---|
| FLIRT | PARTIAL (`make_signatures`, plan_to_apply via plugin) | expose `apply_startup_sig`-lite: keep make_signatures; list signature files? out of scope here |
| auto-analysis state | PARTIAL (auto_wait bool) | expose `ida_is_auto_enabled` (shim exists inf) + database_change_count in db.info |
| bookmarks | DONE | keep |

## Segments
| item | status | plan |
|---|---|---|
| list/details | DONE | add bitness/base (get_segm_base shim) to payload |
| safe create/modify/rebase | MISSING (defer per issue: "when required") | out of scope for #19; segments read-only here |

## Cross-cutting
- New worker methods: `db.metadata`, `func.tails`, `func.create`, `func.delete`, `func.resize`, `func.switch_info`, `func.sp_delta`, `hr.cfunc` (ctree+lvars+rtype+warnings, bounded, result handle), `hr.microcode` (bounded), `types.list`, `types.get`, `types.parse_decl` (mutation), `types.apply` (mutation), `imports.list`, `fixups.list`, `file.map` (ea<->offset), `insn.features`, `names.demangle`
- `ida_capabilities` extended: types, imports_exports, patch_bytes stay honest; new fields: ctree, microcode, lvars, switches, fixups, tails, sp_delta, file_map
- All list ops bounded (limit + offset), large outputs through bound_output
- Mutations: expected_revision checked, revision bumped, audit detail returned
- Real IDA 9.2 tests: imports/exports, CFG, switch (dispatch fixture), lvars (decrypt_packet), local types (parse+apply), ctree, microcode, fixups, file map, tails, demangle

---

# Implementation status (2026-09-15, feat/issue19-capability-gaps)

Shipped in this branch (all real-IDA verified on `tests/fixtures/simple.exe`,
see `tests/idalib_real.rs` `real_ida_issue19_*`):

| audit item | result |
|---|---|
| input hashes + imagebase + entries | `db.metadata` (md5 verified against independent hash; TLS callbacks / exception handlers reported `supported:false`) |
| imports + modules | `imports.list` (per-module ea/name/ord, paginated) |
| relocations/fixups | `fixups.list` (bounded, typed fields) |
| file-offset <-> EA | `file.map` (roundtrip verified) |
| function chunks/tails | `func.tails` (entry+tail chunks) |
| create/delete/resize functions | `func.create/delete/resize` (mutation + `expected_revision` + revision bump, tested) |
| switch/jump-table metadata | `func.switch_info` (get_switch_info; fixture compiles to cmp chain so populated path is untested locally — honest) |
| sp delta | `func.sp_delta` |
| ctree typed summaries | `hr.cfunc` (bounded, cot_*/cit_* op + payload + rendered text) |
| lvars + return type | `hr.cfunc` (name/type/width/arg/result, one-line type text) |
| rename lvars | `hr.lvar_rename` (persists via user lvar settings, verified in re-decompilation) |
| instruction features | `insn.features` (canon CF_* bits + mnemonic) |
| demangling | `names.demangle` (None/passthrough for non-mangled names) |

Deferred from the audit (tracked, honestly reported):

- microcode generation/inspection -> issue #9 (capability `microcode:false`)
- local types list/parse/apply -> issue #11 / #16 (capability `types:false` unchanged)
- pseudocode line <-> EA mapping (eamap) -> follow-up
- decompiler warnings via `cfunc.get_warnings()` -> follow-up
- type/field xrefs -> #11 as planned in the audit
