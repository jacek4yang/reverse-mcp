#pragma once
#include "pro.h"
#include "nalt.hpp"
#include "loader.hpp"
#include "fixup.hpp"
#include "funcs.hpp"
#include "frame.hpp"
#include "gdl.hpp"
#include "ua.hpp"
#include "name.hpp"
#include "segregs.hpp"
#include "cxx.h"
#include <cstdint>
#include <type_traits>
#include <vector>

// ---- image base ----
inline uint64_t idalib_get_imagebase() { return get_imagebase(); }

// ---- file offset <-> EA ----
inline int64_t idalib_get_fileregion_offset(ea_t ea) { return get_fileregion_offset(ea); }
inline uint64_t idalib_get_fileregion_ea(int64_t off) { return (uint64_t)get_fileregion_ea((qoff64_t)off); }

// ---- imports ----
inline size_t idalib_get_import_module_qty() { return get_import_module_qty(); }
inline rust::String idalib_get_import_module_name(int mod_index) {
  auto buf = qstring();
  if (get_import_module_name(&buf, mod_index)) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}

// Thunk-free C callback trampoline for enum_import_names. `param` points at a
// caller-owned ImportCollector holding three parallel vectors.
struct ImportCollector {
  std::vector<uint64_t> eas;
  std::vector<rust::String> names;
  std::vector<uint64_t> ords;
};

inline int idaapi idalib_import_enum_cb(ea_t ea, const char *name, uval_t ord, void *param) {
  auto *out = static_cast<ImportCollector *>(param);
  out->eas.push_back((uint64_t)ea);
  out->names.push_back(rust::String(name == nullptr ? "" : name));
  out->ords.push_back((uint64_t)ord);
  return 1;  // continue enumeration
}

inline size_t idalib_enum_import_names(int mod_index,
                                       rust::Vec<uint64_t> &eas,
                                       rust::Vec<rust::String> &names,
                                       rust::Vec<uint64_t> &ords) {
  ImportCollector collected;
  // IDA SDK: enum_import_names returns the NUMBER of imports found (>=0) on
  // success and a negative value on failure (e.g. bad module index). The
  // count is not an error - a successful enumeration must be forwarded.
  int rc = enum_import_names(mod_index, idalib_import_enum_cb, &collected);
  if (rc < 0) {
    return 0;
  }
  for (size_t i = 0; i < collected.eas.size(); ++i) {
    eas.push_back(collected.eas[i]);
    names.push_back(std::move(collected.names[i]));
    ords.push_back(collected.ords[i]);
  }
  return eas.size();
}

// ---- fixups ----
inline uint64_t idalib_get_first_fixup_ea() { return get_first_fixup_ea(); }
inline uint64_t idalib_get_next_fixup_ea(ea_t ea) { return get_next_fixup_ea(ea); }
// Appends [type, flags, base, sel, off, displacement] for the fixup at source.
inline bool idalib_get_fixup(ea_t source, rust::Vec<uint64_t> &out) {
  fixup_data_t fd;
  if (!get_fixup(&fd, source)) {
    return false;
  }
  out.push_back((uint64_t)fd.get_type());
  out.push_back((uint64_t)fd.get_flags());
  out.push_back((uint64_t)fd.get_base());
  out.push_back((uint64_t)fd.sel);
  out.push_back((uint64_t)fd.off);
  out.push_back((uint64_t)fd.displacement);
  return true;
}

// ---- switch (jump table) info ----
// Appends a bounded subset of switch_info_t: [flags, jumps, values, defjump,
// elbase, ncases, jcases, lowcase, regnum, jsize, vsize, startea].
inline bool idalib_get_switch_info(ea_t ea, rust::Vec<uint64_t> &out) {
  switch_info_t si;
  if (get_switch_info(&si, ea) <= 0) {
    return false;
  }
  out.push_back(si.flags);
  out.push_back((uint64_t)si.jumps);
  out.push_back((uint64_t)si.values);
  out.push_back((uint64_t)si.defjump);
  out.push_back((uint64_t)si.elbase);
  out.push_back((uint64_t)si.ncases);
  out.push_back((uint64_t)si.jcases);
  out.push_back((uint64_t)(int64_t)si.get_lowcase());
  out.push_back((uint64_t)si.regnum);
  out.push_back((uint64_t)si.get_jtable_element_size());
  out.push_back((uint64_t)si.get_vtable_element_size());
  out.push_back((uint64_t)si.startea);
  return true;
}

// ---- function chunks/tails ----
inline size_t idalib_get_fchunk_qty() { return get_fchunk_qty(); }
inline const func_t *idalib_getn_fchunk(int n) { return getn_fchunk(n); }
inline bool idalib_func_is_tail(const func_t *f) { return f != nullptr && (f->flags & FUNC_TAIL) != 0; }

// Enumerate all chunks of a function (entry chunk first) via
// iterate_func_chunks; appends start_ea/end_ea pairs to `out`.
inline void idaapi idalib_chunks_cb(ea_t ea1, ea_t ea2, void *ud) {
  auto *out = static_cast<rust::Vec<uint64_t> *>(ud);
  out->push_back((uint64_t)ea1);
  out->push_back((uint64_t)ea2);
}
inline size_t idalib_func_chunks(func_t *f, rust::Vec<uint64_t> &out) {
  iterate_func_chunks(f, idalib_chunks_cb, &out, false);
  return out.size() / 2;
}

// ---- function create/delete/resize ----
inline bool idalib_add_func(ea_t start, ea_t end /*BADADDR => let IDA decide*/) {
  return add_func(start, end);
}
inline bool idalib_del_func(ea_t start) { return del_func(start); }
inline int idalib_set_func_start(ea_t ea, ea_t newstart) { return set_func_start(ea, newstart); }
inline bool idalib_set_func_end(ea_t ea, ea_t newend) { return set_func_end(ea, newend); }

// ---- stack pointer delta ----
inline int64_t idalib_get_sp_delta(func_t *f, ea_t ea) { return get_sp_delta(f, ea); }

// ---- demangling ----
inline rust::String idalib_demangle_name(const char *name) {
  qstring out;
  // Returns MT_/ME_ bitmask; 0 means "not demangleable". Empty output with
  // a nonzero return means the name has no demangled form.
  int32 rc = demangle_name(&out, name, 0, DQT_FULL);
  if (rc == 0 || out.empty()) {
    return rust::String();
  }
  return rust::String(out.c_str());
}

// ---- instruction features ----
// Promote undefined bytes at ea into an instruction (ida_bytes create_insn).
// Returns the instruction length (>0) or 0/-1 when the bytes cannot be
// decoded as an instruction by the current processor. Used by the generic
// zero-function recovery path to give add_func code anchors.
inline int idalib_create_insn(ea_t ea) {
  return create_insn(ea);
}
// Canon feature bits of the instruction at ea (0 if it cannot be decoded).
inline uint32_t idalib_get_insn_feature(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return 0;
  }
  const processor_t &ph = *get_ph();
  return insn.get_canon_feature(ph);
}
inline rust::String idalib_print_insn_mnem(ea_t ea) {
  qstring out;
  if (!print_insn_mnem(&out, ea)) {
    return rust::String();
  }
  return rust::String(out.c_str());
}

// ---- segments ----
inline uint64_t idalib_get_segm_base(const segment_t *s) { return get_segm_base(s); }
