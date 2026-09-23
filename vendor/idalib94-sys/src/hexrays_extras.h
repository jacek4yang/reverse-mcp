#pragma once

#include "hexrays.hpp"
#include "lines.hpp"
#include "pro.h"

#include <cstdint>
#include <memory>
#include <sstream>

#ifdef __NT__
#include <windows.h>
#endif

#include "cxx.h"

// The SDK's init_hexrays_plugin/term_hexrays_plugin inline functions go
// through the `callui` data export of ida.dll. Data imports cannot be
// delay-loaded (LNK1194), so resolve callui at runtime instead and keep
// ida.dll delay-loadable for the combined broker/worker exe.
typedef callui_t(idaapi *idalib_callui_fn_t)(ui_notification_t what, ...);

inline HMODULE idalib_ida_module() {
  HMODULE ida = GetModuleHandleW(L"ida.dll");
  if (!ida) {
    ida = LoadLibraryW(L"ida.dll");
  }
  return ida;
}

inline idalib_callui_fn_t idalib_callui_resolver() {
  // callui is a data export: GetProcAddress returns the address OF the
  // pointer variable, so dereference it to get the dispatcher function.
  static idalib_callui_fn_t fp = nullptr;
  if (!fp) {
    HMODULE ida = idalib_ida_module();
    FARPROC p = ida ? GetProcAddress(ida, "callui") : nullptr;
    if (p) {
      fp = *reinterpret_cast<idalib_callui_fn_t *>(p);
    }
  }
  return fp;
}

inline bool idalib_hexrays_init(int flags) {
  idalib_callui_fn_t fp = idalib_callui_resolver();
  if (!fp) {
    return false;
  }
  hexdsp_t *dummy = nullptr;
  return fp(ui_broadcast, HEXRAYS_API_MAGIC, &dummy, flags).i ==
         (HEXRAYS_API_MAGIC >> 32);
}

inline void idalib_hexrays_term() {}

#ifndef CXXBRIDGE1_STRUCT_hexrays_error_t
#define CXXBRIDGE1_STRUCT_hexrays_error_t
struct hexrays_error_t final {
  ::std::int32_t code;
  ::std::uint64_t addr;
  ::rust::String desc;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_error_t

struct cblock_iter {
  qlist<cinsn_t>::iterator start;
  qlist<cinsn_t>::iterator end;

  cblock_iter(cblock_t *b) : start(b->begin()), end(b->end()) {}
};

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

std::unique_ptr<cfuncptr_t>
idalib_hexrays_decompile_function(ea_t func_ea, hexrays_error_t *err, int flags) {
  hexrays_failure_t failure;
  cfuncptr_t cf = decompile_function(func_ea, &failure, flags);

  if (failure.code >= 0 && cf != nullptr) {
    return std::unique_ptr<cfuncptr_t>(new cfuncptr_t(cf));
  }

  err->code = failure.code;
  err->desc = rust::String(failure.desc().c_str());
  err->addr = failure.errea;

  return nullptr;
}

// reverse-mcp: func_t-based decompile entry used by the Rust safe layer and
// the #72 large-function range analysis (which already resolved the func_t).
// The 9.4 SDK deprecates decompile_func(); route through
// decompile_function(f->start_ea), which is what it did internally.
std::unique_ptr<cfuncptr_t>
idalib_hexrays_decompile_func(func_t *f, hexrays_error_t *err, int flags) {
  return idalib_hexrays_decompile_function(f->start_ea, err, flags);
}

// reverse-mcp: the autocxx-idalib 0.30 engine emits wrappers for the two
// carglist_t::print overloads even though no import library resolves them
// (the decompiler registers its functions dynamically; hexx64.dll exports
// only PLUGIN). reverse-mcp never renders arg lists through these paths;
// these inert definitions satisfy the generated wrappers. If arg-list
// printing is ever needed, route it through gen_microcode/ctree rows
// instead of these.
void carglist_t::print(qstring *vout, const cfunc_t *func) const {
  (void)func;
  if (vout) vout->clear();
}

int carglist_t::print(int curpos, vc_printer_t &vp) const {
  (void)vp;
  return curpos;
}

rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}

std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

std::size_t idalib_hexrays_cblock_len(cblock_t *b) { return b->size(); }

cblock_t *idalib_hexrays_cfunc_body(cfunc_t *f) { return f->body.cblock; }

// ---- issue #43: bounded microcode generation/inspection ----
// gen_microcode() runs the full microcode pipeline for one function up to the
// requested maturity. The returned mba_t is owned by the caller (deleted with
// `delete`, which calls the SDK ~mba_t -> term()). Rows are extracted in C++
// so no Hex-Rays object crosses the FFI boundary.

#ifndef CXXBRIDGE1_STRUCT_hexrays_mblock_row_t
#define CXXBRIDGE1_STRUCT_hexrays_mblock_row_t
struct hexrays_mblock_row_t final {
  ::std::uint32_t serial;
  ::std::uint32_t type;    // mblock_type_t (BLT_*)
  ::std::uint64_t start_ea;
  ::std::uint64_t end_ea;
  ::std::uint32_t flags;   // MBL_ bits
  ::std::uint32_t n_pred;
  ::std::uint32_t n_succ;
  ::std::uint32_t n_insns;

  using IsRelocatable = ::std::true_type;
};
#endif

#ifndef CXXBRIDGE1_STRUCT_hexrays_minsn_row_t
#define CXXBRIDGE1_STRUCT_hexrays_minsn_row_t
struct hexrays_minsn_row_t final {
  ::std::uint32_t block;   // block serial
  ::std::uint32_t opcode;  // mcode_t
  ::std::uint64_t ea;
  ::std::uint32_t l_type;  // mopt_t of the left operand
  ::std::uint32_t r_type;  // mopt_t of the right operand
  ::std::uint32_t d_type;  // mopt_t of the destination operand
  ::std::int32_t d_size;   // destination operand size (bytes), NOSIZE when none
  ::std::uint64_t n_value; // immediate value when the destination/left is mop_n
  ::std::string text;      // rendered instruction text (tag-stripped)

  using IsRelocatable = ::std::true_type;
};
#endif

struct hexrays_mba_dump_t {
  std::vector<hexrays_mblock_row_t> blocks;
  std::vector<hexrays_minsn_row_t> insns;
  std::uint32_t maturity = 0; // MMAT_* level actually reached
  std::uint32_t qty = 0;      // number of blocks
  bool truncated = false;
};

inline void idalib_hexrays_minsn_rows_free(hexrays_mba_dump_t *dump) { delete dump; }

inline size_t idalib_hexrays_mba_blocks(const hexrays_mba_dump_t &d) { return d.blocks.size(); }
inline uint32_t idalib_hexrays_mba_block_serial(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].serial; }
inline uint32_t idalib_hexrays_mba_block_type(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].type; }
inline uint64_t idalib_hexrays_mba_block_start(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].start_ea; }
inline uint64_t idalib_hexrays_mba_block_end(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].end_ea; }
inline uint32_t idalib_hexrays_mba_block_flags(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].flags; }
inline uint32_t idalib_hexrays_mba_block_npred(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].n_pred; }
inline uint32_t idalib_hexrays_mba_block_nsucc(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].n_succ; }
inline uint32_t idalib_hexrays_mba_block_ninsns(const hexrays_mba_dump_t &d, size_t i) { return d.blocks[i].n_insns; }

inline size_t idalib_hexrays_mba_insns(const hexrays_mba_dump_t &d) { return d.insns.size(); }
inline uint32_t idalib_hexrays_minsn_block(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].block; }
inline uint32_t idalib_hexrays_minsn_opcode(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].opcode; }
inline uint64_t idalib_hexrays_minsn_ea(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].ea; }
inline uint32_t idalib_hexrays_minsn_l_type(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].l_type; }
inline uint32_t idalib_hexrays_minsn_r_type(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].r_type; }
inline uint32_t idalib_hexrays_minsn_d_type(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].d_type; }
inline int32_t idalib_hexrays_minsn_d_size(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].d_size; }
inline uint64_t idalib_hexrays_minsn_n_value(const hexrays_mba_dump_t &d, size_t i) { return d.insns[i].n_value; }
inline rust::String idalib_hexrays_minsn_text(const hexrays_mba_dump_t &d, size_t i) {
  return rust::String(d.insns[i].text.c_str());
}

inline uint32_t idalib_hexrays_mba_maturity(const hexrays_mba_dump_t &d) { return d.maturity; }
inline uint32_t idalib_hexrays_mba_qty(const hexrays_mba_dump_t &d) { return d.qty; }
inline bool idalib_hexrays_mba_truncated(const hexrays_mba_dump_t &d) { return d.truncated; }

// Render one microinstruction via the SDK's own printer (SHINS_SHORT keeps
// use-def chains out of the text). Operands are summarized by mopt_t so the
// Rust side stays free of Hex-Rays object ownership.
inline hexrays_mba_dump_t *idalib_hexrays_gen_microcode(
    func_t *f,
    hexrays_error_t *err,
    int decomp_flags,
    uint32_t req_maturity,
    size_t max_insns) {
  auto *dump = new hexrays_mba_dump_t();
  hexrays_failure_t failure;
  mba_ranges_t mbr(f);
  mba_t *mba = gen_microcode(mbr, &failure, nullptr, decomp_flags,
                             static_cast<mba_maturity_t>(req_maturity));
  if (mba == nullptr) {
    err->code = failure.code;
    err->desc = rust::String(failure.desc().c_str());
    err->addr = failure.errea;
    delete dump;
    return nullptr;
  }
  dump->maturity = static_cast<uint32_t>(mba->maturity);
  dump->qty = static_cast<uint32_t>(mba->qty);
  for (int b = 0; b < mba->qty; b++) {
    // mba->get_mblock(b) expands the SDK QASSERT macro, which references the
    // under_debugger data export of ida.dll and breaks /DELAYLOAD (see the
    // cot_num note in hexrays_caps.h). natural[] is the public backing array
    // and 0 <= b < mba->qty is guaranteed by the loop above.
    mblock_t *blk = mba->natural[b];
    hexrays_mblock_row_t row{};
    row.serial = static_cast<uint32_t>(blk->serial);
    row.type = static_cast<uint32_t>(blk->type);
    row.start_ea = static_cast<uint64_t>(blk->start);
    row.end_ea = static_cast<uint64_t>(blk->end);
    row.flags = blk->flags;
    row.n_pred = static_cast<uint32_t>(blk->npred());
    row.n_succ = static_cast<uint32_t>(blk->nsucc());
    row.n_insns = static_cast<uint32_t>(blk->get_reginsn_qty());
    dump->blocks.push_back(row);

    for (minsn_t *ins = blk->head; ins != nullptr; ins = ins->next) {
      if (dump->insns.size() >= max_insns) {
        dump->truncated = true;
        break;
      }
      hexrays_minsn_row_t r{};
      r.block = static_cast<uint32_t>(b);
      r.opcode = static_cast<uint32_t>(ins->opcode);
      r.ea = static_cast<uint64_t>(ins->ea);
      r.l_type = static_cast<uint32_t>(ins->l.t);
      r.r_type = static_cast<uint32_t>(ins->r.t);
      r.d_type = static_cast<uint32_t>(ins->d.t);
      r.d_size = ins->d.size;
      if (ins->l.t == mop_n && ins->l.nnn != nullptr) {
        r.n_value = ins->l.nnn->value;
      } else if (ins->d.t == mop_n && ins->d.nnn != nullptr) {
        r.n_value = ins->d.nnn->value;
      }
      qstring text;
      ins->print(&text, SHINS_SHORT | SHINS_VALNUM);
      r.text = std::string(text.c_str());
      dump->insns.push_back(std::move(r));
    }
    if (dump->truncated) {
      break;
    }
  }
  delete mba;
  return dump;
}

