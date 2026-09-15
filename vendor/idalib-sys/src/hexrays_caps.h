#pragma once
#include "pro.h"
#include "hexrays.hpp"
#include "funcs.hpp"
#include "lines.hpp"
#include "typeinf.hpp"
#include "cxx.h"
#include <cstdint>
#include <memory>
#include <vector>

// Bounded Hex-Rays capability shims (issue #19): ctree node summaries,
// lvars, return type and lvar rename. Rows are returned through opaque
// C++ list containers accessed with scalar accessors from Rust (see the
// ffix bridge in src/lib.rs and the safe wrappers in caps.rs).

// ---- row containers (C++-side only; Rust sees opaque handles) ----

struct CtreeRow {
  uint64_t ea = 0;
  uint32_t op = 0; // cot_* for expressions, cit_* for statements
  uint64_t a = 0;  // item-specific: x/idx/label (0 unless set)
  uint64_t b = 0;  // item-specific: y (0 unless set)
  uint64_t c = 0;  // item-specific: z / number value (0 unless set)
  bool is_expr = false;
  std::string text;
};

struct CtreeRowList {
  std::vector<CtreeRow> rows;
  bool truncated = false;
};

struct LvarRow {
  uint64_t defea = 0;
  std::string name;
  std::string type_text;
  int64_t width = 0;
  bool is_arg = false;
  bool is_result = false;
};

struct LvarRowList {
  std::vector<LvarRow> rows;
  bool truncated = false;
};

struct CallRow {
  uint64_t call_ea = 0;   // address of the cot_call expression
  uint64_t target_ea = 0; // direct callee EA (BADADDR when indirect)
  bool direct = false;    // callee resolved to a fixed EA
  std::string target_name; // rendered callee expression text
  std::vector<std::string> args; // rendered argument expressions
  std::string ret_type;   // declared return type text (empty if unknown)
};

struct CallRowList {
  std::vector<CallRow> rows;
  bool truncated = false;
};

// ---- ctree: bounded typed node summaries ----

namespace ctree_detail {

struct WalkCtx {
  CtreeRowList *out;
  size_t limit;
};

inline std::string render_expr(cexpr_t *e) {
  qstring out;
  e->print1(&out, nullptr);
  tag_remove(&out);
  return std::string(out.c_str());
}

inline void collect_row(WalkCtx &ctx, citem_t *item) {
  if (ctx.out->rows.size() >= ctx.limit) {
    ctx.out->truncated = true;
    return;
  }
  CtreeRow row;
  row.ea = (uint64_t)item->ea;
  row.op = (uint32_t)item->op;
  row.is_expr = item->is_expr();
  if (item->is_expr()) {
    auto *e = (cexpr_t *)item;
    switch (item->op) {
      case cot_num:
        // e->numval() expands the SDK's QASSERT macro, which references the
        // `under_debugger` data export of ida.dll — a data import that breaks
        // /DELAYLOAD:ida.dll (data imports cannot be delay-bound). We already
        // guarantee op == cot_num here, so take the assert-free path via
        // cnumber_t::value(); that still imports extend_sign, but it is a
        // function import and delay-loadable.
        row.c = e->n->value(e->type);
        break;
      case cot_obj:
        row.c = (uint64_t)e->obj_ea;
        break;
      case cot_var:
        row.c = (uint64_t)e->v.idx;
        break;
      case cot_memptr:
      case cot_memref:
        row.c = (uint64_t)e->m;
        break;
      case cot_ptr:
        row.c = (uint64_t)e->ptrsize;
        break;
      default:
        break;
    }
    row.text = render_expr(e);
  }
  ctx.out->rows.push_back(std::move(row));
}

// Visitor with bounded output; returns non-zero to stop when full.
struct BoundedCtreeVisitor : public ctree_parentee_t {
  WalkCtx &ctx;
  explicit BoundedCtreeVisitor(WalkCtx &c) : ctree_parentee_t(CV_FAST), ctx(c) {}

  int idaapi visit_insn(cinsn_t *i) override {
    collect_row(ctx, i);
    return ctx.out->truncated ? 1 : 0;
  }
  int idaapi visit_expr(cexpr_t *e) override {
    collect_row(ctx, e);
    return ctx.out->truncated ? 1 : 0;
  }
};

}  // namespace ctree_detail

// Generate ctree summaries for `f`, stopping at `limit` rows. The caller
// owns the returned list and must release it with idalib_ctree_rows_free.
inline CtreeRowList *idalib_ctree_walk(cfunc_t *f, size_t limit) {
  auto *out = new CtreeRowList();
  ctree_detail::WalkCtx ctx{out, limit};
  ctree_detail::BoundedCtreeVisitor v(ctx);
  v.apply_to(&f->body, nullptr);
  return out;
}

inline void idalib_ctree_rows_free(CtreeRowList *rows) { delete rows; }

inline size_t idalib_ctree_rows_size(const CtreeRowList *rows) {
  return rows->rows.size();
}
inline bool idalib_ctree_rows_truncated(const CtreeRowList *rows) {
  return rows->truncated;
}
inline uint64_t idalib_ctree_row_ea(const CtreeRowList *rows, size_t i) {
  return rows->rows[i].ea;
}
inline uint32_t idalib_ctree_row_op(const CtreeRowList *rows, size_t i) {
  return rows->rows[i].op;
}
inline uint64_t idalib_ctree_row_a(const CtreeRowList *rows, size_t i) {
  return rows->rows[i].a;
}
inline uint64_t idalib_ctree_row_b(const CtreeRowList *rows, size_t i) {
  return rows->rows[i].b;
}
inline uint64_t idalib_ctree_row_c(const CtreeRowList *rows, size_t i) {
  return rows->rows[i].c;
}
inline bool idalib_ctree_row_is_expr(const CtreeRowList *rows, size_t i) {
  return rows->rows[i].is_expr;
}
inline rust::String idalib_ctree_row_text(const CtreeRowList *rows, size_t i) {
  return rust::String(rows->rows[i].text.c_str());
}

// ---- lvars ----

// Enumerate lvars of a decompiled function with one-line type rendering.
inline LvarRowList *idalib_lvars_walk(cfunc_t *f, size_t limit) {
  auto *out = new LvarRowList();
  lvars_t *lvs = f->get_lvars();
  if (lvs == nullptr) {
    return out;
  }
  for (auto &lv : *lvs) {
    if (out->rows.size() >= limit) {
      out->truncated = true;
      break;
    }
    LvarRow row;
    row.defea = (uint64_t)lv.defea;
    row.name = std::string(lv.name.c_str());
    qstring tt;
    print_tinfo(&tt, nullptr, 0, 0, PRTYPE_1LINE | PRTYPE_TYPE | PRTYPE_SEMI, &lv.tif, nullptr,
                nullptr);
    row.type_text = std::string(tt.c_str());
    row.width = lv.width;
    row.is_arg = lv.is_arg_var();
    row.is_result = lv.is_result_var();
    out->rows.push_back(std::move(row));
  }
  return out;
}

inline void idalib_lvar_rows_free(LvarRowList *rows) { delete rows; }

inline size_t idalib_lvar_rows_size(const LvarRowList *rows) {
  return rows->rows.size();
}
inline bool idalib_lvar_rows_truncated(const LvarRowList *rows) {
  return rows->truncated;
}
inline uint64_t idalib_lvar_row_defea(const LvarRowList *rows, size_t i) {
  return rows->rows[i].defea;
}
inline rust::String idalib_lvar_row_name(const LvarRowList *rows, size_t i) {
  return rust::String(rows->rows[i].name.c_str());
}
inline rust::String idalib_lvar_row_type_text(const LvarRowList *rows, size_t i) {
  return rust::String(rows->rows[i].type_text.c_str());
}
inline int64_t idalib_lvar_row_width(const LvarRowList *rows, size_t i) {
  return rows->rows[i].width;
}
inline bool idalib_lvar_row_is_arg(const LvarRowList *rows, size_t i) {
  return rows->rows[i].is_arg;
}
inline bool idalib_lvar_row_is_result(const LvarRowList *rows, size_t i) {
  return rows->rows[i].is_result;
}

// Function return type as one-line text (empty when unknown).
inline rust::String idalib_func_return_type(cfunc_t *f) {
  tinfo_t tif;
  if (!f->get_func_type(&tif)) {
    return rust::String();
  }
  tinfo_t ret = tif.get_nth_arg(-1);
  qstring tt;
  print_tinfo(&tt, nullptr, 0, 0, PRTYPE_1LINE | PRTYPE_TYPE | PRTYPE_SEMI, &ret, nullptr, nullptr);
  return rust::String(tt.c_str());
}

// Rename one lvar identified by its definition EA (user lvar settings).
// lvar_saved_infos_t in lvinf->lvvec only carries vars that ALREADY have
// user info, so when the target is absent we add a fresh entry instead of
// failing. The entry's location is filled in from the cfunc's lvars.
inline bool idalib_lvar_rename(cfunc_t *f, uint64_t var_defea, const char *new_name) {
  lvars_t *lvs = f->get_lvars();
  if (lvs == nullptr) {
    return false;
  }
  const lvar_t *victim = nullptr;
  for (const lvar_t &lv : *lvs) {
    if ((uint64_t)lv.defea == var_defea) {
      victim = &lv;
      break;
    }
  }
  if (victim == nullptr) {
    return false;
  }
  struct RenameLvars : public user_lvar_modifier_t {
    const lvar_t *victim;
    qstring new_name;
    bool idaapi modify_lvars(lvar_uservec_t *lvinf) override {
      const lvar_locator_t &loc = *victim;
      for (auto &info : lvinf->lvvec) {
        if (info.ll == loc) {
          info.name = new_name;
          return true;
        }
      }
      lvar_saved_info_t &ni = lvinf->lvvec.push_back();
      ni.ll = loc;
      ni.name = new_name;
      return true;
    }
  };
  RenameLvars mlv;
  mlv.victim = victim;
  mlv.new_name = qstring(new_name);
  return modify_user_lvars(f->entry_ea, mlv);
}

// ---- deep analysis (#10): call sites, full prototype, prototype apply ----

// Full function prototype: return type + per-argument type texts.
struct ProtoRow {
  std::string ret_type;
  std::vector<std::string> arg_types; // "..." entries beyond max_args are dropped
  bool truncated = false;
  bool known = false; // false when the function type is not available
};

inline std::unique_ptr<ProtoRow> idalib_func_prototype(cfunc_t *f, size_t max_args) {
  auto out = std::make_unique<ProtoRow>();
  tinfo_t tif;
  if (!f->get_func_type(&tif)) {
    return out;
  }
  out->known = true;
  qstring rt;
  tinfo_t ret = tif.get_nth_arg(-1);
  print_tinfo(&rt, nullptr, 0, 0, PRTYPE_1LINE | PRTYPE_TYPE | PRTYPE_SEMI, &ret, nullptr, nullptr);
  out->ret_type = std::string(rt.c_str());
  // get_func_details fills func_type_data_t with per-arg tinfo_t.
  func_type_data_t fti;
  if (tif.get_func_details(&fti)) {
    for (size_t i = 0; i < fti.size(); i++) {
      if (out->arg_types.size() >= max_args) {
        out->truncated = true;
        break;
      }
      qstring at;
      print_tinfo(&at, nullptr, 0, 0, PRTYPE_1LINE | PRTYPE_TYPE | PRTYPE_SEMI,
                  &fti[i].type, nullptr, nullptr);
      out->arg_types.push_back(std::string(at.c_str()));
    }
  }
  return out;
}

inline rust::String idalib_proto_ret_type(const ProtoRow &p) {
  return rust::String(p.ret_type.c_str());
}
inline size_t idalib_proto_arg_count(const ProtoRow &p) {
  return p.arg_types.size();
}
inline rust::String idalib_proto_arg_type(const ProtoRow &p, size_t i) {
  return rust::String(p.arg_types[i].c_str());
}
inline bool idalib_proto_truncated(const ProtoRow &p) {
  return p.truncated;
}
inline bool idalib_proto_known(const ProtoRow &p) {
  return p.known;
}

// Bounded call-site walker: every cot_call expression becomes one row with
// the rendered callee expression, direct-target EA (when resolvable) and
// rendered argument texts (concrete ctree evidence, issue #10).
namespace ctree_detail {

struct CallCtx {
  CallRowList *out;
  size_t limit;
};

inline void collect_call(CallCtx &ctx, cexpr_t *e) {
  if (ctx.out->rows.size() >= ctx.limit) {
    ctx.out->truncated = true;
    return;
  }
  CallRow row;
  row.call_ea = (uint64_t)e->ea;
  cexpr_t *callee = e->x;
  if (callee != nullptr) {
    if (callee->op == cot_obj) {
      row.direct = true;
      row.target_ea = (uint64_t)callee->obj_ea;
    }
    row.target_name = render_expr(callee);
  }
  if (e->a != nullptr) {
    for (carg_t &arg : *e->a) {
      if (row.args.size() >= 16) {
        break;
      }
      row.args.push_back(render_expr(&arg));
    }
  }
  ctx.out->rows.push_back(std::move(row));
}

struct BoundedCallVisitor : public ctree_parentee_t {
  CallCtx &ctx;
  explicit BoundedCallVisitor(CallCtx &c) : ctree_parentee_t(CV_FAST), ctx(c) {}

  int idaapi visit_expr(cexpr_t *e) override {
    if (e->op == cot_call) {
      collect_call(ctx, e);
      if (ctx.out->truncated) {
        return 1;
      }
    }
    return 0;
  }
};

}  // namespace ctree_detail

inline CallRowList *idalib_calls_walk(cfunc_t *f, size_t limit) {
  auto *out = new CallRowList();
  ctree_detail::CallCtx ctx{out, limit};
  ctree_detail::BoundedCallVisitor v(ctx);
  v.apply_to(&f->body, nullptr);
  return out;
}

inline void idalib_call_rows_free(CallRowList *rows) { delete rows; }
inline size_t idalib_call_rows_size(const CallRowList *rows) {
  return rows->rows.size();
}
inline bool idalib_call_rows_truncated(const CallRowList *rows) {
  return rows->truncated;
}
inline uint64_t idalib_call_row_call_ea(const CallRowList *rows, size_t i) {
  return rows->rows[i].call_ea;
}
inline uint64_t idalib_call_row_target_ea(const CallRowList *rows, size_t i) {
  return rows->rows[i].target_ea;
}
inline bool idalib_call_row_direct(const CallRowList *rows, size_t i) {
  return rows->rows[i].direct;
}
inline rust::String idalib_call_row_target_name(const CallRowList *rows, size_t i) {
  return rust::String(rows->rows[i].target_name.c_str());
}
inline rust::String idalib_call_row_arg(const CallRowList *rows, size_t i, size_t j) {
  return rust::String(rows->rows[i].args[j].c_str());
}
inline size_t idalib_call_row_arg_count(const CallRowList *rows, size_t i) {
  return rows->rows[i].args.size();
}

// Apply a prototype to the function at ea by parsing a C declaration like
// "int __usercall f(int, char *)" (name is ignored; PT_NDC keeps it raw).
// Returns false on parse failure or when apply_tinfo rejects the type.
inline bool idalib_apply_prototype(cfunc_t *f, const char *decl) {
  tinfo_t tif;
  qstring name;
  if (!parse_decl(&tif, &name, nullptr, decl, PT_SIL | PT_NDC | PT_TYP)) {
    return false;
  }
  return apply_tinfo(f->entry_ea, tif, TINFO_DEFINITE);
}

// Current prototype of the function at f as a printable one-line declaration
// (empty string when the type is unknown). Used to compare before/after and
// to feed the propagation loop.
inline rust::String idalib_prototype_text(cfunc_t *f) {
  tinfo_t tif;
  if (!f->get_func_type(&tif)) {
    return rust::String();
  }
  qstring out;
  print_tinfo(&out, nullptr, 0, 0, PRTYPE_1LINE | PRTYPE_TYPE | PRTYPE_SEMI, &tif, nullptr, nullptr);
  return rust::String(out.c_str());
}
