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

// ---- type recovery (#11): member access evidence, UDT create/match ----

// One member-access observation: an expression of the form base->m /
// base.m with the accessed offset and width. base_text renders the base
// expression so the Rust side can group observations by object.
struct MemberRow {
  std::string base_text; // rendered base expression ("" when unresolved)
  bool is_global = false; // base is a fixed object (cot_obj)
  uint64_t base_ea = 0;   // EA of the global base object (0 unless global)
  uint64_t offset = 0;    // member offset in bytes
  uint32_t access_size = 0; // width of the access in bytes (0 if unknown)
  bool is_write = false;  // true when the member expr is the asg LHS
  uint64_t at_ea = 0;     // EA of the enclosing expression
};

struct MemberRowList {
  std::vector<MemberRow> rows;
  bool truncated = false;
};

namespace ctree_detail {

struct MemberCtx {
  MemberRowList *out;
  size_t limit;
};

// Classify an assignment op: true when x is the written location.
inline bool is_assign_op(uint32_t op) {
  return op == cot_asg || (op >= cot_asgbor && op <= cot_asgumod);
}

inline void record_member(MemberCtx &ctx, cexpr_t *e, bool is_write) {
  if (ctx.out->rows.size() >= ctx.limit) {
    ctx.out->truncated = true;
    return;
  }
  MemberRow row;
  row.at_ea = (uint64_t)e->ea;
  row.is_write = is_write;
  if (e->op == cot_memptr) {
    row.access_size = (uint32_t)e->ptrsize;
    row.offset = (uint64_t)e->m;
    if (e->x != nullptr) {
      if (e->x->op == cot_obj) {
        row.is_global = true;
        row.base_ea = (uint64_t)e->x->obj_ea;
      }
      row.base_text = render_expr(e->x);
    }
  } else if (e->op == cot_memref) {
    row.offset = (uint64_t)e->m;
    if (e->x != nullptr) {
      if (e->x->op == cot_obj) {
        row.is_global = true;
        row.base_ea = (uint64_t)e->x->obj_ea;
      }
      row.base_text = render_expr(e->x);
    }
  } else {
    return;
  }
  ctx.out->rows.push_back(std::move(row));
}

struct BoundedMemberVisitor : public ctree_parentee_t {
  MemberCtx &ctx;
  explicit BoundedMemberVisitor(MemberCtx &c) : ctree_parentee_t(CV_FAST), ctx(c) {}

  int idaapi visit_expr(cexpr_t *e) override {
    if (e->op == cot_memptr || e->op == cot_memref) {
      record_member(ctx, e, false);
      if (ctx.out->truncated) {
        return 1;
      }
    }
    // Assignment: the LHS (x) member expression is a write site.
    if (is_assign_op((uint32_t)e->op) && e->x != nullptr
        && (e->x->op == cot_memptr || e->x->op == cot_memref)) {
      record_member(ctx, e->x, true);
      if (ctx.out->truncated) {
        return 1;
      }
    }
    // Untyped-object access: IDA renders member reads through raw pointers
    // as *(T *)((char *)obj + off) — a cot_ptr whose x is cot_add with a
    // constant (cot_num) operand over a base object. Record (obj, off,
    // ptrsize) so the engine can propose a field without any prior type.
    if (e->op == cot_ptr && e->x != nullptr && e->x->op == cot_add
        && e->x->y != nullptr && e->x->y->op == cot_num) {
      cexpr_t *base = e->x->x;
      if (base != nullptr) {
        MemberRow row;
        row.at_ea = (uint64_t)e->ea;
        // _value (not numval()): numval() expands the SDK QASSERT macro
        // which references the under_debugger data export and breaks
        // /DELAYLOAD:ida.dll (see the cot_num note above).
        row.offset = e->x->y->n->_value;
        row.access_size = (uint32_t)e->ptrsize;
        if (base->op == cot_obj) {
          row.is_global = true;
          row.base_ea = (uint64_t)base->obj_ea;
        }
        row.base_text = render_expr(base);
        if (ctx.out->rows.size() >= ctx.limit) {
          ctx.out->truncated = true;
          return 1;
        }
        ctx.out->rows.push_back(std::move(row));
      }
    }
    return 0;
  }
};

}  // namespace ctree_detail

inline MemberRowList *idalib_members_walk(cfunc_t *f, size_t limit) {
  auto *out = new MemberRowList();
  ctree_detail::MemberCtx ctx{out, limit};
  ctree_detail::BoundedMemberVisitor v(ctx);
  v.apply_to(&f->body, nullptr);
  return out;
}

inline void idalib_member_rows_free(MemberRowList *rows) { delete rows; }
inline size_t idalib_member_rows_size(const MemberRowList *rows) {
  return rows->rows.size();
}
inline bool idalib_member_rows_truncated(const MemberRowList *rows) {
  return rows->truncated;
}
inline rust::String idalib_member_row_base(const MemberRowList *rows, size_t i) {
  return rust::String(rows->rows[i].base_text.c_str());
}
inline bool idalib_member_row_global(const MemberRowList *rows, size_t i) {
  return rows->rows[i].is_global;
}
inline uint64_t idalib_member_row_base_ea(const MemberRowList *rows, size_t i) {
  return rows->rows[i].base_ea;
}
inline uint64_t idalib_member_row_offset(const MemberRowList *rows, size_t i) {
  return rows->rows[i].offset;
}
inline uint32_t idalib_member_row_size(const MemberRowList *rows, size_t i) {
  return rows->rows[i].access_size;
}
inline bool idalib_member_row_write(const MemberRowList *rows, size_t i) {
  return rows->rows[i].is_write;
}
inline uint64_t idalib_member_row_at(const MemberRowList *rows, size_t i) {
  return rows->rows[i].at_ea;
}

// Virtual-function-table scan: read `max_entries` qwords starting at ea and
// resolve each to a function name when it points at code. Read-only, no
// mutation; the Rust side proposes, the agent applies.
struct VtableRow {
  uint64_t slot = 0;      // slot index
  uint64_t target_ea = 0; // qword value
  bool is_code = false;   // target is a function
  std::string name;       // function name when is_code
};

inline std::unique_ptr<VtableRow> idalib_vtable_scan_row(uint64_t ea, uint64_t slot) {
  auto out = std::make_unique<VtableRow>();
  out->slot = slot;
  ea_t target = get_qword(ea + slot * sizeof(ea_t));
  out->target_ea = (uint64_t)target;
  func_t *f = get_func(target);
  if (f != nullptr && f->start_ea == target) {
    out->is_code = true;
    qstring n;
    if (get_func_name(&n, target) > 0) {
      out->name = std::string(n.c_str());
    }
  }
  return out;
}

inline uint64_t idalib_vtable_row_slot(const VtableRow &r) { return r.slot; }
inline uint64_t idalib_vtable_row_target(const VtableRow &r) { return r.target_ea; }
inline bool idalib_vtable_row_is_code(const VtableRow &r) { return r.is_code; }
inline rust::String idalib_vtable_row_name(const VtableRow &r) {
  return rust::String(r.name.c_str());
}

// Create (or replace) a named struct type in the local TIL from a list of
// member declarations. decl_items: "offset:size:name:type_decl" quadruples,
// comma separated - parsed with parse_decl per member. Returns the ordinal
// of the created type or 0 on failure. Mutation: caller bumps the revision.
// Example: "0:8:id:int, 8:16:name:char [16]"
inline uint32_t idalib_udt_create(const char *name, const char *decl_items) {
  tinfo_t udt;
  udt_type_data_t ud;
  ud.is_union = false;
  std::string items(decl_items);
  size_t pos = 0;
  while (pos < items.size()) {
    size_t comma = items.find(',', pos);
    std::string item = items.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
    pos = comma == std::string::npos ? items.size() : comma + 1;
    // fields: offset:size:name:type_decl
    size_t c1 = item.find(':');
    size_t c2 = item.find(':', c1 + 1);
    size_t c3 = item.find(':', c2 + 1);
    if (c1 == std::string::npos || c2 == std::string::npos || c3 == std::string::npos) {
      return 0;
    }
    uint64_t offset = strtoull(item.substr(0, c1).c_str(), nullptr, 0);
    uint64_t size = strtoull(item.substr(c1 + 1, c2 - c1 - 1).c_str(), nullptr, 0);
    std::string mname = item.substr(c2 + 1, c3 - c2 - 1);
    std::string mdecl = item.substr(c3 + 1);
    // trim leading spaces
    size_t ns = mdecl.find_first_not_of(' ');
    mdecl = ns == std::string::npos ? "" : mdecl.substr(ns);
    tinfo_t tif;
    qstring parsed_name;
    // parse_decl wants a declaration with a declarator: "int level" not a
    // bare "int". Compose "type membername;" so the name lands in
    // parsed_name and the type in tif.
    std::string decl = mdecl + " " + mname;
    if (!parse_decl(&tif, &parsed_name, nullptr, decl.c_str(),
                    PT_SIL | PT_NDC | PT_TYP | PT_SEMICOLON)) {
      return 0;
    }
    udm_t m(parsed_name.c_str(), tif, offset * 8);
    if (m.size == 0) {
      m.size = size * 8;
    }
    ud.push_back(std::move(m));
  }
  if (ud.empty()) {
    return 0;
  }
  if (!udt.create_udt(ud)) {
    return 0;
  }
  uint32_t ord = alloc_type_ordinal(nullptr);
  if (ord == 0) {
    return 0;
  }
  tinfo_code_t rc = udt.set_numbered_type(nullptr, ord, NTF_REPLACE, name);
  if (rc != TERR_OK) {
    del_numbered_type(nullptr, ord);
    return 0;
  }
  return ord;
}

// Find a local type whose UDT layout matches (offset, size) pairs and
// return its name. shape: "offset:size" pairs, comma separated.
// Returns "" when nothing matches.
inline rust::String idalib_udt_match_shape(const char *shape) {
  std::string spec(shape);
  std::vector<std::pair<uint64_t, uint64_t>> want;
  size_t pos = 0;
  while (pos < spec.size()) {
    size_t comma = spec.find(',', pos);
    std::string item = spec.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
    pos = comma == std::string::npos ? spec.size() : comma + 1;
    size_t colon = item.find(':');
    if (colon == std::string::npos) {
      continue;
    }
    uint64_t o = strtoull(item.substr(0, colon).c_str(), nullptr, 0);
    uint64_t s = strtoull(item.substr(colon + 1).c_str(), nullptr, 0);
    want.emplace_back(o, s);
  }
  if (want.empty()) {
    return rust::String();
  }
  uint32_t limit = get_ordinal_limit(nullptr);
  for (uint32_t ord = 1; ord < limit; ord++) {
    const type_t *tp = nullptr;
    const p_list *fields = nullptr;
    if (!get_numbered_type(nullptr, ord, &tp, &fields, nullptr, nullptr, nullptr)) {
      continue;
    }
    tinfo_t tif;
    if (!tif.deserialize(nullptr, &tp, &fields)) {
      continue;
    }
    udt_type_data_t ud;
    if (!tif.get_udt_details(&ud)) {
      continue;
    }
    if (ud.size() != want.size()) {
      continue;
    }
    bool ok = true;
    for (size_t i = 0; i < want.size(); i++) {
      if (ud[i].offset / 8 != want[i].first || ud[i].size / 8 != want[i].second) {
        ok = false;
        break;
      }
    }
    if (ok) {
      qstring nm;
      if (tif.get_type_name(&nm)) {
        return rust::String(nm.c_str());
      }
    }
  }
  return rust::String();
}
