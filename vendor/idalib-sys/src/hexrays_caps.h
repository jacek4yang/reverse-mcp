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
