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
idalib_hexrays_decompile_func(func_t *f, hexrays_error_t *err, int flags) {
  hexrays_failure_t failure;
  cfuncptr_t cf = decompile_func(f, &failure, flags);

  if (failure.code >= 0 && cf != nullptr) {
    return std::unique_ptr<cfuncptr_t>(new cfuncptr_t(cf));
  }

  err->code = failure.code;
  err->desc = rust::String(failure.desc().c_str());
  err->addr = failure.errea;

  return nullptr;
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
